// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type uninstallFixture struct {
	dir, systemd, sysctl string
	calls                []string
	nftCalls             int
	hooks                *uninstallHooks
	lines                []string
}

func newUninstallFixture(t *testing.T) *uninstallFixture {
	t.Helper()
	f := &uninstallFixture{dir: initProxyTestState(t), systemd: t.TempDir(), sysctl: t.TempDir()}
	f.hooks = &uninstallHooks{
		systemdDir: f.systemd, sysctlDir: f.sysctl,
		systemctl: func(_ context.Context, args ...string) error {
			f.calls = append(f.calls, strings.Join(args, " "))
			return nil
		},
		nft:        func(context.Context) error { f.nftCalls++; return nil },
		otherNetns: func() bool { return false },
	}
	return f
}

func (f *uninstallFixture) opts() UninstallOptions {
	return UninstallOptions{Dir: f.dir, hooks: f.hooks, Inform: func(s string) { f.lines = append(f.lines, s) }}
}

func (f *uninstallFixture) installFiles(t *testing.T) {
	t.Helper()
	settings, err := ReadSettings(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := filepath.Abs(f.dir)
	for _, file := range installArtifacts(settings, state, "/usr/local/bin/pipe") {
		switch file.name {
		case "pipe.service", "pipe-hop.service":
			must(t, os.WriteFile(filepath.Join(f.systemd, file.name), []byte(file.contents), 0644))
		case "90-pipe.conf":
			must(t, os.WriteFile(filepath.Join(f.sysctl, file.name), []byte(file.contents), 0644))
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestUninstallRemovesOwnUnitsAndSysctl(t *testing.T) {
	f := newUninstallFixture(t)
	f.installFiles(t)
	must(t, Uninstall(t.Context(), f.opts()))
	if exists(filepath.Join(f.systemd, "pipe.service")) || exists(filepath.Join(f.sysctl, "90-pipe.conf")) {
		t.Fatal("pipe.service and the sysctl file should be gone")
	}
	want := "disable --now pipe.service|daemon-reload"
	if f.nftCalls != 1 || strings.Join(f.calls, "|") != want {
		t.Fatalf("nft=%d calls=%v", f.nftCalls, f.calls)
	}
	out := strings.Join(f.lines, "\n")
	for _, text := range []string{"until reboot", "/usr/local/bin/pipe is kept"} {
		if !strings.Contains(out, text) {
			t.Fatalf("missing %q in %s", text, out)
		}
	}
}

func TestUninstallRemovesHopUnit(t *testing.T) {
	f := newUninstallFixture(t)
	settings, err := ReadSettings(f.dir)
	must(t, err)
	settings.FastHop = "20000-20010"
	must(t, writeJSON(f.dir, settingsFile, settings))
	f.installFiles(t)
	must(t, Uninstall(t.Context(), f.opts()))
	if exists(filepath.Join(f.systemd, "pipe-hop.service")) || len(f.calls) != 3 {
		t.Fatalf("hop unit should be disabled and removed: %v", f.calls)
	}
}

func TestUninstallWithoutSystemd(t *testing.T) {
	f := newUninstallFixture(t)
	f.hooks.systemdDir = filepath.Join(f.systemd, "missing")
	f.hooks.systemctl = func(context.Context, ...string) error { return exec.ErrNotFound }
	must(t, Uninstall(t.Context(), f.opts()))
	if f.nftCalls != 1 {
		t.Fatal("the hop table must still be removed")
	}
	// Units exist but systemctl does not.
	f.hooks.systemdDir = f.systemd
	f.installFiles(t)
	must(t, Uninstall(t.Context(), f.opts()))
	if exists(filepath.Join(f.systemd, "pipe.service")) {
		t.Fatal("unit file should still be removed")
	}
}

func TestUninstallRespectsMarkersAndOtherInstalls(t *testing.T) {
	f := newUninstallFixture(t)
	foreign := "[Unit]\nDescription=Something else\n[Service]\nExecStart=/bin/true\n"
	must(t, os.WriteFile(filepath.Join(f.systemd, "pipe.service"), []byte(foreign), 0644))
	must(t, os.WriteFile(filepath.Join(f.sysctl, "90-pipe.conf"), []byte(sysctlConfig), 0644))
	must(t, Uninstall(t.Context(), f.opts()))
	if !exists(filepath.Join(f.systemd, "pipe.service")) || len(f.calls) != 0 {
		t.Fatal("a unit without pipe's marker must stay")
	}
	// A pipe unit that runs another state directory is not ours either.
	other := "[Unit]\nDescription=Pipe server\n[Service]\nExecStart=\"/usr/local/bin/pipe\" server run --dir \"/srv/other\"\n"
	must(t, os.WriteFile(filepath.Join(f.systemd, "pipe.service"), []byte(other), 0644))
	f.nftCalls, f.lines = 0, nil
	must(t, Uninstall(t.Context(), f.opts()))
	if !exists(filepath.Join(f.systemd, "pipe.service")) || !exists(filepath.Join(f.sysctl, "90-pipe.conf")) || len(f.calls) != 0 {
		t.Fatal("another install's unit and shared sysctl file must stay")
	}
	if f.nftCalls != 0 || !strings.Contains(strings.Join(f.lines, "\n"), "belongs to the install at /srv/other") {
		t.Fatalf("the live hop table must stay: nft=%d %v", f.nftCalls, f.lines)
	}
	// Inside another network namespace nft cannot reach the live table.
	f.hooks.otherNetns = func() bool { return true }
	must(t, Uninstall(t.Context(), f.opts()))
	if f.nftCalls != 1 || !exists(filepath.Join(f.systemd, "pipe.service")) {
		t.Fatalf("netns removal: nft=%d", f.nftCalls)
	}
}

func TestUninstallMatchesOldHopUnitForm(t *testing.T) {
	f := newUninstallFixture(t)
	f.installFiles(t)
	state, _ := filepath.Abs(f.dir)
	old := "[Unit]\nDescription=Pipe Fast UDP port hopping\n[Service]\nExecStart=/usr/local/bin/pipe hop-apply --dir " + unitArgument(state) + "\n"
	must(t, os.WriteFile(filepath.Join(f.systemd, "pipe-hop.service"), []byte(old), 0644))
	must(t, Uninstall(t.Context(), f.opts()))
	if exists(filepath.Join(f.systemd, "pipe-hop.service")) {
		t.Fatal("the pre-M3.1 hop unit should be removed")
	}
}

func TestUninstallKeepsHopUnitWithoutOwnPipeService(t *testing.T) {
	f := newUninstallFixture(t)
	settings, err := ReadSettings(f.dir)
	must(t, err)
	settings.FastHop = "20000-20010"
	must(t, writeJSON(f.dir, settingsFile, settings))
	f.installFiles(t)
	must(t, os.Remove(filepath.Join(f.systemd, "pipe.service")))
	must(t, Uninstall(t.Context(), f.opts()))
	if !exists(filepath.Join(f.systemd, "pipe-hop.service")) || len(f.calls) != 0 {
		t.Fatal("a hop unit without this dir's pipe.service must stay")
	}
}

func TestUninstallKeepsEditedSysctl(t *testing.T) {
	f := newUninstallFixture(t)
	f.installFiles(t)
	must(t, os.WriteFile(filepath.Join(f.sysctl, "90-pipe.conf"), []byte(sysctlConfig+"vm.swappiness = 1\n"), 0644))
	must(t, Uninstall(t.Context(), f.opts()))
	if !exists(filepath.Join(f.sysctl, "90-pipe.conf")) {
		t.Fatal("an edited sysctl file must stay")
	}
}

func TestUninstallMentionsCopiedNginxFile(t *testing.T) {
	f := newUninstallFixture(t)
	must(t, os.MkdirAll(filepath.Join(f.dir, "install"), 0700))
	must(t, os.WriteFile(filepath.Join(f.dir, "install", "pipe-nginx.conf"), []byte("x"), 0600))
	must(t, Uninstall(t.Context(), f.opts()))
	if !strings.Contains(strings.Join(f.lines, "\n"), "reload nginx") {
		t.Fatalf("expected the nginx reminder: %v", f.lines)
	}
}

func TestPurgeGuards(t *testing.T) {
	for _, path := range []string{"/", "/root", "/home", "/etc", "/usr", "/var", "/var/lib", "/tmp"} {
		f := newUninstallFixture(t)
		opts := f.opts()
		opts.Dir, opts.Purge, opts.Yes = path, true, true
		err := Uninstall(t.Context(), opts)
		if err == nil || f.nftCalls != 0 {
			t.Fatalf("%s should be rejected before anything changes: %v", path, err)
		}
	}
	// A directory with one component, even with a server.json.
	t.Run("one component", func(t *testing.T) {
		if _, err := purgeTarget("/onlyone"); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("symlink to etc", func(t *testing.T) {
		f := newUninstallFixture(t)
		link := filepath.Join(t.TempDir(), "state")
		must(t, os.Symlink("/etc", link))
		opts := f.opts()
		opts.Dir, opts.Purge, opts.Yes = link, true, true
		if err := Uninstall(t.Context(), opts); err == nil || !strings.Contains(err.Error(), "/etc") {
			t.Fatalf("a symlink to /etc must be rejected: %v", err)
		}
	})
	t.Run("missing server.json", func(t *testing.T) {
		f := newUninstallFixture(t)
		empty := t.TempDir()
		must(t, os.WriteFile(filepath.Join(empty, "keep"), nil, 0600))
		opts := f.opts()
		opts.Dir, opts.Purge, opts.Yes = empty, true, true
		if err := Uninstall(t.Context(), opts); err == nil || !exists(filepath.Join(empty, "keep")) {
			t.Fatalf("expected a refusal: %v", err)
		}
	})
	t.Run("not a terminal", func(t *testing.T) {
		f := newUninstallFixture(t)
		opts := f.opts()
		opts.Purge = true
		if err := Uninstall(t.Context(), opts); err == nil || !strings.Contains(err.Error(), "--yes") || !exists(f.dir) || f.nftCalls != 0 {
			t.Fatalf("purge without a terminal or --yes must refuse: %v", err)
		}
	})
	t.Run("declined", func(t *testing.T) {
		f := newUninstallFixture(t)
		opts := f.opts()
		opts.Purge = true
		opts.Confirm = func(string) (bool, error) { return false, nil }
		if err := Uninstall(t.Context(), opts); err == nil || !exists(f.dir) {
			t.Fatalf("declined purge must keep the directory: %v", err)
		}
	})
	t.Run("confirm error", func(t *testing.T) {
		f := newUninstallFixture(t)
		opts := f.opts()
		opts.Purge = true
		opts.Confirm = func(string) (bool, error) { return false, errors.New("eof") }
		if err := Uninstall(t.Context(), opts); err == nil || !exists(f.dir) {
			t.Fatal("expected an error")
		}
	})
}

func TestPurgeDeletesAfterConfirmation(t *testing.T) {
	f := newUninstallFixture(t)
	var asked string
	resolved, _ := filepath.EvalSymlinks(f.dir)
	opts := f.opts()
	opts.Purge = true
	opts.Confirm = func(prompt string) (bool, error) { asked = prompt; return true, nil }
	must(t, Uninstall(t.Context(), opts))
	if asked != "Delete "+resolved+" and all device keys? [y/N]" || exists(f.dir) {
		t.Fatalf("prompt=%q exists=%v", asked, exists(f.dir))
	}
}

func TestPurgeWithYesSkipsPrompt(t *testing.T) {
	f := newUninstallFixture(t)
	opts := f.opts()
	opts.Purge, opts.Yes = true, true
	must(t, Uninstall(t.Context(), opts))
	if exists(f.dir) {
		t.Fatal("directory should be deleted")
	}
}

func TestInstallOnlyReportsHopping(t *testing.T) {
	dir := initProxyTestState(t)
	settings, err := ReadSettings(dir)
	must(t, err)
	settings.FastHop = "20000-20010"
	must(t, writeJSON(dir, settingsFile, settings))
	t.Setenv("PATH", t.TempDir()) // An installer that invokes nft must fail.
	oldEUID := installEUID
	defer func() { installEUID = oldEUID }()
	for _, euid := range []int{1000, 0} {
		installEUID = func() int { return euid }
		_, hints, err := Install(t.Context(), dir, "/usr/local/bin/pipe", "", nil)
		must(t, err)
		if !strings.Contains(strings.Join(hints, "\n"), "supply --fast-hop and --fast-port") {
			t.Fatalf("euid %d did not get explicit hop setup instructions: %v", euid, hints)
		}
	}
}
