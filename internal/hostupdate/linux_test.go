// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux

package hostupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"pipe/internal/clientctl"
	"pipe/internal/helper"
	"pipe/internal/localfile"
	"pipe/internal/update"
	"pipe/internal/version"
)

const (
	helperBinary = "/usr/local/lib/pipe/pipe-helper"
	oldVersion   = "0.7.5-alpha"
	newVersion   = "0.7.6-alpha"
)

type fixtureUnit struct {
	binary, arguments, state, dropIns string
	pid                               int
}

type fixtureHost struct {
	t             *testing.T
	host          linuxHost
	ctl           string
	units         map[string]*fixtureUnit
	commands      []string
	restarts      []string
	installs      []string
	requests      []update.ResolveOptions
	helperVersion []string
	helperChecks  int
	runningChecks int
	nextPID       int
	failedRestart string
}

func newFixtureHost(t *testing.T) *fixtureHost {
	t.Helper()
	f := &fixtureHost{t: t, units: make(map[string]*fixtureUnit), nextPID: 200}
	f.host = linuxHost{
		root: t.TempDir(), command: f.command,
		checkTrusted: func(path string) error {
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
				return errors.New("unprotected fixture file")
			}
			return nil
		},
		trustedRunning: func(path string) (*os.File, error) {
			f.runningChecks++
			return os.Open(path)
		},
		resolve: func(context.Context, update.ResolveOptions) (update.StagedRelease, error) {
			t.Fatal("resolved a release before validating the installation")
			return update.StagedRelease{}, nil
		},
		install: f.install,
		helperStatus: func() clientctl.Status {
			f.helperChecks++
			return clientctl.Status{State: clientctl.StateOff}
		},
		helperReady: func(want string) bool {
			f.helperVersion = append(f.helperVersion, want)
			return true
		},
	}
	t.Setenv("XDG_CONFIG_HOME", f.host.path("/config"))
	return f
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixtureHost) write(path string, data []byte, mode os.FileMode) {
	f.t.Helper()
	real := f.host.path(path)
	check(f.t, os.MkdirAll(filepath.Dir(real), 0755))
	check(f.t, os.WriteFile(real, data, mode))
}

func (f *fixtureHost) binary(path, tag string) { f.write(path, fixtureImage(tag), 0755) }

func (f *fixtureHost) self(path string) {
	f.t.Helper()
	proc := f.host.path("/proc/self/exe")
	check(f.t, os.MkdirAll(filepath.Dir(proc), 0755))
	check(f.t, os.Symlink(f.host.path(path), proc))
}

func (f *fixtureHost) systemd(path string) {
	f.t.Helper()
	check(f.t, os.MkdirAll(f.host.path("/run/systemd/system"), 0755))
	f.write(path, []byte("fixture systemctl"), 0755)
	f.ctl = f.host.path(path)
}

func (f *fixtureHost) unit(name, path, args, state string) *fixtureUnit {
	f.t.Helper()
	f.write("/etc/systemd/system/"+name, []byte("fixture unit"), 0644)
	u := &fixtureUnit{binary: path, arguments: args, state: state}
	f.units[name] = u
	if state == "active" && (name == "pipe.service" || name == helper.UnitName) && strings.HasPrefix(path, "/usr/local/") {
		f.activate(u)
	}
	return u
}

func (f *fixtureHost) activate(u *fixtureUnit) {
	f.t.Helper()
	f.nextPID++
	u.state, u.pid = "active", f.nextPID
	exe := f.host.path(fmt.Sprintf("/proc/%d/exe", u.pid))
	check(f.t, os.MkdirAll(filepath.Dir(exe), 0755))
	check(f.t, os.Link(f.host.path(u.binary), exe))
}

func (f *fixtureHost) command(_ context.Context, path string, args ...string) (string, error) {
	f.t.Helper()
	if f.ctl == "" || path != f.ctl {
		f.t.Fatalf("unexpected systemctl executable %s", path)
	}
	call := strings.Join(args, " ")
	f.commands = append(f.commands, call)
	if args[0] == "show" {
		if len(args) != 3 || args[1] != unitShow {
			f.t.Fatalf("unexpected systemctl show flags %v", args)
		}
		name := args[2]
		u := f.units[name]
		if u == nil {
			return "LoadState=not-found\nActiveState=inactive\nMainPID=0\n", errors.New("unit not found")
		}
		return fmt.Sprintf("LoadState=loaded\nActiveState=%s\nFragmentPath=/etc/systemd/system/%s\nDropInPaths=%s\nMainPID=%d\n"+
			"ExecStart={ path=%s ; argv[]=%s %s ; ignore_errors=no ; }\n", u.state, name, u.dropIns, u.pid, u.binary, u.binary, u.arguments), nil
	}
	f.restarts = append(f.restarts, call)
	u := f.units[args[1]]
	if u == nil || (args[0] != "try-restart" && args[0] != "restart") {
		f.t.Fatalf("unexpected systemctl command %v", args)
	}
	if f.failedRestart == call {
		u.state, u.pid = "failed", 0
		return "", errors.New("fixture restart failed")
	}
	if args[0] == "restart" || u.state == "active" {
		f.activate(u)
	}
	return "", nil
}

func (f *fixtureHost) install(source *os.File, dest string) error {
	f.installs = append(f.installs, dest)
	parent := filepath.Dir(dest)
	file, err := os.CreateTemp(parent, ".fixture-install-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, io.NewSectionReader(source, 0, info.Size())); err != nil {
		return err
	}
	if err := file.Chmod(0755); err != nil {
		return err
	}
	return os.Rename(file.Name(), dest)
}

func fixtureImage(tag string) []byte {
	image := make([]byte, 512)
	copy(image, "\x7fELF")
	image[4], image[5] = 2, 1
	binary.LittleEndian.PutUint16(image[16:], 2)
	machine := uint16(62)
	if runtime.GOARCH == "arm64" {
		machine = 183
	}
	binary.LittleEndian.PutUint16(image[18:], machine)
	return fmt.Appendf(image, "%c%s linux %s %s%c", 0, "pipe-desktop-release-v1", runtime.GOARCH, tag, 0)
}

func (f *fixtureHost) signedRelease(tag string) string {
	f.t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	check(f.t, err)
	f.host.resolve = func(ctx context.Context, request update.ResolveOptions) (update.StagedRelease, error) {
		f.requests = append(f.requests, request)
		request.Key = pub
		return update.Resolve(ctx, request)
	}
	return f.writeSignedRelease(tag, key)
}

func (f *fixtureHost) writeSignedRelease(tag string, key ed25519.PrivateKey) string {
	f.t.Helper()
	target := update.Target{OS: "linux", ABI: runtime.GOARCH}
	if target.Filename() == "" {
		f.t.Skip("no release archive for this Linux architecture")
	}
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"pipe", fixtureImage(tag)}, {"README.txt", []byte("Fixture release")}} {
		check(f.t, tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0755, Size: int64(len(entry.data)), Typeflag: tar.TypeReg}))
		_, err := tw.Write(entry.data)
		check(f.t, err)
	}
	check(f.t, tw.Close())
	check(f.t, gz.Close())
	manifest := fmt.Appendf(nil, "pipe-sha256sums-v1\nversion %s\nchannel alpha\nlinux %s %s %d %x\n",
		tag, runtime.GOARCH, target.Filename(), archive.Len(), sha256.Sum256(archive.Bytes()))
	dir := filepath.Join("/release", tag)
	f.write(filepath.Join(dir, target.Filename()), archive.Bytes(), 0644)
	f.write(filepath.Join(dir, update.ManifestFilename), manifest, 0644)
	f.write(filepath.Join(dir, update.SignatureFilename), ed25519.Sign(key, manifest), 0644)
	return f.host.path(dir)
}

func (f *fixtureHost) expectBinary(path, tag string) {
	f.t.Helper()
	data, err := os.ReadFile(f.host.path(path))
	check(f.t, err)
	if !bytes.Equal(data, fixtureImage(tag)) {
		_, _, got, _ := version.ParseIdentity(data)
		f.t.Fatalf("%s contains release %s, want %s", path, got, tag)
	}
}

func (f *fixtureHost) expectNoBackups() {
	f.t.Helper()
	check(f.t, filepath.WalkDir(f.host.root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && (strings.HasSuffix(d.Name(), ".bak") || strings.HasPrefix(d.Name(), ".rollback-") || strings.HasPrefix(d.Name(), "cli-stage-")) {
			return fmt.Errorf("left temporary update data at %s", path)
		}
		return err
	}))
}

func TestSystemInventoryAndNonRootPreview(t *testing.T) {
	f := newFixtureHost(t)
	f.host.uid = 1000
	f.systemd("/bin/systemctl")
	f.binary(pipeBinary, newVersion)
	f.binary(relayBinary, oldVersion)
	f.binary(helperBinary, oldVersion)
	f.unit("pipe.service", pipeBinary, "server run --dir /var/lib/pipe", "active")
	f.unit("pipe-hop.service", pipeBinary, "server hop-apply", "active")
	f.unit("pipe-relay.service", relayBinary, "relay apply", "active")
	f.unit(helper.UnitName, helperBinary, "helper run", "active")
	f.host.resolve = func(_ context.Context, request update.ResolveOptions) (update.StagedRelease, error) {
		if !request.CheckOnly || !request.ReadOnlyState || request.StateDir != f.host.path(systemUpdateState) || request.Installed != oldVersion || request.Newest != newVersion {
			t.Fatalf("unexpected release preview request %+v", request)
		}
		return update.StagedRelease{Version: newVersion, StateUnverified: true}, nil
	}
	var out bytes.Buffer
	check(t, f.host.run(t.Context(), Options{Check: true, From: "fixture", Out: &out}))
	for _, path := range []string{pipeBinary, relayBinary, helperBinary} {
		if strings.Count(out.String(), " at "+f.host.path(path)+"\n") != 1 {
			t.Fatalf("target %s missing or duplicated in %s", path, &out)
		}
	}
	for _, want := range []string{
		"Offered Pipe " + newVersion, "Would restart " + helper.UnitName,
		"Would update " + f.host.path(relayBinary), "Would update " + f.host.path(helperBinary),
		"sudo pipe update --check", "next apply or boot",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("preview missing %q in %s", want, &out)
		}
	}
	if strings.Contains(out.String(), "Would restart pipe.service") || strings.Contains(out.String(), "Would update "+f.host.path(pipeBinary)) {
		t.Fatalf("preview included an already current server in the plan: %s", &out)
	}
	if len(f.installs)+len(f.restarts)+f.runningChecks+f.helperChecks != 0 {
		t.Fatal("a check changed or attempted to restart the installation")
	}
	if err := f.host.run(t.Context(), Options{From: "fixture", Out: io.Discard}); err == nil || !strings.Contains(err.Error(), "sudo pipe update") {
		t.Fatalf("unprivileged system apply returned %v", err)
	}
}

func TestLegacyRelayDeduplicatesSystemBinary(t *testing.T) {
	f := newFixtureHost(t)
	f.systemd("/usr/bin/systemctl")
	f.binary(pipeBinary, oldVersion)
	f.unit("pipe-relay.service", pipeBinary, "relay apply", "active")
	f.unit("pipe-hop.service", pipeBinary, "server hop-apply", "active")
	inv, err := f.host.inventory(t.Context())
	check(t, err)
	if !inv.system || !slices.Equal(inv.targets, []string{f.host.path(pipeBinary)}) || len(inv.units) != 2 {
		t.Fatalf("legacy units did not share the system executable: %+v", inv)
	}
}

func TestNonRootPreviewCanSkipRootPrivateState(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("fixture requires a root-owned directory")
	}
	f := newFixtureHost(t)
	f.host.uid = 1000
	f.binary(pipeBinary, oldVersion)
	check(t, os.MkdirAll(f.host.path(systemUpdateState), 0700))
	from := f.signedRelease(newVersion)
	var out bytes.Buffer
	check(t, f.host.run(t.Context(), Options{Check: true, From: from, Out: &out}))
	if len(f.requests) != 1 || !f.requests[0].ReadOnlyState || f.requests[0].StateDir != "" ||
		!strings.Contains(out.String(), "could not be verified") {
		t.Fatalf("preview did not label the unchecked rollback record: %s", &out)
	}
}

func TestRejectsForeignOrUntrustedUnitBeforeApply(t *testing.T) {
	for _, name := range []string{"foreign executable", "foreign role", "untrusted drop-in", "missing executable"} {
		t.Run(name, func(t *testing.T) {
			f := newFixtureHost(t)
			f.systemd("/usr/bin/systemctl")
			f.binary(pipeBinary, oldVersion)
			u := f.unit("pipe.service", pipeBinary, "server run", "inactive")
			switch name {
			case "foreign executable":
				u.binary = "/opt/pipe"
			case "foreign role":
				u.arguments = "server setup"
			case "untrusted drop-in":
				u.dropIns = "/etc/systemd/system/pipe.service.d/override.conf"
				f.write(u.dropIns, nil, 0600)
				check(t, os.Chmod(f.host.path(u.dropIns), 0666))
			case "missing executable":
				check(t, os.Remove(f.host.path(pipeBinary)))
			}
			if err := f.host.run(t.Context(), Options{From: "fixture", Out: io.Discard}); err == nil || !strings.Contains(err.Error(), "pipe.service") {
				t.Fatalf("invalid systemd unit returned %v", err)
			}
			if _, err := os.Lstat(f.host.path(systemUpdateLock)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("update touched its lock before rejecting the unit: %v", err)
			}
		})
	}
}

func TestHelperSessionBlocksApply(t *testing.T) {
	for _, status := range []clientctl.Status{
		{State: clientctl.StateOn}, {State: clientctl.StateConnecting}, {State: clientctl.StateOff, Guarded: true}, {State: clientctl.StateError},
	} {
		t.Run(status.State, func(t *testing.T) {
			f := newFixtureHost(t)
			f.systemd("/usr/bin/systemctl")
			f.binary(helperBinary, oldVersion)
			f.self(helperBinary)
			f.unit(helper.UnitName, helperBinary, "helper run", "active")
			f.host.helperStatus = func() clientctl.Status { return status }
			from := f.signedRelease(newVersion)
			if err := f.host.run(t.Context(), Options{From: from, Out: io.Discard}); err == nil || !strings.Contains(err.Error(), "Disconnect and Quit") {
				t.Fatalf("active Helper update returned %v", err)
			}
			if len(f.installs)+len(f.restarts) != 0 {
				t.Fatal("updater touched the live Helper")
			}
			f.expectBinary(helperBinary, oldVersion)
			f.expectNoBackups()
		})
	}
}

func TestPortableOfflineUpdateWithoutSystemd(t *testing.T) {
	for _, configHome := range []string{"xdg", "home"} {
		t.Run(configHome, func(t *testing.T) {
			f := newFixtureHost(t)
			f.host.uid = 1000
			f.write("/usr/bin/systemctl", nil, 0755) // installed, but not booted
			const portable = "/home/fixture/tools/pipe"
			f.binary(portable, oldVersion)
			f.self(portable)
			t.Setenv("XDG_STATE_HOME", f.host.path("/separate-state"))
			base := f.host.path("/config")
			if configHome == "home" {
				t.Setenv("XDG_CONFIG_HOME", "")
				t.Setenv("HOME", f.host.path("/home/fixture"))
				base = f.host.path("/home/fixture/.config")
			}
			from := f.signedRelease(newVersion)
			var out bytes.Buffer
			check(t, f.host.run(t.Context(), Options{From: from, Out: &out}))
			f.expectBinary(portable, newVersion)
			f.expectNoBackups()
			stateDir := filepath.Join(base, "pipe", "updates")
			if len(f.requests) != 1 || f.requests[0].StateDir != stateDir || f.requests[0].Installed != oldVersion {
				t.Fatalf("wrong portable release selection %+v", f.requests)
			}
			_, err := os.Stat(filepath.Join(stateDir, "verified-alpha-linux-"+runtime.GOARCH+".json"))
			check(t, err)
			if f.runningChecks != 0 || len(f.commands) != 0 || !slices.Equal(f.installs, []string{f.host.path(portable)}) {
				t.Fatal("portable update used the managed service path")
			}
			if !strings.Contains(out.String(), "Updated Pipe to "+newVersion) {
				t.Fatalf("unexpected update summary %s", &out)
			}
		})
	}
}

func TestRejectsPackageManagedAndLegacyExecutables(t *testing.T) {
	for _, dir := range []string{"/usr/bin", "/bin", "/sbin", "/usr/sbin", "/home/fixture"} {
		t.Run(dir, func(t *testing.T) {
			f := newFixtureHost(t)
			path := filepath.Join(dir, "pipe")
			f.write(path, []byte("legacy executable"), 0755)
			f.self(path)
			want := "system package manager"
			if dir == "/home/fixture" {
				want = "install -m 0755"
			}
			if err := f.host.run(t.Context(), Options{Check: true, From: "fixture", Out: io.Discard}); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("installed executable check returned %v", err)
			}
		})
	}
}

func fixtureManagedSystem(t *testing.T, helperState string) *fixtureHost {
	t.Helper()
	f := newFixtureHost(t)
	f.systemd("/usr/bin/systemctl")
	f.binary(pipeBinary, oldVersion)
	f.binary(relayBinary, oldVersion)
	f.binary(helperBinary, oldVersion)
	f.self(pipeBinary)
	f.unit("pipe.service", pipeBinary, "server run --dir /var/lib/pipe", "active")
	f.unit(helper.UnitName, helperBinary, "helper run", helperState)
	f.unit("pipe-hop.service", pipeBinary, "server hop-apply", "active")
	f.unit("pipe-relay.service", relayBinary, "relay apply", "active")
	return f
}

func TestManagedUpdateRestartsOnlyActiveDaemons(t *testing.T) {
	for _, helperState := range []string{"active", "inactive"} {
		t.Run(helperState, func(t *testing.T) {
			f := fixtureManagedSystem(t, helperState)
			from := f.signedRelease(newVersion)
			var out bytes.Buffer
			check(t, f.host.run(t.Context(), Options{From: from, Out: &out}))
			for _, path := range []string{pipeBinary, relayBinary, helperBinary} {
				f.expectBinary(path, newVersion)
			}
			want := []string{"try-restart pipe.service"}
			if helperState == "active" {
				want = append(want, "try-restart "+helper.UnitName)
				if f.helperChecks != 1 || !slices.Equal(f.helperVersion, []string{newVersion}) {
					t.Fatal("active Helper did not pass idle and version checks")
				}
			} else if f.helperChecks != 0 {
				t.Fatal("stopped Helper was contacted")
			}
			if f.runningChecks != 1 || !slices.Equal(f.restarts, want) || len(f.installs) != 3 || !strings.Contains(out.String(), "next apply or boot") {
				t.Fatalf("unexpected install or restart plan %+v, %+v, %s", f.installs, f.restarts, &out)
			}
			f.expectNoBackups()
		})
	}
}

func TestMixedVersionUpdateTouchesOnlyOlderRelay(t *testing.T) {
	f := fixtureManagedSystem(t, "active")
	f.binary(pipeBinary, newVersion)
	f.binary(helperBinary, newVersion)
	f.host.helperStatus = func() clientctl.Status {
		f.helperChecks++
		return clientctl.Status{State: clientctl.StateOn}
	}
	from := f.signedRelease(newVersion)
	var out bytes.Buffer
	check(t, f.host.run(t.Context(), Options{Check: true, From: from, Out: &out}))
	if strings.Count(out.String(), "Would update ") != 1 || !strings.Contains(out.String(), "Would update "+f.host.path(relayBinary)) ||
		strings.Contains(out.String(), "Would restart ") || strings.Contains(out.String(), "pipe-hop.service") {
		t.Fatalf("unexpected mixed-version preview: %s", &out)
	}
	out.Reset()
	check(t, f.host.run(t.Context(), Options{From: from, Out: &out}))
	if len(f.restarts) != 0 || f.helperChecks != 0 || !slices.Equal(f.installs, []string{f.host.path(relayBinary)}) ||
		!strings.Contains(out.String(), "Updated "+f.host.path(relayBinary)) {
		t.Fatalf("relay update touched other installations: installs=%v, restarts=%v, Helper checks=%d\n%s", f.installs, f.restarts, f.helperChecks, &out)
	}
	f.expectBinary(relayBinary, newVersion)
	f.expectNoBackups()
}

func TestNewerFloorRecordedBeforePublicationAbortsApply(t *testing.T) {
	f := fixtureManagedSystem(t, "inactive")
	const newerVersion = "0.7.7-alpha"
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	from := f.writeSignedRelease(newVersion, key)
	newer := f.writeSignedRelease(newerVersion, key)
	f.host.resolve = func(ctx context.Context, request update.ResolveOptions) (update.StagedRelease, error) {
		if unlock, err := lockUpdate(ctx, f.host.path(systemUpdateLock), false); err == nil {
			unlock()
			t.Fatal("apply did not hold the publication lock while resolving the release")
		}
		request.Key = pub
		staged, err := update.Resolve(ctx, request)
		check(t, err)
		t.Cleanup(staged.Cleanup)
		// A second check can record a newer offer while apply is still staging.
		request.CheckOnly, request.From = true, newer
		checked, err := update.Resolve(ctx, request)
		check(t, err)
		defer cleanStage(checked)
		if checked.Version != newerVersion {
			t.Fatalf("newer check resolved %q", checked.Version)
		}
		return staged, nil
	}
	err = f.host.run(t.Context(), Options{From: from, Out: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "older version") {
		t.Fatalf("superseded release returned %v", err)
	}
	if len(f.installs) != 0 || len(f.restarts) != 0 {
		t.Fatalf("superseded release changed the installation: %v, %v", f.installs, f.restarts)
	}
	f.expectNoBackups()
}

func TestCurrentInstallDoesNotRestart(t *testing.T) {
	f := fixtureManagedSystem(t, "active")
	from := f.signedRelease(oldVersion)
	var out bytes.Buffer
	check(t, f.host.run(t.Context(), Options{From: from, Out: &out}))
	if len(f.restarts)+len(f.installs)+f.helperChecks != 0 || !strings.Contains(out.String(), "already up to date") {
		t.Fatalf("current release changed the installation: %s", &out)
	}
}

func TestFailedRestartRollsBackWithoutLeavingBackups(t *testing.T) {
	f := fixtureManagedSystem(t, "active")
	f.failedRestart = "try-restart pipe.service"
	from := f.signedRelease(newVersion)
	err := f.host.run(t.Context(), Options{From: from, Out: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "previous installation was restored") || !strings.Contains(err.Error(), "fixture restart failed") {
		t.Fatalf("failed restart returned %v", err)
	}
	for _, path := range []string{pipeBinary, relayBinary, helperBinary} {
		f.expectBinary(path, oldVersion)
	}
	if want := []string{"try-restart pipe.service", "restart pipe.service", "restart " + helper.UnitName}; !slices.Equal(f.restarts, want) {
		t.Fatalf("rollback restart plan %v, want %v", f.restarts, want)
	}
	f.expectNoBackups()
}

func TestFailedSecondReplacementRollsBackFirst(t *testing.T) {
	f := fixtureManagedSystem(t, "inactive")
	from := f.signedRelease(newVersion)
	installError := errors.New("fixture second replacement failed")
	f.host.install = func(source *os.File, dest string) error {
		if dest == f.host.path(relayBinary) {
			return installError
		}
		return f.install(source, dest)
	}
	if err := f.host.run(t.Context(), Options{From: from, Out: io.Discard}); !errors.Is(err, installError) {
		t.Fatalf("failed replacement returned %v", err)
	}
	for _, path := range []string{pipeBinary, relayBinary, helperBinary} {
		f.expectBinary(path, oldVersion)
	}
	if !slices.Equal(f.restarts, []string{"restart pipe.service"}) {
		t.Fatalf("rollback restarted %v", f.restarts)
	}
	f.expectNoBackups()
}

func TestReplacementErrorAfterRenameRollsBackChangedTarget(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "parent sync", err: fmt.Errorf("fixture sync failure: %w", localfile.ErrSyncAfterReplace)},
		{name: "unmarked committed rename", err: errors.New("fixture error after rename")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixtureManagedSystem(t, "inactive")
			from := f.signedRelease(newVersion)
			relay := f.host.path(relayBinary)
			failed := false
			f.host.install = func(source *os.File, dest string) error {
				if err := f.install(source, dest); err != nil {
					return err
				}
				if dest == relay && !failed {
					failed = true
					return tc.err
				}
				return nil
			}
			err := f.host.run(t.Context(), Options{From: from, Out: io.Discard})
			if !errors.Is(err, tc.err) || !strings.Contains(err.Error(), "previous installation was restored") {
				t.Fatalf("error after rename returned %v", err)
			}
			for _, path := range []string{pipeBinary, relayBinary, helperBinary} {
				f.expectBinary(path, oldVersion)
			}
			pipe := f.host.path(pipeBinary)
			if !slices.Equal(f.installs, []string{pipe, relay, relay, pipe}) || !slices.Equal(f.restarts, []string{"restart pipe.service"}) {
				t.Fatalf("unexpected rollback order: installs=%v, restarts=%v", f.installs, f.restarts)
			}
			f.expectNoBackups()
		})
	}
}

func TestRejectsMixedChannels(t *testing.T) {
	f := fixtureManagedSystem(t, "inactive")
	f.binary(relayBinary, "0.7.5")
	if err := f.host.run(t.Context(), Options{Check: true, From: "fixture", Out: io.Discard}); err == nil || !strings.Contains(err.Error(), "mixed release channels") {
		t.Fatalf("mixed channels returned %v", err)
	}
}

func TestPortableUpdateLockIsExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "update.lock")
	release, err := lockUpdate(t.Context(), path, true)
	check(t, err)
	defer release()
	if second, err := lockUpdate(t.Context(), path, true); err == nil {
		second()
		t.Fatal("a second updater acquired the same lock")
	}
}

func TestUpdateRejectsConflictingSources(t *testing.T) {
	if err := Run(t.Context(), Options{From: "local", Proxy: "https://example.invalid"}); err == nil || !strings.Contains(err.Error(), "cannot be used together") {
		t.Fatalf("conflicting source flags returned %v", err)
	}
}
