// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFindBrowser(t *testing.T) {
	env := func(k string) string {
		return map[string]string{"ProgramFiles": `C:\Program Files`, "ProgramFiles(x86)": `C:\Program Files (x86)`, "HOME": "/Users/x"}[k]
	}
	none := func(string) (string, error) { return "", errors.New("no") }
	edge := filepath.Join(`C:\Program Files (x86)`, `Microsoft\Edge\Application\msedge.exe`)
	if got := findBrowser("windows", env, func(p string) bool { return p == edge }, none); got != edge {
		t.Errorf("windows edge: %q", got)
	}
	chrome := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	if got := findBrowser("darwin", env, func(p string) bool { return p == chrome }, none); got != chrome {
		t.Errorf("mac chrome: %q", got)
	}
	look := func(n string) (string, error) {
		if n == "chromium" {
			return "/usr/bin/chromium", nil
		}
		return "", errors.New("no")
	}
	if got := findBrowser("linux", env, func(string) bool { return false }, look); got != "/usr/bin/chromium" {
		t.Errorf("linux chromium: %q", got)
	}
	if got := findBrowser("linux", env, func(string) bool { return false }, none); got != "" {
		t.Errorf("none installed: %q", got)
	}
	args := strings.Join(browserArgs("http://127.0.0.1:1/#boot=x", "/p"), " ")
	for _, want := range []string{"--app=http://127.0.0.1:1/#boot=x", "--user-data-dir=/p", "--no-proxy-server", "--window-size=1040,700", "--disable-extensions"} {
		if !strings.Contains(args, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestAutostartFiles(t *testing.T) {
	home := t.TempDir()
	cases := map[string]string{
		"linux":  filepath.Join(home, ".config", "autostart", "pipe.desktop"),
		"darwin": filepath.Join(home, "Library", "LaunchAgents", "io.pipe.app.plist"),
	}
	for goos, path := range cases {
		a := autostartFor(goos, home)
		if err := a.Enable("/opt/My Apps/pipe"); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), "--background") || !strings.Contains(string(data), "My Apps") {
			t.Fatalf("%s: %v %s", goos, err, data)
		}
		if err := a.Disable(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("not removed")
		}
		if err := a.Disable(); err != nil {
			t.Fatal("second disable must be quiet:", err)
		}
	}
	if !strings.Contains(AutostartDesktop("/opt/My Apps/pipe"), `Exec="/opt/My Apps/pipe" app --background`) {
		t.Fatal(AutostartDesktop("/opt/My Apps/pipe"))
	}
}

func TestInstallDesktopEntry(t *testing.T) {
	data := t.TempDir()
	entry, err := InstallDesktopEntry(data, "/usr/local/bin/pipe")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(entry)
	if !strings.Contains(string(body), `Exec="/usr/local/bin/pipe" app`) || !strings.Contains(string(body), "Icon=pipe") {
		t.Fatalf("%s", body)
	}
	icon, err := os.ReadFile(filepath.Join(data, "icons", "hicolor", "256x256", "apps", "pipe.png"))
	if err != nil || len(icon) < 100 || string(icon[1:4]) != "PNG" {
		t.Fatalf("icon: %v", err)
	}
}

func TestSingleInstanceShowsExisting(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t)
	shown := make(chan struct{}, 1)
	e.srv.cfg.OnShow = func() { shown <- struct{}{} }
	port := 0
	if _, err := fmtSscan(strings.TrimPrefix(e.ts.URL, "http://127.0.0.1:"), &port); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(instanceFile{Port: port, Secret: e.srv.ShowSecret()})
	os.WriteFile(filepath.Join(dir, "app.instance"), raw, 0600)
	if err := showExisting(dir); err != nil {
		t.Fatal(err)
	}
	select {
	case <-shown:
	case <-time.After(time.Second):
		t.Fatal("not shown")
	}
}

func TestRunLockAndQuit(t *testing.T) {
	e := newEnv(t)
	var out strings.Builder
	dir := t.TempDir()
	opts := AppOptions{Config: e.srv.cfg, NoWindow: true, Stdout: &out}
	opts.Dir = dir
	opts.ProfilesDir = filepath.Join(dir, "profiles")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, opts) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "app.instance")); err == nil && strings.Contains(out.String(), "#boot=") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "http://127.0.0.1:") {
		t.Fatalf("no URL printed: %q", out.String())
	}
	// A second Run with the same dir finds the lock held and asks the first to show.
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal("second instance:", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "app.instance")); !os.IsNotExist(err) {
		t.Fatal("instance file left behind")
	}
}

func TestBackgroundSecondInstanceExitsQuietly(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	release, _, err := acquireLock(filepath.Join(dir, "app.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	opts := AppOptions{Config: e.srv.cfg, Background: true}
	opts.Dir = dir
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal("--background with a running instance must exit 0:", err)
	}
}

func TestStaleInstanceFileRemoved(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.instance"), []byte(`{"port":1,"secret":"old"}`), 0600)
	opts := AppOptions{Config: e.srv.cfg, Background: true, NoWindow: true}
	opts.Dir = dir
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, opts) }()
	time.Sleep(300 * time.Millisecond)
	raw, _ := os.ReadFile(filepath.Join(dir, "app.instance"))
	if strings.Contains(string(raw), "old") {
		t.Fatal("stale instance file kept")
	}
	cancel()
	<-done
}
