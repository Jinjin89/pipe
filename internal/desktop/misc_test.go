// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/localfile"
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
	args := strings.Join(browserArgs("file:///fixture/boot.html", "/p"), " ")
	for _, want := range []string{"--app=file:///fixture/boot.html", "--user-data-dir=/p", "--no-proxy-server", "--window-size=1040,700", "--disable-extensions"} {
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
	if err := localfile.WritePrivate(filepath.Join(dir, "app.instance"), raw); err != nil {
		t.Fatal(err)
	}
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
	t.Setenv("HOME", t.TempDir())
	e := newEnv(t)
	out := make(bootstrapOutput, 2)
	dir := t.TempDir()
	opts := AppOptions{Config: e.srv.cfg, NoWindow: true, Stdout: out}
	opts.Dir = dir
	opts.ProfilesDir = filepath.Join(dir, "profiles")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, opts) }()
	var path string
	select {
	case line := <-out:
		path = strings.TrimSpace(line)
	case err := <-done:
		t.Fatalf("app exited before printing its bootstrap path: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("app did not print its bootstrap path")
	}
	if strings.Contains(path, "#boot=") || !filepath.IsAbs(path) || filepath.Ext(path) != ".html" {
		t.Fatal("expected the path to a browser bootstrap file")
	}
	if body, err := os.ReadFile(path); err != nil || !strings.Contains(string(body), "http://127.0.0.1:") {
		t.Fatalf("expected the bootstrap file to target the local server: %v", err)
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

func TestRunRetriesProxyRestoreAfterContextCancellation(t *testing.T) {
	e := newEnv(t)
	e.login()
	if resp, _ := e.api("POST", "/api/profiles", `{"link":"`+testLink(t, "phone", "")+`"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("add profile returned %d", resp.StatusCode)
	}
	var restoreAllowed atomic.Bool
	attempts := 0
	firstAttempt := make(chan struct{})
	restoreErr := errors.New("fixture restore failure")
	e.proxy.onRestore = func() {
		e.proxy.restoreErr = restoreErr
		if restoreAllowed.Load() {
			e.proxy.restoreErr = nil
		}
		attempts++
		if attempts == 1 {
			close(firstAttempt)
		}
	}
	ready := make(chan *App, 1)
	opts := AppOptions{Config: e.srv.cfg, Background: true, Started: func(a *App) { ready <- a }}
	ctx, cancel := context.WithCancel(t.Context())
	defer func() {
		restoreAllowed.Store(true)
		cancel()
	}()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, opts) }()
	var a *App
	select {
	case a = <-ready:
	case err := <-done:
		t.Fatalf("app exited during startup: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("app did not start")
	}
	if err := a.srv.Connect(); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-firstAttempt:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not trigger proxy restoration")
	}
	if e.ctl.Status().State != clientctl.StateOn || !e.srv.cfg.Proxy.Armed() {
		t.Fatal("failed restoration lost the proxy listener or recovery snapshot")
	}
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get(a.url + "/")
	if err != nil {
		t.Fatalf("app HTTP server stopped while waiting for proxy restoration: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("app HTTP server returned %d while waiting for proxy restoration", resp.StatusCode)
	}
	restoreAllowed.Store(true)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("app quit failed after proxy restoration: %v", err)
		}
	case <-time.After(shutdownRetryInterval + 3*time.Second):
		t.Fatal("app did not quit after retrying proxy restoration")
	}
	if attempts < 2 || e.proxy.state != "orig" || e.ctl.Status().State != clientctl.StateOff || e.srv.cfg.Proxy.Armed() {
		t.Fatalf("app did not restore the original proxy before exit, attempts = %d", attempts)
	}
}

type bootstrapOutput chan string

func (out bootstrapOutput) Write(p []byte) (int, error) {
	out <- string(p)
	return len(p), nil
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
