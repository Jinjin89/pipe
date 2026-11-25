// SPDX-License-Identifier: GPL-3.0-or-later

package helper

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/logring"
)

func newRemote(sock string, version string, logs *logring.Ring) *Remote {
	r := NewRemote(RemoteOptions{Socket: sock, Version: version, Exe: "/Apps/Pipe", Logs: logs})
	return r
}

func TestRemoteInfoStates(t *testing.T) {
	missing := newRemote(filepath.Join(t.TempDir(), "none.sock"), "1.2.3", nil)
	if i := missing.Info(); i.State != StateMissing || i.Note != msgMissing {
		t.Fatalf("missing: %+v", i)
	}
	srv := startServer(t, nil)
	if i := newRemote(srv.sock, "1.2.3", nil).Info(); i.State != StateOK || i.Version != "1.2.3" {
		t.Fatalf("ok: %+v", i)
	}
	if i := newRemote(srv.sock, "9.9.9", nil).Info(); i.State != StateOutdated || i.Version != "1.2.3" || i.Note != msgOutdated {
		t.Fatalf("outdated: %+v", i)
	}
	other := startServer(t, func(o *ServeOptions) {
		o.OwnerUID = 4242
		o.PeerUID = func(*net.UnixConn) (int, error) { return 1000, nil }
	})
	if i := newRemote(other.sock, "1.2.3", nil).Info(); i.State != StateError || i.Note != msgOtherUser {
		t.Fatalf("error: %+v", i)
	}
	none := newRemote("", "1.2.3", nil)
	none.socket = ""
	if i := none.Info(); i.State != StateUnsupported {
		t.Fatalf("unsupported: %+v", i)
	}
}

func TestRemoteInfoCache(t *testing.T) {
	r := newRemote(filepath.Join(t.TempDir(), "late.sock"), "1.2.3", nil)
	if r.Info().State != StateMissing {
		t.Fatal("want missing")
	}
	r.socket = startServer(t, nil).sock
	if r.Info().State != StateMissing {
		t.Fatal("cache not used")
	}
	r.dropInfo()
	if r.Info().State != StateOK {
		t.Fatal("cache not dropped")
	}
}

func TestRemoteStatusWhenDown(t *testing.T) {
	r := newRemote(filepath.Join(t.TempDir(), "none.sock"), "1", nil)
	st := r.Status()
	if st.State != clientctl.StateError || st.LastError != "Pipe Helper isn't answering." || st.Routes == nil || len(st.Routes) != 0 {
		t.Fatalf("%+v", st)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(testOptions(t)); err == nil || err.Error() != msgNotAnswering {
		t.Fatalf("start: %v", err)
	}
	if got := r.TestRoutes(context.Background()); got == nil || len(got) != 0 {
		t.Fatalf("routes %v", got)
	}
}

func TestRemoteSession(t *testing.T) {
	srv := startServer(t, func(o *ServeOptions) { o.FirstHold, o.LastHold = 300*time.Millisecond, 300*time.Millisecond })
	logs := logring.New(50)
	r := newRemote(srv.sock, "1.2.3", logs)
	if err := r.Start(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	if st := r.Status(); st.State != clientctl.StateOn || st.Profile != "phone" {
		t.Fatalf("status %+v", st)
	}
	srv.ring.Add("warn", "engine", "something odd")
	if e, _ := logs.Since(0, 0); len(e) != 0 {
		t.Fatal("logs must be fetched on demand, not pumped")
	}
	r.SyncLogs()
	r.SyncLogs() // the cursor keeps the second call from copying again
	if e, _ := logs.Since(0, 0); len(e) != 1 {
		t.Fatalf("logs %v", e)
	}
	if e, _ := logs.Since(0, 0); e[0].Level != "warn" || e[0].Source != "engine" || e[0].Message != "something odd" {
		t.Fatalf("entry %+v", e[0])
	}
	time.Sleep(700 * time.Millisecond) // longer than both lease waits
	if !srv.ses.running() {
		t.Fatal("lease lapsed while the app held it")
	}
	if err := r.SetMode("global"); err != nil || srv.ses.mode != "global" {
		t.Fatalf("setMode %v", err)
	}
	if err := r.SetTier("nope"); err == nil {
		t.Fatal("bad tier accepted")
	}
	if got := r.TestRoutes(context.Background()); !got["fast"].OK {
		t.Fatalf("routes %v", got)
	}
	if err := r.Stop(); err != nil || srv.ses.running() {
		t.Fatalf("stop %v", err)
	}
	r.mu.Lock()
	held := r.holdStop != nil
	r.mu.Unlock()
	if held {
		t.Fatal("hold not released")
	}
}

func TestRemoteHoldEndsWhenHelperDies(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "h.sock")
	serve := func(ses *fakeSession) (stop func()) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			Serve(ctx, ServeOptions{Socket: sock, OwnerUID: os.Getuid(), Version: "1", Session: ses,
				FirstHold: 400 * time.Millisecond, LastHold: 400 * time.Millisecond})
			close(done)
		}()
		waitFor(t, "socket", func() bool {
			c, err := net.Dial("unix", sock)
			if err == nil {
				c.Close()
			}
			return err == nil
		})
		return func() { cancel(); <-done }
	}
	defer func(d time.Duration) { holdRetry = d }(holdRetry)
	holdRetry = 50 * time.Millisecond
	stop := serve(&fakeSession{})
	r := newRemote(sock, "1", nil)
	changed := make(chan struct{}, 4)
	r.OnChange(func() { changed <- struct{}{} })
	if err := r.Start(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	time.Sleep(200 * time.Millisecond) // let the hold connect first
	stop()                             // the helper dies; its session is gone
	select {
	case <-changed:
	case <-time.After(2 * time.Second):
		t.Fatal("no change signal after the helper died")
	}
	waitFor(t, "hold slot freed", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.holdStop == nil
	})

	second := &fakeSession{}
	defer serve(second)()
	if err := r.Start(testOptions(t)); err != nil { // the user connects again
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond) // well past both lease waits
	if !second.running() {
		t.Fatal("the new session lost its lease")
	}
}

func TestElevateCommands(t *testing.T) {
	name, args := elevateCommand("darwin", "/Apps/Pipe.app/pipe", 501, false)
	wantArgs := []string{
		"-e", "on run argv",
		"-e", `do shell script (quoted form of item 1 of argv) & " helper install --uid " & item 2 of argv with prompt "Pipe wants to install Pipe Helper so TUN can start without asking again." with administrator privileges`,
		"-e", "end run", "/Apps/Pipe.app/pipe", "501",
	}
	if name != "osascript" || !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("%s %q", name, args)
	}
	name, args = elevateCommand("darwin", "/x y/pipe", 501, true)
	if name != "osascript" || !strings.Contains(args[3], `& " helper remove" with prompt`) || args[len(args)-2] != "/x y/pipe" {
		t.Fatalf("%s %q", name, args)
	}
	name, args = elevateCommand("linux", "/opt/pipe", 1000, false)
	if name != "pkexec" || !reflect.DeepEqual(args, []string{"/opt/pipe", "helper", "install", "--uid", "1000"}) {
		t.Fatalf("%s %q", name, args)
	}
	name, args = elevateCommand("linux", "/opt/pipe", 1000, true)
	if name != "pkexec" || !reflect.DeepEqual(args, []string{"/opt/pipe", "helper", "remove"}) {
		t.Fatalf("%s %q", name, args)
	}
}

func exitError(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit "+strconv.Itoa(code)).Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatal("no exit error")
	}
	return err
}

func TestRemoteElevation(t *testing.T) {
	srv := startServer(t, nil)
	r := newRemote(srv.sock, "1.2.3", nil)
	r.goos = "linux"
	r.lookPath = func(string) (string, error) { return "/usr/bin/pkexec", nil }
	var gotName string
	var gotArgs []string
	r.run = func(name string, args ...string) ([]byte, error) { gotName, gotArgs = name, args; return nil, nil }
	if err := r.Install(); err != nil {
		t.Fatal(err)
	}
	if gotName != "pkexec" || !reflect.DeepEqual(gotArgs, []string{"/Apps/Pipe", "helper", "install", "--uid", strconv.Itoa(os.Getuid())}) {
		t.Fatalf("%s %q", gotName, gotArgs)
	}

	// Dismissed prompts.
	r.run = func(string, ...string) ([]byte, error) { return nil, exitError(t, 126) }
	if err := r.Install(); !errors.Is(err, ErrCanceled) {
		t.Fatalf("pkexec 126: %v", err)
	}
	if err := r.Remove(); !errors.Is(err, ErrCanceled) {
		t.Fatalf("pkexec 126 remove: %v", err)
	}
	r.run = func(string, ...string) ([]byte, error) { return nil, exitError(t, 127) }
	if err := r.Install(); err == nil || errors.Is(err, ErrCanceled) {
		t.Fatalf("pkexec 127: %v", err)
	}
	r.goos = "darwin"
	r.run = func(string, ...string) ([]byte, error) {
		return []byte("execution error: User canceled. (-128)\n"), exitError(t, 1)
	}
	if err := r.Install(); !errors.Is(err, ErrCanceled) {
		t.Fatalf("osascript -128: %v", err)
	}
	r.run = func(string, ...string) ([]byte, error) { return []byte("boom"), exitError(t, 1) }
	if err := r.Install(); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("osascript failure: %v", err)
	}

	// pkexec missing: the sudo command.
	r.goos = "linux"
	r.lookPath = func(string) (string, error) { return "", errors.New("missing") }
	err := r.Install()
	want := "Run this once in a terminal: sudo '/Apps/Pipe' helper install --uid " + strconv.Itoa(os.Getuid())
	if err == nil || err.Error() != want {
		t.Fatalf("got %v", err)
	}
}

func TestRemoteWaitsForState(t *testing.T) {
	r := newRemote(filepath.Join(t.TempDir(), "late.sock"), "1.2.3", nil)
	r.goos = "linux"
	r.lookPath = func(string) (string, error) { return "x", nil }
	r.run = func(string, ...string) ([]byte, error) { return nil, nil }
	if err := r.Remove(); err != nil { // missing is the wanted state
		t.Fatalf("remove: %v", err)
	}
	start := time.Now()
	err := r.Install() // the helper never comes up
	if err == nil || time.Since(start) < 4*time.Second {
		t.Fatalf("returned too early or without error: %v after %v", err, time.Since(start))
	}
}

func TestRemoteStopTimeoutAndConnectedReadFailure(t *testing.T) {
	if stopLimit < 20*time.Second {
		t.Fatalf("stop timeout is too short: %v", stopLimit)
	}
	r := newRemote("connected", "1", nil)
	accepted := make(chan struct{})
	r.dialContext = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_, _ = bufio.NewReader(server).ReadBytes('\n')
			close(accepted)
			_, _ = io.Copy(io.Discard, server)
		}()
		return client, nil
	}
	notAnswering, err := r.call(context.Background(), 25*time.Millisecond, "stop", nil, nil)
	if notAnswering || err == nil || err.Error() != msgNotAnswering {
		t.Fatalf("connected read timeout classification: notAnswering=%v err=%v", notAnswering, err)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("helper connection was not accepted")
	}
	r.dialContext = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_, _ = bufio.NewReader(server).ReadBytes('\n')
		}()
		return client, nil
	}
	if err := r.Stop(); err == nil || err.Error() != msgNotAnswering {
		t.Fatalf("Stop swallowed a failure after connecting: %v", err)
	}
}
