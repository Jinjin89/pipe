// SPDX-License-Identifier: GPL-3.0-or-later

package helper

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/logring"
)

func newRemote(sock string, version string, logs *logring.Ring) *Remote {
	r := NewRemote(RemoteOptions{Socket: sock, Version: version, Exe: "/Apps/Pipe", Logs: logs})
	r.trustedPath = func(path string) (string, error) { return path, nil }
	return r
}

func TestRemoteRefusesInstallerWhenRunningImageCannotBeRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe-fixture")
	if err := os.WriteFile(path, []byte("fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	r := NewRemote(RemoteOptions{Socket: "fixture", Exe: path})
	r.goos = "linux"
	r.openImage = func(string) (*os.File, error) { return nil, os.ErrPermission }
	r.lookPath = func(string) (string, error) { return "fixture", nil }
	called := false
	r.run = func(string, ...string) ([]byte, error) {
		called = true
		return nil, nil
	}
	if err := r.elevate(false); err == nil || called {
		t.Fatalf("unsafe installer reached the elevation hook: %v", err)
	}
}

func TestRemotePortableInstallerPassesRunningDigestToOSStager(t *testing.T) {
	if _, supported := PathsFor(runtime.GOOS); !supported {
		t.Skip("portable Helper installation uses Unix executable permissions")
	}
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			dir, perm := "home/alex/pipe", os.FileMode(0700)
			if platform == "darwin" {
				dir, perm = "Applications/Pipe.app/Contents/MacOS", 0775
			}
			base := t.TempDir()
			if err := os.MkdirAll(filepath.Join(base, dir), perm); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(base, dir, "Pipe's binary")
			contents := []byte("unit test running image")
			if err := os.WriteFile(path, contents, 0755); err != nil {
				t.Fatal(err)
			}
			r := NewRemote(RemoteOptions{Socket: "fixture", Exe: path})
			r.goos = platform
			r.openImage = os.Open
			r.lookPath = func(string) (string, error) { return "fixture", nil }
			called := false
			r.run = func(name string, args ...string) ([]byte, error) {
				called = true
				paths, _ := PathsFor(platform)
				want := []string{"-c", stageHelperScript, "pipe-helper", path, fmt.Sprintf("%x", sha256.Sum256(contents)),
					filepath.Dir(paths.Binary), strconv.Itoa(os.Getuid()), platform}
				if len(args) < len(want) || !reflect.DeepEqual(args[len(args)-len(want):], want) {
					t.Errorf("stager did not receive the running image and digest (launcher %s)", name)
				}
				if platform == "darwin" && (name != "osascript" || !strings.Contains(strings.Join(args, "\n"), `set commandLine to "/bin/sh"`)) ||
					platform == "linux" && (name != "pkexec" || args[0] != "/bin/sh") {
					t.Errorf("unexpected launcher %s", name)
				}
				return nil, nil
			}
			if err := r.elevate(false); err != nil || !called {
				t.Fatalf("portable installation did not reach staging: %v", err)
			}
		})
	}
}

func TestPortableDigestSurvivesMacImagePathReplacement(t *testing.T) {
	if _, supported := PathsFor(runtime.GOOS); !supported {
		t.Skip("portable Helper installation uses Unix executable permissions")
	}
	path := filepath.Join(t.TempDir(), "Pipe")
	original := []byte("early image fixture")
	if err := os.WriteFile(path, original, 0755); err != nil {
		t.Fatal(err)
	}
	r := NewRemote(RemoteOptions{Socket: "fixture", Exe: path})
	r.goos = "darwin"
	r.darwinDigest = pinHelperDigest(path, os.Open)
	if err := os.Rename(path, path+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	gotPath, digest, err := r.installImage()
	if gotPath != path || digest != fmt.Sprintf("%x", sha256.Sum256(original)) || err != nil {
		t.Fatalf("installer did not use the early open image: %v", err)
	}
}

func TestStagedHelperVerifiesTheRootOwnedCopyBeforeExecution(t *testing.T) {
	if os.Geteuid() != 0 || (runtime.GOOS != "linux" && runtime.GOOS != "darwin") {
		t.Skip("shell fixture requires a protected directory owned by root")
	}
	dir, err := os.MkdirTemp(".", ".helper-stage-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	const fixture = "#!/bin/sh\nprintf '%s\\n' \"$*\"\n"
	for _, name := range []string{"verified bytes", "path replaced before copy", "changed bytes during copy"} {
		t.Run(name, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "portable")
			if err := os.WriteFile(source, []byte(fixture), 0755); err != nil {
				t.Fatal(err)
			}
			digest := fmt.Sprintf("%x", sha256.Sum256([]byte(fixture)))
			script := stageHelperScript
			switch name {
			case "path replaced before copy":
				replacement := source + "-new"
				if err := os.WriteFile(replacement, []byte("different bytes"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, source); err != nil {
					t.Fatal(err)
				}
			case "changed bytes during copy":
				const copyImage = `cat < "$source" > "$staged"`
				script = strings.Replace(script, copyImage, copyImage+` && printf '\nchanged bytes\n' >> "$staged"`, 1)
			}
			out, err := exec.Command("/bin/sh", "-c", script, "pipe-helper", source, digest, dir, "501", runtime.GOOS).CombinedOutput()
			if name == "verified bytes" {
				if err != nil || strings.TrimSpace(string(out)) != "helper install --uid 501" {
					t.Fatalf("verified image did not run: %v, %s", err, out)
				}
			} else if err == nil || !strings.Contains(string(out), "changed before it could be installed") {
				t.Fatalf("altered image was not rejected by the digest check: %v, %s", err, out)
			}
			if entries, err := os.ReadDir(dir); len(entries) != 0 || err != nil {
				t.Fatalf("staged copies left behind: %v, %v", entries, err)
			}
		})
	}
}

func TestRemoteRemovalValidatesInstalledHelperEvenWithPortableGUI(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			r := NewRemote(RemoteOptions{Socket: "fixture", Exe: filepath.Join(t.TempDir(), "portable GUI")})
			r.goos = platform
			paths, _ := PathsFor(platform)
			r.trustedPath = func(path string) (string, error) {
				if path != paths.Binary {
					t.Errorf("validated %q, want installed helper %q", path, paths.Binary)
					return "", os.ErrPermission
				}
				return path, nil
			}
			r.lookPath = func(string) (string, error) { return "fixture", nil }
			r.openImage = func(string) (*os.File, error) { t.Fatal("opened GUI image for removal"); return nil, nil }
			r.run = func(name string, args ...string) ([]byte, error) {
				wantName, wantArgs := elevateCommand(platform, paths.Binary, os.Getuid(), true)
				if name != wantName || !reflect.DeepEqual(args, wantArgs) {
					t.Error("removal did not use the protected helper")
				}
				return nil, nil
			}
			if err := r.elevate(true); err != nil {
				t.Fatal(err)
			}
		})
	}
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

func TestRemoteHelperVersionAndProtocol(t *testing.T) {
	for _, tc := range []struct {
		name, ver, want string
		protocol        int
	}{
		{"newer release", "1.2.4", StateNewer, ProtocolVersion},
		{"newer release with older protocol", "1.2.4", StateNewer, ProtocolVersion - 1},
		{"newer protocol with older release", "1.2.2", StateNewer, ProtocolVersion + 1},
		{"older release", "1.2.2", StateOutdated, ProtocolVersion},
		{"older protocol", "1.2.3", StateOutdated, ProtocolVersion - 1},
		{"uncomparable build", "local", StateOutdated, ProtocolVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := relayTestRemote(t, func(_ context.Context, req Request) (any, string) {
				if req.Method != "hello" {
					t.Errorf("sent %q to an incompatible Helper", req.Method)
					return nil, "unexpected method"
				}
				return map[string]any{"version": tc.ver, "protocol": tc.protocol}, ""
			})
			r.goos = "linux"
			if info := r.Info(); info.State != tc.want || info.Version != tc.ver {
				t.Fatalf("Helper info = %+v, want state %q and version %q", info, tc.want, tc.ver)
			}
			if tc.want != StateNewer {
				return
			}
			if info := r.Info(); info.Note != msgNewer {
				t.Errorf("newer Helper note = %q, want %q", info.Note, msgNewer)
			}
			if err := r.Start(testOptions(t)); !errors.Is(err, ErrNewer) {
				t.Errorf("starting a session with a newer Helper returned %v", err)
			}
			r.lookPath = func(string) (string, error) { return "pkexec", nil }
			r.run = func(string, ...string) ([]byte, error) {
				t.Error("downgrade reached the elevation command")
				return nil, ErrNewer
			}
			// A host upgrade can happen while the GUI still has cached
			// information about the old Helper.
			r.info = Info{State: StateOutdated}
			r.infoAt = time.Now()
			if err := r.Install(); !errors.Is(err, ErrNewer) {
				t.Errorf("install over a newer Helper returned %v", err)
			}
		})
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

func TestRemoteDistinguishesSocketDialErrors(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		err         error
	}{
		{"socket absent", StateMissing, syscall.ENOENT},
		{"dial timeout", StateError, context.DeadlineExceeded},
		{"permission denied", StateError, syscall.EACCES},
		{"operation not permitted", StateError, syscall.EPERM},
		{"connection refused", StateError, syscall.ECONNREFUSED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRemote("helper.sock", "1", nil)
			r.dialContext = func(context.Context, string, string) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", tc.err)}
			}
			r.info, r.infoAt = Info{State: StateOK}, time.Now()
			if err := r.Stop(); (err == nil) != (tc.state == StateMissing) {
				t.Fatalf("Stop result for %s: %v", tc.state, err)
			}
			if !r.infoAt.IsZero() {
				t.Fatal("Stop left the old Helper info cached")
			}
			if info := r.Info(); info.State != tc.state {
				t.Fatalf("got Helper state %+v, want %s", info, tc.state)
			}
		})
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
