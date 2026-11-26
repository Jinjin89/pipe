// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/helper"
	"pipe/internal/update"
)

func TestUpdateRouteRequiresConfirmedDisconnection(t *testing.T) {
	for _, tc := range []struct {
		name        string
		state, via  string
		helperInfo  string
		helperState string
		dialErr     error
		localGuard  bool
		helperGuard bool
		direct      bool
		viaHelper   bool
	}{
		{state: clientctl.StateOff, direct: true},
		{state: clientctl.StateError},
		{state: "indeterminate"},
		{state: clientctl.StateConnecting},
		{state: clientctl.StateOff, via: viaProxy},
		{state: clientctl.StateError, via: viaTUN},
		{state: clientctl.StateOff, helperInfo: helper.StateOK, helperState: clientctl.StateOn, viaHelper: true},
		{name: "helper dial timeout", state: clientctl.StateOff, dialErr: context.DeadlineExceeded},
		{name: "helper permission denied", state: clientctl.StateOff, dialErr: syscall.EACCES},
		{state: clientctl.StateOff, helperInfo: helper.StateOutdated, helperState: clientctl.StateOff, direct: true},
		{state: clientctl.StateOff, helperInfo: helper.StateMissing, helperState: clientctl.StateError, direct: true},
		{state: clientctl.StateOff, helperInfo: helper.StateUnsupported, helperState: clientctl.StateError, direct: true},
		{name: "local capture guard", state: clientctl.StateOff, localGuard: true},
		{name: "helper capture guard", state: clientctl.StateOff, helperInfo: helper.StateOK, helperState: clientctl.StateOff, helperGuard: true},
	} {
		name := tc.name
		if name == "" {
			name = tc.state + "/" + tc.via + "/" + tc.helperInfo
		}
		t.Run(name, func(t *testing.T) {
			s := &Server{cfg: Config{Controller: &fakeCtl{state: tc.state, guarded: tc.localGuard}}}
			info := helper.Info{State: tc.helperInfo}
			state := tc.helperState
			if tc.dialErr != nil {
				info = helper.Info{State: helper.StateError, Note: tc.dialErr.Error()}
				state = clientctl.StateError
			}
			h := &updateTestHelper{fakeHelper: &fakeHelper{
				fakeCtl: &fakeCtl{state: state, guarded: tc.helperGuard}, info: info,
			}}
			if info.State != "" {
				s.cfg.Helper = h
			}
			s.setVia(tc.via)
			// An unsupported installed version makes the direct route fail
			// before any network call. The unavailable route has its own error.
			m := update.NewManager("invalid", update.Target{OS: "linux", ABI: "amd64"}, t.TempDir())
			t.Cleanup(m.Close)
			m.Check(s.updateRoute(), false)
			if (h.checks == 1) != tc.viaHelper {
				t.Fatalf("Helper route selected %d times, want selected: %t", h.checks, tc.viaHelper)
			}
			deadline := time.Now().Add(time.Second)
			for st := m.Status(); time.Now().Before(deadline); st = m.Status() {
				if st.State == "error" {
					want := update.ErrTunnelUnavailable.Error()
					if tc.direct {
						want = "Updates are unavailable for this build."
					}
					if st.Error != want {
						t.Fatalf("unexpected route result: %+v", st)
					}
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Fatal("update check did not finish")
		})
	}
}

func TestUpdateCheckSelectsRouteAfterConnectionStarts(t *testing.T) {
	dir := t.TempDir()
	ctl := &fakeCtl{state: clientctl.StateOff}
	s := NewServer(Config{Dir: dir, ProfilesDir: filepath.Join(dir, "profiles"), Controller: ctl, Version: "invalid"})
	t.Cleanup(s.updates.Close)
	s.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.mu.Unlock()
		}
	}()
	accepted := make(chan error, 1)
	go func() {
		_, err := s.checkUpdate(httptest.NewRequest(http.MethodPost, "/api/updates/check", nil))
		accepted <- err
	}()
	deadline := time.Now().Add(time.Second)
	for s.updates.Status().State != "checking" {
		if time.Now().After(deadline) {
			t.Fatal("desktop check did not queue while the route was locked")
		}
		time.Sleep(time.Millisecond)
	}
	s.updates.CancelDirect()
	ctl.mu.Lock()
	ctl.state = clientctl.StateConnecting
	ctl.mu.Unlock()
	s.mu.Unlock()
	locked = false
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("desktop check did not respond")
	}

	deadline = time.Now().Add(time.Second)
	for st := s.updates.Status(); time.Now().Before(deadline); st = s.updates.Status() {
		if st.State == "error" {
			if st.Error != update.ErrTunnelUnavailable.Error() {
				t.Fatalf("check used the disconnected route: %+v", st)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("desktop check did not finish")
}

func TestUpdateActionsShareDesktopAuthorization(t *testing.T) {
	e := newEnv(t)
	for _, action := range []string{"check", "download", "reveal", "apply"} {
		res := e.do(http.MethodPost, "/api/updates/"+action, "{}")
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s: %d", action, res.StatusCode)
		}
	}
	e.login()
	if err := e.srv.store.Update(func(d *appData) { d.Settings.UpdateAuto = new(false) }); err != nil {
		t.Fatal(err)
	}
	res, status := e.api(http.MethodPost, "/api/updates/check", `{"automatic":true}`)
	if res.StatusCode != http.StatusOK || status["state"] != "idle" || status["installed"] != "9.9.9-test" {
		t.Fatalf("automatic check ignored saved setting: %d %+v", res.StatusCode, status)
	}
	res, _ = e.api(http.MethodPost, "/api/updates/reveal", `{"artifact":"../unverified.zip"}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unverified file reached reveal: %d", res.StatusCode)
	}
}

func TestUpdateInstallPolicy(t *testing.T) {
	for _, tc := range []struct {
		goos, exe string
		canApply  bool
		hint      string
	}{
		{"linux", "/home/alice/bin/pipe", true, ""},
		{"linux", "/usr/local/bin/pipe", false, "Run sudo pipe update to install."},
		{"linux", "/usr/bin/pipe", false, "Update Pipe with your system package manager."},
		{"linux", "/bin/pipe", false, "Update Pipe with your system package manager."},
		{"linux", "/usr/sbin/pipe", false, "Update Pipe with your system package manager."},
		{"linux", "/sbin/pipe", false, "Update Pipe with your system package manager."},
		{"linux", "/usr/bin-portable/pipe", true, ""},
		{"darwin", "/Applications/Pipe.app/Contents/MacOS/Pipe", false, "Quit Pipe, then replace Pipe.app in Applications."},
		{"windows", `C:\Pipe\Pipe.exe`, false, "Quit Pipe, then replace Pipe.exe and pipe-cli.exe together."},
	} {
		t.Run(tc.goos+"/"+tc.exe, func(t *testing.T) {
			if apply, hint := updateInstallPolicy(tc.goos, tc.exe); apply != tc.canApply || hint != tc.hint {
				t.Errorf("policy = (%t, %q), want (%t, %q)", apply, hint, tc.canApply, tc.hint)
			}
		})
	}
}

func TestApplyUpdateRejectsUnsupportedInstall(t *testing.T) {
	e := newEnv(t)
	e.srv.cfg.Exe = "/usr/local/bin/pipe"
	e.srv.cfg.extractUpdate = func(string) (*os.File, string, func(), error) {
		t.Error("unsupported install reached artifact extraction")
		return nil, "", nil, errors.New("unexpected extraction")
	}
	e.login()
	res, body := e.api(http.MethodPost, "/api/updates/apply", `{"artifact":"verified-handle"}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("apply response = %d, %v", res.StatusCode, body)
	}
	res, status := e.api(http.MethodGet, "/api/updates", "")
	if res.StatusCode != http.StatusOK || status["canApply"] != nil {
		t.Fatalf("unsupported status = %d, %v", res.StatusCode, status)
	}
	if _, hint := updateInstallPolicy(runtime.GOOS, e.srv.cfg.Exe); hint != "" && status["installHint"] != hint {
		t.Errorf("status omitted the install hint: %v", status)
	}
}

func TestApplyUpdateRejectsDifferentExecutable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("portable apply is Linux-only")
	}
	e := newEnv(t)
	e.srv.cfg.Exe = filepath.Join(t.TempDir(), "pipe")
	if err := os.WriteFile(e.srv.cfg.Exe, []byte("other binary"), 0700); err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.extractUpdate = func(string) (*os.File, string, func(), error) {
		t.Error("unrelated executable reached artifact extraction")
		return nil, "", nil, errors.New("unexpected extraction")
	}
	e.login()
	res, body := e.api(http.MethodPost, "/api/updates/apply", `{"artifact":"verified-handle"}`)
	if res.StatusCode != http.StatusBadRequest || body["error"] != "The install path does not match the running Pipe executable." {
		t.Fatalf("apply response = %d, %v", res.StatusCode, body)
	}
}

func TestApplyUpdateInstallsVerifiedHandle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("portable apply is Linux-only")
	}
	exe, err := filepath.EvalSymlinks("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	e.srv.cfg.Exe = exe
	const handle, offered, contents = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "9.9.10-test", "verified binary fixture"
	staged, err := os.CreateTemp(t.TempDir(), "pipe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { staged.Close() })
	if _, err := staged.WriteString(contents); err != nil {
		t.Fatal(err)
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	var installed, cleaned atomic.Bool
	e.srv.cfg.extractUpdate = func(requested string) (*os.File, string, func(), error) {
		if requested != handle {
			return e.srv.updates.ExtractVerifiedLinuxBinary(requested)
		}
		return staged, offered, func() {
			staged.Close()
			cleaned.Store(true)
		}, nil
	}
	e.srv.cfg.applyPortable = func(source *os.File, dest string) error {
		data, err := io.ReadAll(source)
		if err != nil {
			return err
		}
		if source != staged || string(data) != contents || dest != exe {
			t.Errorf("unexpected apply source or destination: %q to %s", data, dest)
		}
		installed.Store(true)
		return nil
	}
	e.login()
	res, body := e.api(http.MethodPost, "/api/updates/apply", `{"artifact":"../unverified"}`)
	if res.StatusCode != http.StatusBadRequest || installed.Load() {
		t.Fatalf("invalid handle response = %d, %v", res.StatusCode, body)
	}
	res, body = e.api(http.MethodPost, "/api/updates/apply", strings.Repeat(" ", 1025))
	if res.StatusCode != http.StatusBadRequest || installed.Load() {
		t.Fatalf("oversized body response = %d, %v", res.StatusCode, body)
	}
	res, body = e.api(http.MethodPost, "/api/updates/apply", `{"artifact":"`+handle+`"}`)
	if res.StatusCode != http.StatusOK || body["appliedVersion"] != offered || !installed.Load() || !cleaned.Load() {
		t.Fatalf("verified apply response = %d, %v", res.StatusCode, body)
	}
	res, body = e.api(http.MethodGet, "/api/updates", "")
	if res.StatusCode != http.StatusOK || body["appliedVersion"] != offered {
		t.Fatalf("status lost the applied version = %d, %v", res.StatusCode, body)
	}
}
