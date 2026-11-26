// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("desktop check selected its route before returning")
	}
	s.updates.CancelDirect()
	ctl.mu.Lock()
	ctl.state = clientctl.StateConnecting
	ctl.mu.Unlock()
	s.mu.Unlock()
	locked = false

	deadline := time.Now().Add(time.Second)
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
	for _, action := range []string{"check", "download", "reveal"} {
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
