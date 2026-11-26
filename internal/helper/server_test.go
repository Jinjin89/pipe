// SPDX-License-Identifier: GPL-3.0-or-later

package helper

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"pipe/internal/clientctl"
)

type guardedSessionFixture struct {
	*fakeSession
	status clientctl.Status
	stops  int
}

func (s *guardedSessionFixture) Status() clientctl.Status { return s.status }

func (s *guardedSessionFixture) StartWithReady(_ clientctl.Options, ready func() error) error {
	if err := ready(); err != nil {
		s.pauseCapture()
		return err
	}
	return nil
}

func (s *guardedSessionFixture) ApplyWithReady(opts clientctl.Options, ready func() error) error {
	return s.StartWithReady(opts, ready)
}

func (s *guardedSessionFixture) SetMode(string) error {
	s.pauseCapture()
	return errors.New("fixture rebuild failed")
}

func (s *guardedSessionFixture) pauseCapture() {
	s.status = clientctl.Status{State: clientctl.StateError, Guarded: true}
}

func (s *guardedSessionFixture) Stop() error {
	s.stops++
	s.status = clientctl.Status{State: clientctl.StateOff}
	return nil
}

func TestGuardedHelperKeepsLeaseAndDNS(t *testing.T) {
	for _, method := range []string{"start", "apply", "setMode"} {
		t.Run(method, func(t *testing.T) {
			session := &guardedSessionFixture{fakeSession: &fakeSession{}, status: clientctl.Status{State: clientctl.StateOn}}
			dns := &fakeSystemDNS{onSet: func() error { return errors.New("fixture DNS setup failed") }}
			s := &server{opts: ServeOptions{Session: session, DNS: dns, FirstHold: time.Hour}, dnsTUN: true}
			s.armLease()
			defer s.disarmLease()
			wire, err := EncodeOptions(testOptions(t))
			if err != nil {
				t.Fatal(err)
			}
			params, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			var wantDNS []string
			if method == "setMode" {
				params = []byte(`{"mode":"global"}`)
			} else {
				wantDNS = []string{"set"}
			}
			if _, message := s.dispatch(t.Context(), Request{Method: method, Params: params}); message == "" {
				t.Fatal("guarded failure was reported as success")
			}
			s.sessionStopped() // A stale stop callback must also respect the guard.
			if !session.Status().Guarded || !s.active || !s.dnsTUN || session.stops != 0 || !slices.Equal(dns.recorded(), wantDNS) {
				t.Fatalf("guard lost its lease or DNS protection: active=%t, DNS=%v, stops=%d", s.active, dns.recorded(), session.stops)
			}
			if method == "apply" {
				s.expire(s.gen)
			} else if _, message := s.dispatch(t.Context(), Request{Method: "stop"}); message != "" {
				t.Fatal(message)
			}
			if session.Status().Guarded || s.active || s.dnsTUN || session.stops != 1 || !slices.Equal(dns.recorded(), append(wantDNS, "restore")) {
				t.Fatalf("lease cleanup did not release guard and DNS: %v", dns.recorded())
			}
		})
	}
}

func TestFailedDNSOnUnchangedApplyKeepsHelperActive(t *testing.T) {
	session := &fakeSession{}
	dns := &fakeSystemDNS{}
	s := &server{opts: ServeOptions{Session: session, DNS: dns, FirstHold: time.Hour}}
	defer s.disarmLease()
	wire, err := EncodeOptions(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, message := s.dispatch(t.Context(), Request{Method: "start", Params: params}); message != "" {
		t.Fatal(message)
	}
	dns.onSet = func() error { return errors.New("fixture reapply failed") }
	if _, message := s.dispatch(t.Context(), Request{Method: "apply", Params: params}); message != "Could not set system DNS: fixture reapply failed" {
		t.Fatalf("unchanged apply returned %q", message)
	}
	if !s.active || !s.dnsTUN || !session.running() || session.stops != 0 || !slices.Equal(dns.recorded(), []string{"set", "set"}) {
		t.Fatalf("unchanged apply dropped protection: lease=%t, stops=%d, DNS=%v", s.active, session.stops, dns.recorded())
	}
}
