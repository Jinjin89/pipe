// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"context"
	"errors"
	"net/http"
	"time"

	"pipe/internal/clientctl"
)

const (
	profileSlotWait = 2 * time.Second
	// Allow the helper to acquire a slot, run the 20 s probe and send the results.
	profileReplyTimeout = 24 * time.Second
)

func (s *Server) beginProfileTest(r *http.Request) (string, clientctl.ProbeOptions, bool, error) {
	parent := r.Context()
	wait, cancel := context.WithTimeout(parent, profileSlotWait)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	var opts clientctl.ProbeOptions
	var name string
	for {
		if err := parent.Err(); err != nil {
			return "", opts, false, err
		}
		var err error
		name, err = s.storedName(r)
		if err != nil {
			return "", opts, false, err
		}
		if _, testing := s.profileTests[name]; testing {
			err = &apiError{status: http.StatusConflict, msg: "That profile is already being tested."}
		} else if len(s.profileTests) >= 2 {
			err = &apiError{status: http.StatusTooManyRequests, msg: "Two profiles are already being tested."}
		} else {
			break
		}
		done := s.profileTestDone
		s.mu.Unlock()
		select {
		case <-done:
		case <-wait.Done():
		}
		s.mu.Lock()
		if canceled := parent.Err(); canceled != nil {
			return "", opts, false, canceled
		}
		if wait.Err() != nil {
			return "", opts, false, err
		}
	}
	profile, err := s.profiles.Load(name)
	if err != nil {
		return "", opts, false, errNoProfile
	}
	data := s.store.Snapshot()
	opts = clientctl.ProbeOptions{
		Profile: profile, Relay: data.relayFor(name, profile.Host).enabledCode(), IPv6: data.Settings.IPv6,
	}
	s.profileTests[name] = struct{}{}
	return name, opts, s.getVia() == viaTUN, nil
}

type profileLatency struct {
	Ms  int64  `json:"ms"`
	OK  bool   `json:"ok"`
	Via string `json:"via,omitempty"`
}

func (s *Server) testProfile(r *http.Request) (any, error) {
	name, opts, tun, err := s.beginProfileTest(r)
	if err != nil {
		return nil, err
	}
	defer func() {
		s.mu.Lock()
		delete(s.profileTests, name)
		close(s.profileTestDone)
		s.profileTestDone = make(chan struct{})
		s.mu.Unlock()
	}()
	parent := r.Context()
	ctx, cancel := context.WithTimeout(parent, profileReplyTimeout)
	defer cancel()
	var routes map[string]clientctl.RouteLatency
	if tun {
		routes, err = s.cfg.Helper.TestProfile(ctx, opts)
	} else {
		routes = s.cfg.probeProfile(ctx, opts)
	}
	if canceled := parent.Err(); canceled != nil {
		return nil, canceled
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	tiers := []string{"fast", "stealth"}
	if opts.Profile.CDN != "" {
		tiers = append(tiers, "rescue")
	}
	result := make(map[string]profileLatency, len(tiers))
	for _, tier := range tiers {
		probe := routes[tier]
		latency := profileLatency{Ms: probe.Ms, OK: probe.OK}
		if probe.OK && probe.Via == "relay" {
			latency.Via = probe.Via
		}
		result[tier] = latency
	}
	return map[string]any{"routes": result}, nil
}
