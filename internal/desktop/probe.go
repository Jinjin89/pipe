// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/link"
)

const (
	profileSlotWait = 2 * time.Second
	// Allow the helper to acquire a slot, run the 20 s probe and send the results.
	profileReplyTimeout = 24 * time.Second
)

type profileTestTarget struct {
	name, revision string
	opts           clientctl.ProbeOptions
	tun            bool
}

func (s *Server) beginProfileTest(r *http.Request) (profileTestTarget, error) {
	parent := r.Context()
	wait, cancel := context.WithTimeout(parent, profileSlotWait)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	var name string
	for {
		if err := parent.Err(); err != nil {
			return profileTestTarget{}, err
		}
		var err error
		name, err = s.storedName(r)
		if err != nil {
			return profileTestTarget{}, err
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
			return profileTestTarget{}, canceled
		}
		if wait.Err() != nil {
			return profileTestTarget{}, err
		}
	}
	profile, revision, err := s.profiles.load(name)
	if err != nil {
		return profileTestTarget{}, errNoProfile
	}
	data := s.store.Snapshot()
	opts := clientctl.ProbeOptions{
		Profile: profile, Relay: data.relayFor(name, profile.Host).enabledCode(), IPv6: data.Settings.IPv6,
	}
	s.profileTests[name] = struct{}{}
	return profileTestTarget{name: name, revision: revision, opts: opts, tun: s.getVia() == viaTUN}, nil
}

type profileLatency struct {
	Ms  int64  `json:"ms"`
	OK  bool   `json:"ok"`
	Via string `json:"via,omitempty"`
}

type profileTestResponse struct {
	Routes      map[string]profileLatency `json:"routes"`
	ExitCountry string                    `json:"exitCountry,omitempty"`
	Rev         string                    `json:"rev"`
}

type profileExitKey struct {
	host, cdn             string
	fastPort, stealthPort uint16
	fingerprint           [32]byte
}

func exitCountryKey(profile link.Profile) profileExitKey {
	return profileExitKey{
		host: strings.ToLower(profile.Host), cdn: strings.ToLower(profile.CDNEndpoint()),
		fastPort: profile.FastEndpointPort(), stealthPort: profile.StealthEndpointPort(),
		fingerprint: sha256.Sum256(profile.PublicKey[:]),
	}
}

func (s *Server) testProfile(r *http.Request) (any, error) {
	target, err := s.beginProfileTest(r)
	if err != nil {
		return nil, err
	}
	defer func() {
		s.mu.Lock()
		delete(s.profileTests, target.name)
		close(s.profileTestDone)
		s.profileTestDone = make(chan struct{})
		s.mu.Unlock()
	}()
	parent := r.Context()
	ctx, cancel := context.WithTimeout(parent, profileReplyTimeout)
	defer cancel()
	opts := target.opts
	key := exitCountryKey(opts.Profile)
	s.mu.Lock()
	country := s.profileCountries[key]
	s.mu.Unlock()
	opts.SkipExitCountry = country != ""

	var result clientctl.ProfileTestResult
	if !target.tun {
		result = s.cfg.probeProfile(ctx, opts)
	} else if helper, ok := s.cfg.Helper.(interface {
		TestProfileResult(context.Context, clientctl.ProbeOptions) (clientctl.ProfileTestResult, error)
	}); ok {
		result, err = helper.TestProfileResult(ctx, opts)
	} else {
		result.Routes, err = s.cfg.Helper.TestProfile(ctx, opts)
	}
	if canceled := parent.Err(); canceled != nil {
		return nil, canceled
	}
	if err != nil && (!errors.Is(err, context.DeadlineExceeded) || len(result.Routes) == 0) {
		return nil, err
	}
	tiers := []string{"fast", "stealth"}
	if opts.Profile.CDN != "" {
		tiers = append(tiers, "rescue")
	}
	reply := profileTestResponse{Rev: target.revision, Routes: make(map[string]profileLatency, len(tiers))}
	hasSuccess := false
	for _, tier := range tiers {
		probe, measured := result.Routes[tier]
		if !measured {
			continue
		}
		latency := profileLatency{Ms: probe.Ms, OK: probe.OK}
		if probe.OK {
			hasSuccess = true
			if probe.Via == "relay" {
				latency.Via = probe.Via
			}
		}
		reply.Routes[tier] = latency
	}
	if hasSuccess {
		if country == "" {
			country = clientctl.NormalizeExitCountry(result.ExitCountry)
			if country != "" {
				s.mu.Lock()
				s.profileCountries[key] = country
				s.mu.Unlock()
			}
		}
		reply.ExitCountry = country
	}
	return reply, nil
}
