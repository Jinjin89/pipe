// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"context"
	"crypto/sha256"
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

type profileIdentity struct{ name, revision string }

type profileTestTarget struct {
	profileIdentity
	opts clientctl.ProbeOptions
	tun  bool
}

func (s *Server) beginProfileTest(r *http.Request, selected bool) (profileTestTarget, error) {
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
		if selected {
			if !running(s.active().Status()) {
				return profileTestTarget{}, &apiError{status: http.StatusConflict, msg: "Connect first."}
			}
			name = s.store.Snapshot().Active
		} else {
			name, err = s.storedName(r)
			if err != nil {
				return profileTestTarget{}, err
			}
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
	id := profileIdentity{name, revision}
	opts.PreferLive = data.Active == name && s.liveProfile == id
	s.profileTests[name] = false
	return profileTestTarget{profileIdentity: id, opts: opts, tun: s.getVia() == viaTUN}, nil
}

// invalidateProfileTest discards a result for a replaced, renamed or deleted
// profile while its probe finishes. The caller holds s.mu.
func (s *Server) invalidateProfileTest(name string) {
	if _, testing := s.profileTests[name]; testing {
		s.profileTests[name] = true
	}
}

type profileLatency struct {
	Ms  int64  `json:"ms"`
	OK  bool   `json:"ok"`
	Via string `json:"via,omitempty"`
}

type profileTestResponse struct {
	Routes        map[string]profileLatency `json:"routes"`
	ExitCountry   string                    `json:"exitCountry,omitempty"`
	Rev           string                    `json:"rev"`
	Profile       string                    `json:"profile"`
	MetricVersion int                       `json:"metricVersion"`
	CompletedAt   time.Time                 `json:"completedAt"`
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
	return s.measureProfile(r, false)
}

func (s *Server) measureProfile(r *http.Request, selected bool) (any, error) {
	target, err := s.beginProfileTest(r, selected)
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
		used := false
		if local, ok := s.cfg.Controller.(interface {
			MeasureProfile(context.Context, clientctl.ProbeOptions) (clientctl.ProfileTestResult, bool)
		}); ok && opts.PreferLive {
			result, used = local.MeasureProfile(ctx, opts)
		}
		if !used {
			result = s.cfg.probeProfile(ctx, opts)
		}
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
	if err != nil {
		return nil, err
	}
	if result.Error != "" {
		return nil, &apiError{status: http.StatusServiceUnavailable, msg: result.Error}
	}
	tiers := []string{"fast", "stealth"}
	if opts.Profile.CDN != "" {
		tiers = append(tiers, "rescue")
	}
	reply := profileTestResponse{
		Rev: target.revision, Profile: target.name, Routes: make(map[string]profileLatency, len(tiers)),
		MetricVersion: clientctl.RTTMetricVersion, CompletedAt: result.CompletedAt,
	}
	if reply.CompletedAt.IsZero() {
		reply.CompletedAt = time.Now().UTC()
	}
	hasSuccess := false
	for _, tier := range tiers {
		probe, measured := result.Routes[tier]
		if !measured {
			continue
		}
		latency := profileLatency{OK: probe.OK}
		if probe.OK {
			if result.MetricVersion == clientctl.RTTMetricVersion {
				latency.Ms = max(0, probe.Ms)
			}
			hasSuccess = true
			if probe.Via == "relay" {
				latency.Via = probe.Via
			}
		}
		reply.Routes[tier] = latency
	}
	if len(reply.Routes) == 0 {
		return nil, &apiError{status: http.StatusConflict, msg: "The profile test was interrupted."}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := parent.Err(); err != nil {
		return nil, err
	}
	current, rev, loadErr := s.profiles.load(target.name)
	data := s.store.Snapshot()
	if s.profileTests[target.name] || loadErr != nil || rev != target.revision || data.Settings.IPv6 != opts.IPv6 ||
		data.relayFor(target.name, current.Host).enabledCode() != opts.Relay {
		return nil, &apiError{status: http.StatusConflict, msg: "The profile changed during the test."}
	}
	if hasSuccess {
		if country == "" {
			country = clientctl.NormalizeExitCountry(result.ExitCountry)
			if country != "" {
				s.profileCountries[key] = country
			}
		}
		reply.ExitCountry = country
	}
	if err := s.store.Update(func(d *appData) {
		d.setMeasurement(target.name, savedMeasurement{
			profileTestResponse: reply, Relay: opts.Relay, IPv6: opts.IPv6, EffectiveIPv6: result.EffectiveIPv6,
		})
	}); err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Server) completeProfileBatch(r *http.Request) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if err := s.store.Update(func(d *appData) { d.LastProfileBatch = now }); err != nil {
		return nil, err
	}
	return map[string]any{"lastTestedAt": now}, nil
}
