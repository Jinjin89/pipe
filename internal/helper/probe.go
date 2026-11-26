// SPDX-License-Identifier: GPL-3.0-or-later

package helper

import (
	"context"
	"encoding/json"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/config"
	"pipe/internal/link"
)

const (
	profileTestTimeout  = 20 * time.Second
	profileSlotWait     = 2 * time.Second
	profileReplyTimeout = profileSlotWait + profileTestTimeout + time.Second
)

func (s *server) testProfile(parent context.Context, raw json.RawMessage) (any, string) {
	var p TestProfileParams
	if json.Unmarshal(raw, &p) != nil {
		return nil, "That request isn't valid."
	}
	profile, err := link.Parse(p.Link)
	if err != nil {
		return nil, "That link isn't a valid Pipe link."
	}
	relay, err := config.ParseRelay(p.Relay, profile.Host)
	if err != nil {
		return nil, err.Error()
	}
	if errText := s.acquireProfileSlot(parent); errText != "" {
		return nil, errText
	}
	defer func() { <-s.probeSlots }()
	if err := parent.Err(); err != nil {
		return nil, err.Error()
	}
	uplink := s.opts.Session.DefaultInterface()
	if uplink == "" {
		return nil, "Pipe couldn't find the physical network for this test."
	}
	ctx, cancel := context.WithTimeout(parent, profileTestTimeout)
	defer cancel()
	result := s.opts.probeProfile(ctx, clientctl.ProbeOptions{
		Profile: profile, Relay: relay.String(), IPv6: p.IPv6, Interface: uplink, SkipExitCountry: p.SkipExitCountry,
	})
	if err := parent.Err(); err != nil {
		return nil, err.Error()
	}
	return result, ""
}

func (s *server) acquireProfileSlot(ctx context.Context) string {
	wait, cancel := context.WithTimeout(ctx, profileSlotWait)
	defer cancel()
	select {
	case s.probeSlots <- struct{}{}:
		return ""
	case <-wait.Done():
		if err := ctx.Err(); err != nil {
			return err.Error()
		}
		return "Two profiles are already being tested."
	}
}

// TestProfile returns timings through the active TUN session's uplink.
func (r *Remote) TestProfile(ctx context.Context, opts clientctl.ProbeOptions) (map[string]clientctl.RouteLatency, error) {
	result, err := r.TestProfileResult(ctx, opts)
	return result.Routes, err
}

// TestProfileResult also returns the optional exit country from the helper.
func (r *Remote) TestProfileResult(ctx context.Context, opts clientctl.ProbeOptions) (clientctl.ProfileTestResult, error) {
	var result clientctl.ProfileTestResult
	text, err := opts.Profile.Encode()
	if err != nil {
		return result, err
	}
	params := TestProfileParams{Link: text, Relay: opts.Relay, IPv6: opts.IPv6, SkipExitCountry: opts.SkipExitCountry}
	callCtx, cancel := context.WithTimeout(ctx, profileReplyTimeout)
	defer cancel()
	_, err = r.call(callCtx, profileReplyTimeout+time.Second, "testProfile", params, &result)
	if ctxErr := callCtx.Err(); ctxErr != nil {
		return result, ctxErr
	}
	return result, err
}
