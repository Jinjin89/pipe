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
	ctx, cancel := context.WithTimeout(parent, profileTestTimeout)
	defer cancel()
	opts := clientctl.ProbeOptions{Profile: profile, Relay: relay.String(), IPv6: p.IPv6, SkipExitCountry: p.SkipExitCountry}
	if p.PreferLive {
		if session, ok := s.opts.Session.(interface {
			MeasureProfile(context.Context, clientctl.ProbeOptions) (clientctl.ProfileTestResult, bool)
		}); ok {
			if result, used := session.MeasureProfile(ctx, opts); used {
				return profileTestReply(parent, result)
			}
		}
	}
	opts.Interface = s.opts.Session.DefaultInterface()
	if opts.Interface == "" {
		return nil, "Pipe couldn't find the physical network for this test."
	}
	return profileTestReply(parent, s.opts.probeProfile(ctx, opts))
}

func profileTestReply(parent context.Context, result clientctl.ProfileTestResult) (any, string) {
	if err := parent.Err(); err != nil {
		return nil, err.Error()
	}
	if result.Error != "" {
		return nil, result.Error
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
	params := TestProfileParams{Link: text, Relay: opts.Relay, IPv6: opts.IPv6, SkipExitCountry: opts.SkipExitCountry, PreferLive: opts.PreferLive}
	callCtx, cancel := context.WithTimeout(ctx, profileReplyTimeout)
	defer cancel()
	_, err = r.call(callCtx, profileReplyTimeout+time.Second, "testProfile", params, &result)
	if ctxErr := callCtx.Err(); ctxErr != nil {
		return result, ctxErr
	}
	return result, err
}
