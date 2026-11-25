// SPDX-License-Identifier: GPL-3.0-or-later

package clientctl

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"pipe/internal/engine"
)

func TestProfileProbeIPv6(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		preferred, network, enable bool
	}{
		{"IPv4-only network", true, false, false},
		{"IPv6 disabled", false, true, false},
		{"IPv6 available", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := ProbeOptions{Profile: opts().Profile, IPv6: tc.preferred}
			checked := false
			networkIPv6 := func() bool {
				checked = true
				return tc.network
			}
			routes := testProfile(t.Context(), options, networkIPv6, func(_ context.Context, compiled engine.Options) (probeEngine, error) {
				dns := compiled.Config["dns"].(engine.Object)
				hasIPv6Upstream := slices.ContainsFunc(dns["servers"].([]engine.Object), func(server engine.Object) bool {
					address, _ := server["server"].(string)
					ip, _ := netip.ParseAddr(address)
					return ip.Is6()
				})
				if (dns["strategy"] != "ipv4_only") != tc.enable || hasIPv6Upstream != tc.enable {
					t.Fatalf("probe DNS with IPv6 enabled=%t: %v", tc.enable, dns)
				}
				for _, outbound := range compiled.Config["outbounds"].([]engine.Object) {
					resolver := outbound["domain_resolver"].(engine.Object)
					if (resolver["strategy"] != "ipv4_only") != tc.enable {
						t.Fatalf("%s resolver with IPv6 enabled=%t: %v", outbound["tag"], tc.enable, resolver)
					}
				}
				return &fakeEngine{}, nil
			})
			if !routes["fast"].OK || checked != tc.preferred {
				t.Fatalf("probe results %v, network checked=%t, want checked=%t", routes, checked, tc.preferred)
			}
		})
	}
}

func TestProfileProbeResults(t *testing.T) {
	instance := &fakeEngine{
		latency:     map[string]time.Duration{"fast": 45 * time.Millisecond, "rescue": 150 * time.Millisecond},
		viaRelay:    map[string]bool{"fast": true, "stealth": true},
		failTier:    map[string]bool{"stealth": true},
		relayStates: map[string]string{"fast": "direct", "rescue": "via"},
	}
	options := ProbeOptions{Profile: opts().Profile, Relay: "relay.example:8444", Interface: "uplink0"}
	routes := testProfile(t.Context(), options, func() bool { return false }, func(_ context.Context, compiled engine.Options) (probeEngine, error) {
		if route := compiled.Config["route"].(engine.Object); route["default_interface"] != options.Interface {
			t.Fatalf("interface was not passed to BuildProbe: %v", route)
		}
		return instance, nil
	})
	if !instance.started.Load() || !instance.closed.Load() {
		t.Fatal("profile engine was not started and closed")
	}
	if fast := routes["fast"]; !fast.OK || fast.Ms != 45 || fast.Via != "relay" {
		t.Fatalf("unexpected Fast result %+v", fast)
	}
	if stealth := routes["stealth"]; stealth.OK || stealth.Ms != 0 || stealth.Via != "" {
		t.Fatalf("unexpected failed Stealth result %+v", stealth)
	}
	if rescue := routes["rescue"]; !rescue.OK || rescue.Ms != 150 || rescue.Via != "" {
		t.Fatalf("unexpected Rescue result %+v", rescue)
	}
	if data, err := json.Marshal(routes); err != nil || strings.Count(string(data), `"via"`) != 1 {
		t.Fatalf("expected exactly one serialized relay result, got %s: %v", data, err)
	}
}

func TestProfileProbeDeadlinesAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name, relay string
		duration    time.Duration
	}{
		{"direct", "", 8 * time.Second},
		{"relay", "relay.example", 9 * time.Second},
		{"canceled", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				instance := &fakeEngine{block: true}
				options := ProbeOptions{Profile: opts().Profile, Relay: tc.relay}
				options.Profile.CDN = ""
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				start := time.Now()
				done := make(chan map[string]RouteLatency, 1)
				go func() {
					done <- testProfile(ctx, options, func() bool { return false }, func(ctx context.Context, _ engine.Options) (probeEngine, error) {
						if deadline, ok := ctx.Deadline(); !ok || deadline.Sub(start) != 20*time.Second {
							t.Errorf("profile deadline %v, want a 20-second cap", deadline.Sub(start))
						}
						return instance, nil
					})
				}()
				synctest.Wait()
				if instance.inProbe.Load() != 2 {
					t.Fatal("Fast and Stealth did not start together")
				}
				if tc.duration == 0 {
					cancel()
				}
				routes := <-done
				if elapsed := time.Since(start); elapsed != tc.duration {
					t.Fatalf("probe took %v, want %v", elapsed, tc.duration)
				}
				if len(routes) != 2 || routes["fast"].OK || routes["stealth"].OK || !instance.closed.Load() {
					t.Fatalf("unexpected results after timeout or cancellation: %+v", routes)
				}
			})
		})
	}
}

func TestProfileProbeClosesOnStartFailure(t *testing.T) {
	instance := &fakeEngine{startErr: errors.New("start failed")}
	routes := testProfile(t.Context(), ProbeOptions{Profile: opts().Profile}, func() bool { return false }, func(context.Context, engine.Options) (probeEngine, error) {
		return instance, nil
	})
	if !instance.closed.Load() {
		t.Fatal("engine was not closed after failed start")
	}
	for _, tier := range []string{"fast", "stealth", "rescue"} {
		if route, ok := routes[tier]; !ok || route.OK || route.Via != "" {
			t.Fatalf("%s should be marked failed, got %+v", tier, routes)
		}
	}
}
