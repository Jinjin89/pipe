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

func (e *fakeEngine) MeasureRTT(ctx context.Context, tier string) (time.Duration, bool, error) {
	_, latency, via, err := e.ProbeLatency(ctx, tier, false)
	if err == nil && latency == 0 {
		latency = time.Millisecond
	}
	return latency, via, err
}

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
			}, lookupExitCountry).Routes
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
	}, lookupExitCountry).Routes
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
				done := make(chan ProfileTestResult, 1)
				go func() {
					done <- testProfile(ctx, options, func() bool { return false }, func(ctx context.Context, _ engine.Options) (probeEngine, error) {
						if deadline, ok := ctx.Deadline(); !ok || deadline.Sub(start) != 20*time.Second {
							t.Errorf("profile deadline %v, want a 20-second cap", deadline.Sub(start))
						}
						return instance, nil
					}, func(context.Context, string) string {
						t.Error("country lookup started without a successful route")
						return ""
					})
				}()
				synctest.Wait()
				if instance.inProbe.Load() != 2 {
					t.Fatal("Fast and Stealth did not start together")
				}
				if tc.duration == 0 {
					cancel()
				}
				result := <-done
				routes := result.Routes
				if elapsed := time.Since(start); elapsed != tc.duration {
					t.Fatalf("probe took %v, want %v", elapsed, tc.duration)
				}
				if tc.duration == 0 {
					if len(routes) != 0 || !result.CompletedAt.IsZero() || result.Error == "" {
						t.Fatalf("interrupted probe reported completed results: %+v", result)
					}
				} else if len(routes) != 2 || routes["fast"].OK || routes["stealth"].OK || result.CompletedAt.IsZero() || result.Error != "" {
					t.Fatalf("unexpected results after timeout or cancellation: %+v", routes)
				}
				if !instance.closed.Load() {
					t.Fatal("probe engine was not closed")
				}
			})
		})
	}
}

func TestProfileProbeClosesOnStartFailure(t *testing.T) {
	instance := &fakeEngine{startErr: errors.New("start failed")}
	result := testProfile(t.Context(), ProbeOptions{Profile: opts().Profile}, func() bool { return false }, func(context.Context, engine.Options) (probeEngine, error) {
		return instance, nil
	}, lookupExitCountry)
	if !instance.closed.Load() {
		t.Fatal("engine was not closed after failed start")
	}
	if len(result.Routes) != 0 || !result.CompletedAt.IsZero() || result.Error == "" {
		t.Fatalf("engine start failure reported completed results: %+v", result)
	}
}

func TestProfileProbeSetupFailureHasNoMeasurements(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts ProbeOptions
	}{
		{name: "configuration"},
		{name: "constructor", opts: ProbeOptions{Profile: opts().Profile}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := testProfile(t.Context(), tc.opts, func() bool { return false }, func(context.Context, engine.Options) (probeEngine, error) {
				return nil, errors.New("fixture constructor failed")
			}, lookupExitCountry)
			if len(result.Routes) != 0 || !result.CompletedAt.IsZero() || result.Error == "" {
				t.Fatalf("setup failure reported completed results: %+v", result)
			}
		})
	}
}

func TestProfileExitCountryKeepsTimings(t *testing.T) {
	for _, tc := range []struct {
		name, wantTier, country string
		failed                  map[string]bool
		remaining               time.Duration
		skip                    bool
	}{
		{name: "fast preferred", wantTier: "fast", country: "DE"},
		{name: "stealth preferred over rescue", wantTier: "stealth", country: "CA", failed: map[string]bool{"fast": true}},
		{name: "rescue only", wantTier: "rescue", country: "JP", failed: map[string]bool{"fast": true, "stealth": true}},
		{name: "lookup times out", wantTier: "fast"},
		{name: "remaining budget", wantTier: "fast", remaining: time.Second},
		{name: "cached", skip: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := t.Context()
				budget := 2 * time.Second
				if tc.remaining != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tc.remaining)
					defer cancel()
					budget = tc.remaining
				}
				instance := &fakeEngine{
					failTier: tc.failed,
					latency:  map[string]time.Duration{"fast": 45 * time.Millisecond, "stealth": 85 * time.Millisecond, "rescue": 150 * time.Millisecond},
					viaRelay: map[string]bool{"fast": true},
				}
				var calls []string
				start := time.Now()
				result := testProfile(ctx, ProbeOptions{Profile: opts().Profile, SkipExitCountry: tc.skip}, func() bool { return false },
					func(context.Context, engine.Options) (probeEngine, error) { return instance, nil },
					func(ctx context.Context, tier string) string {
						calls = append(calls, tier)
						if instance.closed.Load() || !instance.started.Load() {
							t.Error("lookup ran outside the probe engine's lifetime")
						}
						if deadline, ok := ctx.Deadline(); !ok || deadline.Sub(start) != budget {
							t.Errorf("lookup deadline = %v, want %v after start", deadline, budget)
						}
						if tc.country == "" {
							<-ctx.Done()
						}
						return tc.country
					})
				if tc.skip && len(calls) != 0 || !tc.skip && !slices.Equal(calls, []string{tc.wantTier}) {
					t.Fatalf("lookup tiers = %v", calls)
				}
				if result.ExitCountry != tc.country || !instance.closed.Load() {
					t.Fatalf("country = %q, engine closed = %t", result.ExitCountry, instance.closed.Load())
				}
				for tier, ms := range map[string]int64{"fast": 45, "stealth": 85, "rescue": 150} {
					if tc.failed[tier] {
						if result.Routes[tier].OK {
							t.Errorf("failed %s reported success", tier)
						}
						continue
					}
					if route := result.Routes[tier]; !route.OK || route.Ms != ms || !route.At.Equal(start) {
						t.Errorf("%s timing changed: %+v", tier, route)
					}
				}
			})
		})
	}
}

func TestMeasureProfileMatchesLiveOptions(t *testing.T) {
	h := newHarness()
	h.c.settings.SkipConnectProbe = true
	settings := opts()
	settings.Tier = "fast"
	if err := h.c.Start(settings); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.c.Stop() })
	probe := ProbeOptions{Profile: settings.Profile, IPv6: settings.IPv6, SkipExitCountry: true}
	reply, used := h.c.MeasureProfile(t.Context(), probe)
	if !used || reply.MetricVersion != RTTMetricVersion || reply.CompletedAt.IsZero() || reply.Routes["fast"].Ms != 42 {
		t.Fatalf("live measurement = %+v, used %t", reply, used)
	}
	probe.Profile.FastPort = 8443
	if _, used := h.c.MeasureProfile(t.Context(), probe); used {
		t.Fatal("reused engine for a changed profile")
	}
	if h.engineCount() != 1 {
		t.Fatal("live measurement opened another engine")
	}
}
