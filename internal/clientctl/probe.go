// SPDX-License-Identifier: GPL-3.0-or-later

package clientctl

import (
	"context"
	"time"

	"pipe/internal/config"
	"pipe/internal/engine"
	"pipe/internal/failover"
	"pipe/internal/link"

	"github.com/sagernet/sing/service"
)

const (
	profileProbeTimeout = 20 * time.Second
	exitCountryTimeout  = 2 * time.Second
	RTTMetricVersion    = 1
)

// ProbeOptions describes the profile and network for TestProfile.
type ProbeOptions struct {
	Profile         link.Profile
	Relay           string
	IPv6            bool
	Interface       string // physical uplink when a TUN session is active
	SkipExitCountry bool   // the desktop session already has a cached country
	PreferLive      bool   // the caller matched the running profile revision
}

type ProfileTestResult struct {
	Routes        map[string]RouteLatency `json:"routes,omitempty"`
	Error         string                  `json:"error,omitempty"` // setup failed or the test was interrupted
	ExitCountry   string                  `json:"exitCountry,omitempty"`
	MetricVersion int                     `json:"metricVersion,omitempty"`
	CompletedAt   time.Time               `json:"completedAt,omitzero"`
	EffectiveIPv6 *bool                   `json:"effectiveIPv6,omitempty"`
}

type probeEngine interface {
	Start() error
	Close() error
	ProbeLatency(ctx context.Context, tier string, burst bool) (stalled bool, latency time.Duration, viaRelay bool, err error)
}

// TestProfile measures each available tier with a fresh engine and looks up
// the exit country through one successful tier while the engine is open.
func TestProfile(ctx context.Context, options ProbeOptions) ProfileTestResult {
	return testProfile(ctx, options, engine.NetworkIPv6, func(ctx context.Context, opts engine.Options) (probeEngine, error) {
		return engine.New(ctx, opts)
	}, lookupExitCountry)
}

func testProfile(ctx context.Context, options ProbeOptions, networkIPv6 func() bool, newEngine func(context.Context, engine.Options) (probeEngine, error), lookupCountry func(context.Context, string) string) ProfileTestResult {
	ctx, cancel := context.WithTimeout(ctx, profileProbeTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return interruptedProfileTest()
	}
	ipv6 := options.IPv6 && networkIPv6()
	compiled, err := config.BuildProbe(config.ProbeOptions{
		Profile: options.Profile, Relay: options.Relay, Interface: options.Interface, IPv6: ipv6,
	})
	if err != nil {
		return ProfileTestResult{Error: "Could not configure the profile test."}
	}
	if ctx.Err() != nil {
		return interruptedProfileTest()
	}
	// Sing-box registers the outbound manager in this engine's own registry.
	ctx = service.ContextWithRegistry(ctx, service.NewRegistry())
	instance, err := newEngine(ctx, compiled)
	if err != nil {
		return ProfileTestResult{Error: "Could not create the profile test engine."}
	}
	defer func() {
		cancel()
		_ = instance.Close()
	}()
	if ctx.Err() != nil {
		return interruptedProfileTest()
	}
	if err := instance.Start(); err != nil {
		return ProfileTestResult{Error: "Could not start the profile test."}
	}
	result := measureProfile(ctx, instance, failover.Available(options.Profile.CDN != ""), options, lookupCountry)
	if result.Error == "" {
		result.EffectiveIPv6 = &ipv6
	}
	return result
}

// MeasureProfile tries the live engine when it is running with these options.
// The caller matches the saved revision before asking to use the live engine.
func (c *Controller) MeasureProfile(ctx context.Context, options ProbeOptions) (ProfileTestResult, bool) {
	c.stateMu.Lock()
	s, online := c.owner, c.status.State == StateOn
	c.stateMu.Unlock()
	if !online || s == nil || !s.opts.UsesProxy() || s.opts.Profile != options.Profile ||
		s.opts.Relay != options.Relay || s.opts.IPv6 != options.IPv6 || !s.begin() {
		return ProfileTestResult{}, false
	}
	defer s.work.Done()
	ctx, cancel := context.WithTimeout(ctx, profileProbeTimeout)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	if e, ok := s.engine.(interface {
		ProbeContext(context.Context) context.Context
	}); ok {
		ctx = e.ProbeContext(ctx)
	}
	result := measureProfile(ctx, s.engine, failover.Available(options.Profile.CDN != ""), options, lookupExitCountry)
	if s.ctx.Err() != nil {
		return interruptedProfileTest(), true
	}
	if result.Error == "" {
		result.EffectiveIPv6 = new(s.opts.IPv6 && s.netIPv6)
	}
	return result, true
}

func interruptedProfileTest() ProfileTestResult {
	return ProfileTestResult{Error: "The profile test was interrupted."}
}

func measureProfile(ctx context.Context, instance probeEngine, tiers []failover.Tier, options ProbeOptions, lookupCountry func(context.Context, string) string) ProfileTestResult {
	if ctx.Err() != nil {
		return interruptedProfileTest()
	}
	timeout := probeTimeout
	if options.Relay != "" {
		timeout += engine.RelayFallbackDelay
	}
	routes := sampleRoutes(ctx, tiers, timeout, func(ctx context.Context, tier string) RouteLatency {
		if rtt, ok := instance.(interface {
			MeasureRTT(context.Context, string) (time.Duration, bool, error)
		}); ok {
			latency, via, err := rtt.MeasureRTT(ctx, tier)
			entry := routeLatency(latency.Round(time.Millisecond), err == nil && ctx.Err() == nil, via)
			if latency == 0 {
				entry.Ms = 0 // A single valid legacy reply establishes reachability.
			}
			return entry
		}
		stalled, _, via, err := instance.ProbeLatency(ctx, tier, false)
		entry := routeLatency(0, err == nil && !stalled, via)
		entry.Ms = 0
		return entry
	}, nil)
	if ctx.Err() != nil {
		return interruptedProfileTest()
	}
	var country string
	if !options.SkipExitCountry && ctx.Err() == nil {
		for _, tier := range tiers {
			if !routes[string(tier)].OK {
				continue
			}
			countryCtx, cancel := context.WithTimeout(ctx, exitCountryTimeout)
			code := lookupCountry(countryCtx, string(tier))
			if countryCtx.Err() == nil {
				country = code
			}
			cancel()
			break
		}
	}
	return ProfileTestResult{
		Routes: routes, ExitCountry: country, MetricVersion: RTTMetricVersion, CompletedAt: time.Now().UTC(),
	}
}

func probeRoutes(ctx context.Context, instance probeEngine, tiers []failover.Tier, timeout time.Duration, record func(string, RouteLatency)) map[string]RouteLatency {
	result := sampleRoutes(ctx, tiers, timeout, func(ctx context.Context, tier string) RouteLatency {
		stalled, latency, via, err := instance.ProbeLatency(ctx, tier, false)
		return routeLatency(latency, err == nil && !stalled, via)
	}, record)
	return result
}

func sampleRoutes(ctx context.Context, tiers []failover.Tier, timeout time.Duration, measure func(context.Context, string) RouteLatency, record func(string, RouteLatency)) map[string]RouteLatency {
	type measurement struct {
		tier  string
		entry RouteLatency
	}
	measured := make(chan measurement, len(tiers))
	for _, tier := range tiers {
		go func() {
			probeCtx, cancel := context.WithTimeout(ctx, timeout)
			entry := measure(probeCtx, string(tier))
			cancel()
			measured <- measurement{string(tier), entry}
		}()
	}
	result := make(map[string]RouteLatency, len(tiers))
	for range tiers {
		m := <-measured
		result[m.tier] = m.entry
		if record != nil {
			record(m.tier, m.entry)
		}
	}
	return result
}

func routeLatency(latency time.Duration, ok, viaRelay bool) RouteLatency {
	entry := RouteLatency{At: time.Now(), OK: ok}
	if ok {
		entry.Ms = max(latency.Milliseconds(), 1)
		if viaRelay {
			entry.Via = "relay"
		}
	}
	return entry
}
