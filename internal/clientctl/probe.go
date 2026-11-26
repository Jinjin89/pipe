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
)

// ProbeOptions describes the profile and network for TestProfile.
type ProbeOptions struct {
	Profile         link.Profile
	Relay           string
	IPv6            bool
	Interface       string // physical uplink when a TUN session is active
	SkipExitCountry bool   // the desktop session already has a cached country
}

type ProfileTestResult struct {
	Routes      map[string]RouteLatency `json:"routes"`
	ExitCountry string                  `json:"exitCountry,omitempty"`
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
	tiers := failover.Available(options.Profile.CDN != "")
	if ctx.Err() != nil {
		return ProfileTestResult{Routes: failedRoutes(tiers)}
	}
	compiled, err := config.BuildProbe(config.ProbeOptions{
		Profile: options.Profile, Relay: options.Relay, Interface: options.Interface, IPv6: options.IPv6 && networkIPv6(),
	})
	if err != nil || ctx.Err() != nil {
		return ProfileTestResult{Routes: failedRoutes(tiers)}
	}
	// Sing-box registers the outbound manager in this engine's own registry.
	ctx = service.ContextWithRegistry(ctx, service.NewRegistry())
	instance, err := newEngine(ctx, compiled)
	if err != nil {
		return ProfileTestResult{Routes: failedRoutes(tiers)}
	}
	defer func() {
		cancel()
		_ = instance.Close()
	}()
	if ctx.Err() != nil || instance.Start() != nil {
		return ProfileTestResult{Routes: failedRoutes(tiers)}
	}
	timeout := probeTimeout
	if options.Relay != "" {
		timeout += engine.RelayFallbackDelay
	}
	result := ProfileTestResult{Routes: probeRoutes(ctx, instance, tiers, timeout, nil)}
	if options.SkipExitCountry || ctx.Err() != nil {
		return result
	}
	for _, tier := range tiers {
		if !result.Routes[string(tier)].OK {
			continue
		}
		countryCtx, cancel := context.WithTimeout(ctx, exitCountryTimeout)
		country := lookupCountry(countryCtx, string(tier))
		if countryCtx.Err() == nil {
			result.ExitCountry = country
		}
		cancel()
		break
	}
	return result
}

func failedRoutes(tiers []failover.Tier) map[string]RouteLatency {
	result := make(map[string]RouteLatency, len(tiers))
	now := time.Now()
	for _, tier := range tiers {
		result[string(tier)] = RouteLatency{At: now}
	}
	return result
}

func probeRoutes(ctx context.Context, instance probeEngine, tiers []failover.Tier, timeout time.Duration, record func(string, RouteLatency)) map[string]RouteLatency {
	type measurement struct {
		tier  string
		entry RouteLatency
	}
	measured := make(chan measurement, len(tiers))
	for _, tier := range tiers {
		go func() {
			probeCtx, cancel := context.WithTimeout(ctx, timeout)
			stalled, latency, via, err := instance.ProbeLatency(probeCtx, string(tier), false)
			cancel()
			measured <- measurement{string(tier), routeLatency(latency, err == nil && !stalled, via)}
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
