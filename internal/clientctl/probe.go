// SPDX-License-Identifier: GPL-3.0-or-later

package clientctl

import (
	"context"
	"time"

	"pipe/internal/config"
	"pipe/internal/engine"
	"pipe/internal/failover"
)

const profileProbeTimeout = 20 * time.Second

// ProbeOptions describes the profile and network for TestProfile.
type ProbeOptions = config.ProbeOptions

type probeEngine interface {
	Start() error
	Close() error
	ProbeLatency(ctx context.Context, tier string, burst bool) (stalled bool, latency time.Duration, viaRelay bool, err error)
}

// TestProfile measures each available tier with a fresh engine. A tier with no
// measurement has OK false. Rescue is only present for profiles with a CDN.
func TestProfile(ctx context.Context, options ProbeOptions) map[string]RouteLatency {
	return testProfile(ctx, options, engine.NetworkIPv6, func(ctx context.Context, opts engine.Options) (probeEngine, error) {
		return engine.New(ctx, opts)
	})
}

func testProfile(ctx context.Context, options ProbeOptions, networkIPv6 func() bool, newEngine func(context.Context, engine.Options) (probeEngine, error)) map[string]RouteLatency {
	ctx, cancel := context.WithTimeout(ctx, profileProbeTimeout)
	defer cancel()
	tiers := failover.Available(options.Profile.CDN != "")
	if ctx.Err() != nil {
		return failedRoutes(tiers)
	}
	options.IPv6 = options.IPv6 && networkIPv6()
	compiled, err := config.BuildProbe(options)
	if err != nil || ctx.Err() != nil {
		return failedRoutes(tiers)
	}
	instance, err := newEngine(ctx, compiled)
	if err != nil {
		return failedRoutes(tiers)
	}
	defer func() {
		cancel()
		_ = instance.Close()
	}()
	if ctx.Err() != nil || instance.Start() != nil {
		return failedRoutes(tiers)
	}
	timeout := probeTimeout
	if options.Relay != "" {
		timeout += engine.RelayFallbackDelay
	}
	return probeRoutes(ctx, instance, tiers, timeout, nil)
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
