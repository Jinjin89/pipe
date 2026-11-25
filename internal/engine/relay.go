// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
)

// Relay configures the first endpoint for selected proxy tiers.
type Relay struct {
	Host        string   // Empty disables the relay.
	Tags        []string // Only the tiers that use the relay.
	StealthPort uint16   // TCP port for Stealth.
	FastPort    uint16   // UDP port or the first port of the hop range.
	FastPorts   string   // Relay hop range in sing-box server_ports form. Empty disables hopping.
}

const (
	// RelayFallbackDelay is the head start given to a relayed dial.
	RelayFallbackDelay = time.Second
	relayCooldown      = time.Minute
)

type relayState struct {
	host          M.Socksaddr
	fast          bool
	stealth       bool
	stealthPort   uint16
	fastPort      uint16
	fastPorts     string
	stealthDetour string
	bootstrap     *option.DomainResolveOptions
	stopMonitor   func()
	noCooldown    bool

	mu          sync.Mutex
	generation  uint64
	retryAt     time.Time
	lastDial    map[string]string
	fastStalled bool
}

func newRelayState(config Relay) *relayState {
	fast := slices.Contains(config.Tags, "fast")
	stealth := slices.Contains(config.Tags, "stealth")
	if config.Host == "" || (!fast && !stealth) {
		return nil
	}
	return &relayState{
		host:        M.ParseSocksaddrHostPort(config.Host, 0).Unwrap(),
		fast:        fast,
		stealth:     stealth,
		stealthPort: config.StealthPort,
		fastPort:    config.FastPort,
		fastPorts:   config.FastPorts,
		lastDial:    make(map[string]string, 2),
	}
}

// RelayState reports the last successful path since the relay state was reset.
func (i *Instance) RelayState(tag string) string {
	r := i.relay
	if r == nil || !(tag == "fast" && r.fast || tag == "stealth" && r.stealth) {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if path := r.lastDial[tag]; path != "" {
		return path
	}
	return "pending"
}

func (r *relayState) endpoint(port uint16) M.Socksaddr {
	endpoint := r.host
	endpoint.Port = port
	return endpoint
}

func (r *relayState) watchNetwork(monitor tun.DefaultInterfaceMonitor) {
	if monitor == nil {
		return
	}
	callback := monitor.RegisterCallback(func(_ *control.Interface, _ int) { r.reset() })
	r.stopMonitor = func() { monitor.UnregisterCallback(callback) }
}

func (r *relayState) interfaceUpdated(tag string) {
	// The monitor resets monitored engines before their subscribers run.
	// Without it, Stealth owns the reset when both tiers receive the update.
	if r.stopMonitor == nil && (tag == "stealth" || !r.stealth) {
		r.reset()
	}
}

func (r *relayState) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.generation++
	r.retryAt = time.Time{}
	clear(r.lastDial)
	r.fastStalled = false
}

func (r *relayState) failed(generation uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation == r.generation {
		r.startCooldownLocked()
	}
}

func (r *relayState) setFastStalled(generation uint64, stalled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation == r.generation {
		r.fastStalled = stalled
	}
}

func (r *relayState) fastWaitTimedOut() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fastStalled {
		r.startCooldownLocked()
	}
}

func (r *relayState) startCooldownLocked() {
	if !r.noCooldown {
		r.retryAt = time.Now().Add(relayCooldown)
	}
}

func dialRelay[T any](ctx context.Context, state *relayState, tag string, dial func(context.Context, bool) (T, error), closeDial func(T)) (T, error) {
	state.mu.Lock()
	generation := state.generation
	tryRelay := !time.Now().Before(state.retryAt)
	state.mu.Unlock()

	var conn T
	var err error
	viaRelay := false
	if tryRelay {
		var winner int
		var relayStalled bool
		var onStall func()
		if tag == "fast" {
			onStall = func() { state.setFastStalled(generation, true) }
		}
		conn, winner, relayStalled, err = staggerDial(ctx, RelayFallbackDelay, func(ctx context.Context, index int) (T, error) {
			viaRelay := index == 0
			candidate, err := dial(ctx, viaRelay)
			if viaRelay && err != nil && ctx.Err() == nil {
				state.failed(generation)
			}
			return candidate, err
		}, closeDial, onStall)
		viaRelay = winner == 0
		if relayStalled {
			if ctx.Err() == context.DeadlineExceeded {
				state.failed(generation)
			}
			if onStall != nil {
				state.setFastStalled(generation, false)
			}
		}
	} else {
		conn, err = dial(ctx, false)
	}
	if err == nil && ctx.Err() == nil {
		state.mu.Lock()
		if generation == state.generation {
			if viaRelay {
				state.lastDial[tag] = "via"
				state.retryAt = time.Time{}
			} else {
				state.lastDial[tag] = "direct"
				if tryRelay {
					state.startCooldownLocked()
				}
			}
		}
		state.mu.Unlock()
	}
	return conn, err
}

// staggerDial races two attempts with a head start for the first.
// The boolean reports whether the delay fired before fallback started.
func staggerDial[T any](ctx context.Context, delay time.Duration, dial func(context.Context, int) (T, error), closeDial func(T), onStall func()) (T, int, bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn  T
		err   error
		index int
	}
	results := make(chan result)
	start := func(index int) {
		go func() {
			conn, err := dial(ctx, index)
			select {
			case results <- result{conn, err, index}:
			case <-ctx.Done():
				if err == nil {
					closeDial(conn)
				}
			}
		}()
	}
	start(0)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	var empty T
	var firstErr error
	var staggered bool
	for remaining := 2; remaining > 0; {
		select {
		case <-ctx.Done():
			if firstErr != nil && ctx.Err() == context.DeadlineExceeded {
				return empty, 0, staggered, firstErr
			}
			return empty, 0, staggered, context.Cause(ctx)
		case <-timer.C:
			staggered = true
			if onStall != nil {
				onStall()
			}
			start(1)
		case result := <-results:
			if result.err == nil {
				return result.conn, result.index, staggered, nil
			}
			if result.index == 0 {
				firstErr = result.err
				if timer.Stop() {
					start(1)
				}
			}
			remaining--
		}
	}
	return empty, 0, staggered, firstErr
}
