// SPDX-License-Identifier: GPL-3.0-or-later

// Package failover selects a healthy proxy tier in priority order.
package failover

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync/atomic"
	"time"
)

type Tier string

const (
	Auto    Tier = "auto"
	Fast    Tier = "fast"
	Stealth Tier = "stealth"
	Rescue  Tier = "rescue"

	failureLimit        = 3
	probePeriod         = 2 * time.Second
	probeTimeout        = 1800 * time.Millisecond
	burstTimeout        = 5 * time.Second
	recentTrafficWindow = 10 * time.Minute
	backoffReset        = 30 * time.Minute
	idleInterval        = 75 * time.Second // With 20% jitter, the minimum is 60 seconds.
	idleJitter          = idleInterval / 5
	stallProbeCooldown  = time.Minute
)

var cooldowns = [...]time.Duration{5 * time.Minute, 15 * time.Minute, 60 * time.Minute}

func Available(cdn bool) []Tier {
	if cdn {
		return []Tier{Fast, Stealth, Rescue}
	}
	return []Tier{Fast, Stealth}
}

type Options struct {
	Tiers          []Tier
	Manual         Tier
	Now            func() time.Time
	Probe          func(ctx context.Context, tier Tier, burst bool) (stalled bool, err error)
	Select         func(Tier) error
	ExtraProbeTime time.Duration // time added to regular and burst probes
}

type Controller struct {
	options         Options
	active          int
	failedProbes    int
	tiers           []tierHealth
	stallProbeAfter time.Time
	// verified is false until the active tier was checked for this session
	// or since the last idle network change.
	verified     bool
	lastTraffic  atomic.Pointer[time.Time]
	dialFailures atomic.Int32
	dialWake     chan struct{}
	trafficWake  chan struct{}
	stallWake    chan struct{}
	resetWake    chan struct{}
}

type tierHealth struct {
	backoff      int
	retryAfter   time.Time
	healthySince time.Time
	clean        int
}

func New(options Options) (*Controller, error) {
	if !slices.Equal(options.Tiers, Available(len(options.Tiers) == 3)) {
		return nil, fmt.Errorf("failover requires fast and stealth, with optional rescue")
	}
	if options.Manual == "" {
		options.Manual = Auto
	}
	active := 0
	if options.Manual != Auto {
		active = slices.Index(options.Tiers, options.Manual)
		if active < 0 {
			return nil, fmt.Errorf("tier %q is unavailable", options.Manual)
		}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Probe == nil || options.Select == nil {
		return nil, fmt.Errorf("failover requires a probe and selector")
	}
	options.Tiers = slices.Clone(options.Tiers)
	return &Controller{
		options: options, active: active, tiers: make([]tierHealth, len(options.Tiers)),
		dialWake: make(chan struct{}, 1), trafficWake: make(chan struct{}, 1),
		stallWake: make(chan struct{}, 1), resetWake: make(chan struct{}, 1),
	}, nil
}

// ObserveTraffic records proxied application activity. A one-second resolution
// is sufficient for the idle gate and avoids waking the scheduler for each packet.
func (c *Controller) ObserveTraffic() {
	now := c.options.Now()
	previous := c.lastTraffic.Load()
	if previous != nil && now.Sub(*previous) < time.Second {
		return
	}
	if c.lastTraffic.CompareAndSwap(previous, &now) && (previous == nil || now.Sub(*previous) >= recentTrafficWindow) {
		wake(c.trafficWake)
	}
}

func (c *Controller) recentTraffic(now time.Time) bool {
	last := c.lastTraffic.Load()
	return last != nil && now.Sub(*last) < recentTrafficWindow
}

// ObserveFastDial takes results from actual new application connections, not
// the controller's probes. A successful dial clears this failure streak.
func (c *Controller) ObserveFastDial(err error) {
	if err == nil {
		c.dialFailures.Store(0)
		return
	}
	if failures := c.dialFailures.Add(1); failures == 1 || failures >= failureLimit {
		wake(c.dialWake)
	}
}

// SuspectFastStall requests a health check after a download stops progressing.
// The download and its transport are left open while the check runs.
func (c *Controller) SuspectFastStall() { wake(c.stallWake) }

// Reset requests fresh tier checks after a change of default network.
func (c *Controller) Reset() { wake(c.resetWake) }

func wake(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (c *Controller) Run(ctx context.Context) error {
	if c.options.Manual != Auto {
		<-ctx.Done()
		return nil
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	var nextProbe time.Time
	for {
		var tick <-chan time.Time
		now := c.options.Now()
		if c.recentTraffic(now) {
			if nextProbe.IsZero() {
				nextProbe = c.schedule(now)
			}
			timer.Reset(nextProbe.Sub(now))
			tick = timer.C
		} else {
			timer.Stop()
			nextProbe = time.Time{}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-c.trafficWake:
			c.tiers[c.active].healthySince = time.Time{}
			if !c.verified {
				// The first traffic checks the active tier at once instead of
				// after the idle schedule. Fast hasn't proven itself yet, so
				// one failure demotes it like a confirmed stall: a network
				// that blocks UDP costs seconds, not repeated failures. Idle
				// sessions still send no probes.
				c.verified = true
				if err := c.check(ctx, true); err != nil {
					return err
				}
				nextProbe = time.Time{}
			}
		case <-tick:
			nextProbe = time.Time{}
			if c.recentTraffic(c.options.Now()) {
				if err := c.check(ctx, false); err != nil {
					return err
				}
			}
		case <-c.dialWake:
			if c.active == 0 && c.recentTraffic(c.options.Now()) {
				c.tiers[0].healthySince = time.Time{}
				if c.dialFailures.Load() >= failureLimit {
					if err := c.demote(ctx); err != nil {
						return err
					}
					nextProbe = time.Time{}
					if c.active == 0 {
						nextProbe = c.options.Now().Add(probePeriod)
					}
				} else if c.dialFailures.Load() > 0 {
					due := c.options.Now().Add(probePeriod)
					if nextProbe.IsZero() || due.Before(nextProbe) {
						nextProbe = due
					}
				}
			}
		case <-c.stallWake:
			now := c.options.Now()
			if c.active == 0 && c.recentTraffic(now) && !now.Before(c.stallProbeAfter) {
				c.stallProbeAfter = now.Add(stallProbeCooldown)
				if err := c.check(ctx, true); err != nil {
					return err
				}
				nextProbe = time.Time{}
			}
		case <-c.resetWake:
			if c.recentTraffic(c.options.Now()) {
				if err := c.networkChanged(ctx); err != nil {
					return err
				}
			} else {
				c.resetHealth()
				c.verified = false
			}
			nextProbe = time.Time{}
		}
	}
}

func (c *Controller) schedule(now time.Time) time.Time {
	if c.failedProbes > 0 {
		return now.Add(probePeriod)
	}
	due := now.Add(idleInterval - idleJitter + rand.N(2*idleJitter))
	for _, health := range c.tiers[:c.active] {
		if !now.Before(health.retryAfter) {
			return now.Add(probePeriod)
		}
		if health.retryAfter.Before(due) {
			due = health.retryAfter
		}
	}
	return due
}

func (c *Controller) probe(ctx context.Context, index int, burst bool) (bool, error) {
	timeout := probeTimeout
	if burst {
		timeout = burstTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout+c.options.ExtraProbeTime)
	defer cancel()
	return c.options.Probe(probeCtx, c.options.Tiers[index], burst)
}

func (c *Controller) check(ctx context.Context, confirmedStall bool) error {
	stalled, err := c.probe(ctx, c.active, false)
	if ctx.Err() != nil {
		return nil
	}
	failed := stalled || err != nil
	active := &c.tiers[c.active]
	if failed {
		c.failedProbes++
		active.healthySince = time.Time{}
	} else {
		c.failedProbes = 0
		now := c.options.Now()
		if active.healthySince.IsZero() {
			active.healthySince = now
		} else if now.Sub(active.healthySince) >= backoffReset {
			active.backoff = 0
			active.retryAfter = time.Time{}
		}
	}
	demote := c.failedProbes >= failureLimit
	if c.active == 0 {
		demote = demote || stalled || (confirmedStall && failed) || c.dialFailures.Load() >= failureLimit
	}
	if demote {
		before := c.active
		if err := c.demote(ctx); err != nil || c.active != before {
			return err
		}
	}
	return c.promote(ctx)
}

func (c *Controller) demote(ctx context.Context) error {
	for next := c.active + 1; next < len(c.tiers); next++ {
		stalled, err := c.probe(ctx, next, false)
		if ctx.Err() != nil {
			return nil
		}
		if !stalled && err == nil {
			c.coolDown(c.active)
			return c.switchTo(next)
		}
		if !c.options.Now().Before(c.tiers[next].retryAfter) {
			c.coolDown(next)
		}
	}
	return nil
}

func (c *Controller) promote(ctx context.Context) error {
	for next := 0; next < c.active; next++ {
		health := &c.tiers[next]
		if c.options.Now().Before(health.retryAfter) {
			continue
		}
		stalled, err := c.probe(ctx, next, health.clean == failureLimit-1)
		if ctx.Err() != nil {
			return nil
		}
		if stalled || err != nil {
			c.coolDown(next)
			continue
		}
		health.clean++
		if health.clean == failureLimit {
			return c.switchTo(next)
		}
		return nil
	}
	return nil
}

func (c *Controller) coolDown(index int) {
	health := &c.tiers[index]
	health.retryAfter = c.options.Now().Add(cooldowns[health.backoff])
	health.backoff = min(health.backoff+1, len(cooldowns)-1)
	health.healthySince = time.Time{}
	health.clean = 0
}

func (c *Controller) switchTo(index int) error {
	if index == c.active {
		return nil
	}
	if err := c.options.Select(c.options.Tiers[index]); err != nil {
		return err
	}
	// Callers switch only to a tier that just passed a probe.
	c.active, c.failedProbes, c.verified = index, 0, true
	for i := range c.tiers {
		c.tiers[i].clean = 0
		c.tiers[i].healthySince = time.Time{}
	}
	c.tiers[index].healthySince = c.options.Now()
	c.dialFailures.Store(0)
	return nil
}

func (c *Controller) resetHealth() {
	clear(c.tiers)
	c.failedProbes = 0
	c.dialFailures.Store(0)
}

func (c *Controller) networkChanged(ctx context.Context) error {
	c.resetHealth()
	c.verified = true
	type result struct {
		tier    int
		healthy bool
	}
	results := make(chan result, len(c.tiers))
	for index := range c.tiers {
		go func() {
			stalled, err := c.probe(ctx, index, false)
			results <- result{index, !stalled && err == nil}
		}()
	}
	best := len(c.tiers)
	for range c.tiers {
		checked := <-results
		if checked.healthy {
			best = min(best, checked.tier)
		}
	}
	if ctx.Err() == nil && best < len(c.tiers) {
		for index := range best {
			c.coolDown(index)
		}
		return c.switchTo(best)
	}
	return nil
}
