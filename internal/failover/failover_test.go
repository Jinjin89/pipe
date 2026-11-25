// SPDX-License-Identifier: GPL-3.0-or-later

package failover

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestProbeExtraTime(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra time.Duration
	}{
		{"default", 0},
		{"with extra time", time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var budgets []time.Duration
				c, err := New(Options{
					Tiers:          Available(false),
					ExtraProbeTime: tc.extra,
					Select:         func(Tier) error { return nil },
					Probe: func(ctx context.Context, _ Tier, _ bool) (bool, error) {
						deadline, ok := ctx.Deadline()
						if !ok {
							t.Error("probe has no deadline")
						}
						budgets = append(budgets, time.Until(deadline))
						return false, nil
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				for _, burst := range []bool{false, true} {
					if _, err := c.probe(t.Context(), 0, burst); err != nil {
						t.Fatal(err)
					}
				}
				if want := []time.Duration{probeTimeout + tc.extra, burstTimeout + tc.extra}; !slices.Equal(budgets, want) {
					t.Fatalf("probe budgets %v, want %v", budgets, want)
				}
			})
		})
	}
}

func TestTierPriorityAndCooldown(t *testing.T) {
	now := time.Unix(0, 0)
	unhealthy := map[Tier]bool{Fast: true}
	var selected []Tier
	var bursts []Tier
	c, err := New(Options{
		Tiers: Available(true), Now: func() time.Time { return now },
		Select: func(tier Tier) error { selected = append(selected, tier); return nil },
		Probe: func(_ context.Context, tier Tier, burst bool) (bool, error) {
			if burst {
				bursts = append(bursts, tier)
			}
			if unhealthy[tier] {
				return false, errors.New("unhealthy")
			}
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	check := func(times int) {
		t.Helper()
		for range times {
			if err := c.check(t.Context(), false); err != nil {
				t.Fatal(err)
			}
		}
	}
	check(2)
	if len(selected) != 0 {
		t.Fatal("demoted before three failures")
	}
	check(1)
	if !slices.Equal(selected, []Tier{Stealth}) {
		t.Fatalf("expected stealth, got %v", selected)
	}
	unhealthy[Fast] = false
	now = now.Add(5*time.Minute - time.Second)
	check(4)
	if len(selected) != 1 {
		t.Fatal("promoted within cooldown")
	}
	now = now.Add(time.Second)
	check(2)
	if len(selected) != 1 {
		t.Fatal("promoted before three clean probes")
	}
	check(1)
	if !slices.Equal(selected, []Tier{Stealth, Fast}) || !slices.Equal(bursts, []Tier{Fast}) {
		t.Fatalf("expected fast after a burst, got %v and bursts %v", selected, bursts)
	}
	check(30)
	if !slices.Equal(bursts, []Tier{Fast}) {
		t.Fatalf("active health checks sent extra bursts: %v", bursts)
	}
	unhealthy[Fast], unhealthy[Stealth] = true, true
	check(3)
	if !slices.Equal(selected, []Tier{Stealth, Fast, Rescue}) {
		t.Fatalf("expected rescue after both failures, got %v", selected)
	}
	if retry := c.tiers[0].retryAfter.Sub(now); retry != 15*time.Minute {
		t.Fatalf("second fast cooldown = %v", retry)
	}
}

func TestNetworkChangeAndStall(t *testing.T) {
	var selected Tier
	stall := true
	c, err := New(Options{
		Tiers:  Available(true),
		Select: func(tier Tier) error { selected = tier; return nil },
		Probe: func(_ context.Context, tier Tier, _ bool) (bool, error) {
			if tier == Fast && stall {
				return true, errors.New("stalled download")
			}
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.check(t.Context(), false); err != nil || selected != Stealth {
		t.Fatalf("stall did not immediately demote fast: %v, %v", selected, err)
	}
	stall = false
	c.Reset()
	<-c.resetWake
	if err := c.networkChanged(t.Context()); err != nil || selected != Fast || c.tiers[0].backoff != 0 {
		t.Fatalf("reset did not restore strict tier priorities: %v, %v", selected, err)
	}
}

func TestDialFailureStreak(t *testing.T) {
	var selected Tier
	c, err := New(Options{
		Tiers: Available(false), Select: func(tier Tier) error { selected = tier; return nil },
		Probe: func(context.Context, Tier, bool) (bool, error) { return false, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		c.ObserveFastDial(errors.New("dial"))
	}
	c.ObserveFastDial(nil)
	for range 2 {
		c.ObserveFastDial(errors.New("dial"))
	}
	if err := c.check(t.Context(), false); err != nil || selected != "" {
		t.Fatalf("demoted on non-consecutive dial failures: %v, %v", selected, err)
	}
	c.ObserveFastDial(errors.New("dial"))
	if err := c.check(t.Context(), false); err != nil || selected != Stealth {
		t.Fatalf("did not demote after three dial failures: %v, %v", selected, err)
	}
}

func TestIdleProbeScheduleAndTrafficExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	c, err := New(Options{
		Tiers: Available(false), Now: func() time.Time { return now }, Select: func(Tier) error { return nil },
		Probe: func(context.Context, Tier, bool) (bool, error) {
			t.Error("idle controller probed without application traffic")
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	c.Reset()
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	c.ObserveTraffic()
	if !c.recentTraffic(now) || c.recentTraffic(now.Add(10*time.Minute)) {
		t.Fatal("application traffic should be recent for ten minutes")
	}
	var first time.Duration
	var varied bool
	for i := range 32 {
		delay := c.schedule(now).Sub(now)
		if delay < 60*time.Second || delay > 90*time.Second {
			t.Fatalf("idle probe delay %v outside the jitter window", delay)
		}
		if i == 0 {
			first = delay
		}
		varied = varied || delay != first
	}
	if !varied {
		t.Fatal("idle interval did not vary")
	}
	c.failedProbes = 1
	if delay := c.schedule(now).Sub(now); delay != 2*time.Second {
		t.Fatalf("degraded probe delay = %v", delay)
	}
}

func TestSuspectedDownloadStallWakesHealthySchedule(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var selected Tier
	c, err := New(Options{
		Tiers: Available(false),
		Probe: func(_ context.Context, tier Tier, _ bool) (bool, error) { return tier == Fast, nil },
		Select: func(tier Tier) error {
			selected = tier
			cancel()
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.ObserveTraffic()
	c.SuspectFastStall()
	if err := c.Run(ctx); err != nil || selected != Stealth {
		t.Fatalf("active stall did not wake the controller and demote: tier %s, %v", selected, err)
	}
}

func TestStallProbeCooldownIsSharedAcrossConnections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		var offset atomic.Int64
		now := func() time.Time { return start.Add(time.Duration(offset.Load())) }
		checks := make(chan time.Time, 8)
		c, err := New(Options{
			Tiers: Available(false), Now: now, Select: func(Tier) error { return nil },
			Probe: func(context.Context, Tier, bool) (bool, error) {
				checks <- now()
				return false, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		c.verified = true // This test counts stall probes only.
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		defer func() {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}()
		c.ObserveTraffic()
		for _, elapsed := range []time.Duration{0, time.Second, 59 * time.Second, 60 * time.Second} {
			offset.Store(int64(elapsed))
			c.SuspectFastStall()
			synctest.Wait()
		}
		var probes []time.Time
		for len(checks) > 0 {
			probes = append(probes, <-checks)
		}
		if !slices.Equal(probes, []time.Time{start, start.Add(time.Minute)}) {
			t.Fatalf("stall probes at %v, want times one minute apart", probes)
		}
	})
}

func TestSilentLossDemotesWithinFifteenSeconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		var selected Tier
		c, err := New(Options{
			Tiers: Available(false),
			Probe: func(ctx context.Context, tier Tier, _ bool) (bool, error) {
				if tier == Fast {
					<-ctx.Done()
					return false, ctx.Err()
				}
				return false, nil
			},
			Select: func(tier Tier) error {
				selected = tier
				cancel()
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		c.verified = true // Fast worked before it went silent.
		c.ObserveTraffic()
		go func() {
			time.Sleep(5 * time.Second)
			c.SuspectFastStall()
		}()
		if err := c.Run(ctx); err != nil || selected != Stealth {
			t.Fatalf("silent loss did not demote in time: selected %s, error %v", selected, err)
		}
	})
}

func TestSustainedHealthResetsBackoffAndBurstDeadline(t *testing.T) {
	now := time.Unix(100, 0)
	c, err := New(Options{
		Tiers: Available(false), Now: func() time.Time { return now }, Select: func(Tier) error { return nil },
		Probe: func(ctx context.Context, _ Tier, burst bool) (bool, error) {
			deadline, _ := ctx.Deadline()
			if burst && (time.Until(deadline) < 4*time.Second || time.Until(deadline) > 5*time.Second) {
				t.Error("burst did not receive a five-second deadline")
			}
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.tiers[0].backoff = 2
	if err := c.check(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	now = now.Add(29 * time.Minute)
	if err := c.check(t.Context(), false); err != nil || c.tiers[0].backoff != 2 {
		t.Fatalf("backoff reset too early: %v", err)
	}
	now = now.Add(time.Minute)
	if err := c.check(t.Context(), false); err != nil || c.tiers[0].backoff != 0 {
		t.Fatalf("backoff did not reset after 30 healthy minutes: %v", err)
	}
	if _, err := c.probe(t.Context(), 0, true); err != nil {
		t.Fatal(err)
	}
}

func TestStallWithoutErrorIsUnhealthyAtEachTier(t *testing.T) {
	now := time.Unix(100, 0)
	stalled := map[Tier]bool{Fast: true, Stealth: true}
	c, err := New(Options{
		Tiers: Available(true), Now: func() time.Time { return now }, Select: func(Tier) error { return nil },
		Probe: func(_ context.Context, tier Tier, _ bool) (bool, error) { return stalled[tier], nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.check(t.Context(), false); err != nil || c.active != 2 {
		t.Fatalf("expected demotion past both stalled tiers, active = %d: %v", c.active, err)
	}
	now = now.Add(5 * time.Minute)
	if err := c.promote(t.Context()); err != nil || c.tiers[0].clean != 0 || c.tiers[1].clean != 0 {
		t.Fatalf("stalled promotion probes were counted as successes: %v", err)
	}
	stalled[Stealth] = false
	if err := c.networkChanged(t.Context()); err != nil || c.active != 1 {
		t.Fatalf("network reset selected a stalled tier, active = %d: %v", c.active, err)
	}
}

func TestFirstTrafficChecksActiveTierAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var probes atomic.Int32
		selected := make(chan Tier, 1)
		c, err := New(Options{
			Tiers: Available(true),
			Probe: func(ctx context.Context, tier Tier, _ bool) (bool, error) {
				probes.Add(1)
				if tier == Fast { // UDP blocked: the probe never answers.
					<-ctx.Done()
					return false, ctx.Err()
				}
				return false, nil
			},
			Select: func(tier Tier) error { selected <- tier; return nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		time.Sleep(time.Hour)
		synctest.Wait()
		if n := probes.Load(); n != 0 {
			t.Fatalf("idle session sent %d probes", n)
		}
		start := time.Now()
		c.ObserveTraffic()
		if tier := <-selected; tier != Stealth || time.Since(start) > 2*time.Second || probes.Load() != 2 {
			t.Fatalf("first traffic selected %s after %v with %d probes", tier, time.Since(start), probes.Load())
		}
		// Healthy Stealth is kept; more traffic doesn't check again.
		synctest.Wait()
		before := probes.Load()
		c.ObserveTraffic()
		synctest.Wait()
		if probes.Load() != before {
			t.Fatal("more traffic checked again")
		}
		// After an idle network change, the next traffic checks again.
		time.Sleep(11 * time.Minute)
		synctest.Wait()
		c.Reset()
		synctest.Wait()
		before = probes.Load()
		c.ObserveTraffic()
		synctest.Wait()
		if probes.Load() == before {
			t.Fatal("traffic after an idle network change was not checked")
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}
