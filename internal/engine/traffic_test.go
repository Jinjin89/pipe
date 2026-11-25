// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"io"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"pipe/internal/failover"

	"github.com/sagernet/sing-box/adapter"
)

func TestFastDownloadStallDemotesWithinEightSeconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var checked []failover.Tier
		var selected failover.Tier
		controller, err := failover.New(failover.Options{
			Tiers: failover.Available(false),
			Probe: func(ctx context.Context, tier failover.Tier, burst bool) (bool, error) {
				checked = append(checked, tier)
				if deadline, ok := ctx.Deadline(); burst || !ok || time.Until(deadline) > 1800*time.Millisecond {
					t.Errorf("demotion check for %s used a burst or exceeded its short timeout", tier)
				}
				if tier == failover.Fast {
					conn, peer := net.Pipe()
					defer peer.Close()
					go io.Copy(io.Discard, peer)
					return probeHTTP(ctx, conn, burst) // Silent loss leaves the request unanswered.
				}
				select {
				case <-time.After(100 * time.Millisecond):
					return false, nil
				case <-ctx.Done():
					return false, ctx.Err()
				}
			},
			Select: func(tier failover.Tier) error {
				selected = tier
				cancel()
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		local, peer := net.Pipe()
		defer peer.Close()
		go io.Copy(io.Discard, peer)
		tracker := trafficTracker{observe: controller.ObserveTraffic, suspectStall: controller.SuspectFastStall}
		download := tracker.RoutedConnection(ctx, local, adapter.InboundContext{
			OutboundChain: []adapter.Outbound{testFastOutbound{}},
		}, nil, nil)
		defer download.Close()
		chunk := make([]byte, 32*1024)
		for range minDownloadToWatch / len(chunk) {
			if _, err := download.Write(chunk); err != nil {
				t.Fatal(err)
			}
			time.Sleep(50 * time.Millisecond)
		}
		outage := time.Now()
		// The server-side INPUT drop allows some downstream data already in flight.
		time.Sleep(700 * time.Millisecond)
		if _, err := download.Write(chunk); err != nil {
			t.Fatal(err)
		}
		run, stop := context.WithDeadline(ctx, outage.Add(15*time.Second))
		defer stop()
		if err := controller.Run(run); err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(outage)
		if selected != failover.Stealth || elapsed >= 8*time.Second || !slices.Equal(checked, []failover.Tier{failover.Fast, failover.Stealth}) {
			t.Fatalf("selected %q after %v with probes %v, want one Fast check then Stealth within 8s", selected, elapsed, checked)
		}
	})
}

func TestFastKeepAliveSocketDoesNotReportStalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, peer := net.Pipe()
		defer peer.Close()
		go io.Copy(io.Discard, peer)
		var probes atomic.Int32
		tracker := trafficTracker{
			observe:      func() {},
			suspectStall: func() { probes.Add(1) },
		}
		conn := tracker.RoutedConnection(t.Context(), local, adapter.InboundContext{
			OutboundChain: []adapter.Outbound{testFastOutbound{}},
		}, nil, nil)
		defer conn.Close()
		// These responses exceed 256 KiB in total while staying below the
		// threshold in every ten-second window.
		response := make([]byte, 64*1024)
		for range 6 {
			if _, err := conn.Write(response); err != nil {
				t.Fatal(err)
			}
			time.Sleep(6 * time.Second)
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if count := probes.Load(); count != 0 {
			t.Fatalf("idle keep-alive requested %d stall probes", count)
		}
	})
}

type testFastOutbound struct{ adapter.Outbound }

func (testFastOutbound) Tag() string { return "fast" }

func TestTrafficWatchSignalsOnlyOnceAfterFiveSecondsWithoutProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var probes atomic.Int32
		watch := downloadWatch{report: func() { probes.Add(1) }}
		defer watch.stop()
		watch.progress(minDownloadToWatch)
		time.Sleep(4 * time.Second)
		watch.progress(1)
		time.Sleep(stallAfter - time.Nanosecond)
		synctest.Wait()
		if probes.Load() != 0 {
			t.Fatal("download reported a stall before five seconds of inactivity")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if count := probes.Load(); count != 1 {
			t.Fatalf("stalled download requested %d probes, want one", count)
		}
		watch.progress(minDownloadToWatch)
		time.Sleep(stallAfter)
		synctest.Wait()
		if probes.Load() != 1 {
			t.Fatal("download requested a second stall probe")
		}
	})
}

func TestTrafficWatchUsesFullTenSecondWindow(t *testing.T) {
	for _, test := range []struct {
		name       string
		span       time.Duration
		wantProbes int32
	}{
		{"ten seconds", 10 * time.Second, 1},
		{"older than ten seconds", 10*time.Second + time.Nanosecond, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var probes atomic.Int32
				watch := downloadWatch{report: func() { probes.Add(1) }}
				defer watch.stop()
				watch.progress(minDownloadToWatch - 1)
				time.Sleep(test.span)
				watch.progress(1)
				time.Sleep(stallAfter)
				synctest.Wait()
				if count := probes.Load(); count != test.wantProbes {
					t.Fatalf("download spanning %v requested %d stall probes, want %d", test.span, count, test.wantProbes)
				}
			})
		})
	}
}

func TestTrafficWatchStopsOnClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var probes atomic.Int32
		watch := downloadWatch{report: func() { probes.Add(1) }}
		watch.progress(minDownloadToWatch)
		watch.stop()
		time.Sleep(stallAfter)
		synctest.Wait()
		if probes.Load() != 0 {
			t.Fatal("closed download reported a stall")
		}
	})
}
