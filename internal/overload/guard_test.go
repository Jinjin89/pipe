// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux

package overload

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

var (
	spare = Snapshot{MaxFDs: 1024, OpenFDs: 20, GoMemoryBytes: 40, GoMemoryLimit: 100}
	low   = Snapshot{GoMemoryBytes: 80, GoMemoryLimit: 100}
	hard  = Snapshot{GoMemoryBytes: 90, GoMemoryLimit: 100}
)

type acquisition struct {
	lease *Lease
	err   error
}

func attempt(g *Guard, ctx context.Context) <-chan acquisition {
	result := make(chan acquisition, 1)
	go func() {
		lease, err := g.Acquire(ctx, ClassFlow)
		result <- acquisition{lease, err}
	}()
	return result
}

func take(t *testing.T, g *Guard, class Class) *Lease {
	t.Helper()
	l, err := g.Acquire(t.Context(), class)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}

func press(g *Guard) {
	g.RecordSample(low)
	g.RecordSample(low)
}

func TestHealthyParallel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := New(Options{Sample: func(context.Context) Snapshot { return spare }})
		g.Start(t.Context())
		defer g.Close()
		var results [50]<-chan acquisition
		for i := range results {
			results[i] = attempt(g, t.Context())
		}
		synctest.Wait()
		if d := g.Diagnostics(); d.ActiveFlows != 50 || d.PendingDials != 50 || d.Waiters != 0 {
			t.Fatalf("healthy admissions = %+v", d)
		}
		for _, result := range results {
			r := <-result
			wantErr(t, r.err, nil)
			r.lease.Release()
		}
	})
}

func TestSampleHysteresis(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sequence := []Snapshot{spare, low, low, spare, spare, spare}
		var count atomic.Int64
		g := New(Options{Sample: func(context.Context) Snapshot {
			index := count.Add(1) - 1
			return sequence[min(index, int64(len(sequence)-1))]
		}})
		var transitions []bool
		unregister := g.OnPressure(func(on bool) {
			if g.Diagnostics().Pressured != on {
				t.Error("callback ran before the transition was visible")
			}
			transitions = append(transitions, on)
		})
		g.Start(t.Context())
		g.Start(t.Context())
		defer g.Close()
		if n := count.Load(); n != 1 {
			t.Fatalf("initial samples = %d", n)
		}
		for i, s := range sequence[1:] {
			time.Sleep(time.Second)
			synctest.Wait()
			s.OpenFDs, s.MaxFDs = spare.OpenFDs, spare.MaxFDs
			if d := g.Diagnostics(); d.Pressured != (i >= 1 && i <= 3) || d.Emergency || !reflect.DeepEqual(d.LastSample, s) {
				t.Fatalf("sample %d = %+v", i, d)
			}
		}
		unregister()
		unregister()
		press(g)
		g.Close()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if n := count.Load(); !slices.Equal(transitions, []bool{true, false}) || n != 6 {
			t.Fatalf("transitions = %v, samples = %d", transitions, n)
		}
	})
}

func TestEmergencySignals(t *testing.T) {
	for _, s := range []Snapshot{
		hard, {MaxFDs: 100, OpenFDs: 84}, {CgroupLimitBytes: 100, CgroupCurrentBytes: 90},
		{HostMemTotalBytes: 512 << 20, HostMemAvailableBytes: 0},
	} {
		g := New(Options{})
		g.RecordSample(s)
		if d := g.Diagnostics(); !d.Pressured || !d.Emergency {
			t.Fatalf("hard floor missed: %+v", d)
		}
	}
	for _, fault := range []error{syscall.EMFILE, syscall.ENFILE} {
		g := New(Options{})
		g.RecordSample(Snapshot{})
		if d := g.Diagnostics(); d.Pressured || d.Emergency {
			t.Fatalf("missing metrics created pressure: %+v", d)
		}
		g.ObserveError(&os.PathError{Op: "dial", Err: fault})
		if d := g.Diagnostics(); !d.Pressured || !d.Emergency {
			t.Fatalf("FD fault did not trigger immediate Emergency: %+v", d)
		}
		g.RecordSample(Snapshot{})
		if d := g.Diagnostics(); !d.Pressured || !d.Emergency {
			t.Fatalf("FD fault lost without a healthy FD sample: %+v", d)
		}
		for i := range 3 {
			g.RecordSample(spare)
			if d := g.Diagnostics(); d.Emergency || d.Pressured != (i < 2) {
				t.Fatalf("FD fault recovery sample %d = %+v", i, d)
			}
		}
	}
}

func TestAncestorCgroupPressure(t *testing.T) {
	s := Snapshot{
		CgroupCurrentBytes: 64 << 20, CgroupLimitBytes: 256 << 20,
		Cgroups: []CgroupMemory{
			{Path: "/tenant/worker", CurrentBytes: 64 << 20, LimitBytes: 256 << 20, ReclaimEvents: 100},
			{Path: "/tenant", CurrentBytes: 505 << 20, LimitBytes: 512 << 20},
		},
	}
	g := New(Options{})
	g.RecordSample(s)
	if d := g.Diagnostics(); !d.Pressured || !d.Emergency {
		t.Fatalf("full ancestor did not trigger Emergency: %+v", d)
	}

	g = New(Options{})
	s.Cgroups[1].CurrentBytes = 384 << 20
	s.CgroupLimitBytes = 0
	s.HostMemTotalBytes = 512 << 20
	g.RecordSample(s)
	for i := range 2 {
		s.Cgroups[0].ReclaimEvents -= 10
		s.Cgroups[1].ReclaimEvents++
		g.RecordSample(s)
		if d := g.Diagnostics(); d.Emergency || d.Pressured != (i == 1) {
			t.Fatalf("ancestor reclaim sample %d = %+v", i, d)
		}
	}
	for range 3 {
		g.RecordSample(s)
	}
	if !g.Diagnostics().Pressured {
		t.Fatal("guard recovered while the ancestor was above its recovery watermark")
	}
	s.Cgroups = s.Cgroups[:1]
	for range 3 {
		g.RecordSample(s)
	}
	if g.Diagnostics().Pressured || len(g.prevCgroupEvents) != 1 {
		t.Fatal("guard retained pressure or event history from a removed ancestor")
	}
}

func TestUnreadableFDsPreserveLastMeasurement(t *testing.T) {
	setSingleFDCheck(t, func() (bool, bool) {
		t.Fatal("allocation check ran without a complete fallback scan")
		return false, false
	})

	failedSample := func(err error) Snapshot {
		var s Snapshot
		sampleFDs(&s, t.Context(), 100, func(path string) (*os.File, error) {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}, func(uint64) error {
			if isFDExhausted(err) {
				t.Fatal("fallback scanned after procfs reported exhaustion")
			}
			return syscall.EACCES
		})
		return s
	}
	g := New(Options{})
	g.RecordSample(Snapshot{OpenFDs: 97, MaxFDs: 100})
	for _, tc := range []struct {
		err       error
		limit     uint64
		exhausted bool
	}{{syscall.EACCES, 0, false}, {syscall.EMFILE, 100, true}, {syscall.ENFILE, 100, true}} {
		s := failedSample(tc.err)
		if s.FDExhausted != tc.exhausted || s.MaxFDs != tc.limit || s.OpenFDs != 0 {
			t.Fatalf("sampler result for %v = %+v", tc.err, s)
		}
		g.RecordSample(s)
		if d := g.Diagnostics(); !d.Emergency || d.LastSample.OpenFDs != 97 || d.LastSample.MaxFDs != 100 {
			t.Fatalf("failed FD measurement discarded headroom limits: %+v", d)
		}
		_, probeErr := g.Acquire(t.Context(), ClassProbe)
		wantErr(t, probeErr, ErrOverloaded)
	}
	g.RecordSample(Snapshot{})
	if !g.Diagnostics().Emergency {
		t.Fatal("an unverified sample cleared measured FD exhaustion")
	}
	g.RecordSample(spare)
	if g.Diagnostics().Emergency {
		t.Fatal("fresh healthy FD count did not clear Emergency")
	}
	g.RecordSample(failedSample(syscall.EMFILE))
	if d := g.Diagnostics(); !d.Emergency || d.LastSample.OpenFDs != spare.OpenFDs {
		t.Fatalf("sampler exhaustion missed even with spare FD headroom in the last count: %+v", d)
	}
	g.RecordSample(Snapshot{FDProbeOK: true})
	if d := g.Diagnostics(); !d.Emergency || d.LastSample.OpenFDs != spare.OpenFDs || d.LastSample.MaxFDs != spare.MaxFDs {
		t.Fatalf("allocation success erased measured FD state: %+v", d)
	}
	g.RecordSample(Snapshot{ProbeFreeFDs: 32})
	if g.Diagnostics().Emergency {
		t.Fatal("a fresh probe with healthy headroom did not clear the fault")
	}
}

func setSingleFDCheck(t *testing.T, check func() (bool, bool)) {
	t.Helper()
	original := checkSingleFD
	checkSingleFD = check
	t.Cleanup(func() { checkSingleFD = original })
}

func sampleFDTable(t *testing.T, limit, open, wantScanned uint64, allocationErr error) Snapshot {
	t.Helper()
	var procOpens, checks int
	var scanned uint64
	setSingleFDCheck(t, func() (bool, bool) {
		checks++
		if scanned != wantScanned {
			t.Fatalf("allocation check followed %d slot checks, want %d", scanned, wantScanned)
		}
		return allocationErr == nil, isFDExhausted(allocationErr)
	})
	var s Snapshot
	sampleFDs(&s, t.Context(), limit, func(path string) (*os.File, error) {
		procOpens++
		if path != "/proc/self/fd" {
			t.Fatalf("unexpected open of %q", path)
		}
		return nil, syscall.EACCES
	}, func(fd uint64) error {
		if fd != scanned || scanned >= wantScanned {
			t.Fatalf("unexpected slot check for FD %d after %d checks", fd, scanned)
		}
		scanned++
		if fd < open {
			return nil
		}
		return syscall.EBADF
	})
	if procOpens != 1 || checks != 1 {
		t.Fatalf("sampler opened procfs %d times and checked allocation %d times", procOpens, checks)
	}
	return s
}

func TestLinuxFDProbeFallback(t *testing.T) {
	t.Run("exact count and recovery", func(t *testing.T) {
		s := sampleFDTable(t, 100, 68, 100, nil)
		if !reflect.DeepEqual(s, Snapshot{OpenFDs: 68, MaxFDs: 100}) {
			t.Fatalf("fallback count = %+v", s)
		}
		g := New(Options{})
		g.RecordSample(Snapshot{OpenFDs: 95, MaxFDs: 100})
		g.ObserveError(syscall.EMFILE)
		g.RecordSample(s)
		if d := g.Diagnostics(); d.Emergency || !reflect.DeepEqual(d.LastSample, s) {
			t.Fatalf("exact fallback count failed to clear the fault: %+v", d)
		}
		take(t, g, ClassFlow).Release()
	})
	t.Run("system-wide exhaustion", func(t *testing.T) {
		s := sampleFDTable(t, 100, 68, 100, syscall.ENFILE)
		if !reflect.DeepEqual(s, Snapshot{MaxFDs: 100, FDExhausted: true}) {
			t.Fatalf("fallback after ENFILE = %+v", s)
		}
		g := New(Options{})
		g.RecordSample(Snapshot{OpenFDs: 68, MaxFDs: 100})
		g.RecordSample(s)
		if d := g.Diagnostics(); !d.Emergency || d.LastSample.OpenFDs != 68 {
			t.Fatalf("ENFILE failed to trigger Emergency with spare slots: %+v", d)
		}
	})
}

func TestLinuxFDScanBounds(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		limit, open, inspected uint64
		want                   Snapshot
	}{
		{"exact-scan cutoff", 4096, 4, 4096, Snapshot{OpenFDs: 4, MaxFDs: 4096}},
		{"target met at last slot", 4097, 3969, 4097, Snapshot{OpenFDs: 3969, MaxFDs: 4097}},
		{"early stop", 100000, 4, 132, Snapshot{ProbeFreeFDs: 128, ProbeReserve: 64, ProbeLimit: 100000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := sampleFDTable(t, tc.limit, tc.open, tc.inspected, nil)
			if !reflect.DeepEqual(s, tc.want) {
				t.Fatalf("FD scan = %+v, want %+v", s, tc.want)
			}
			if s.ProbeFreeFDs != 0 {
				g := New(Options{})
				g.RecordSample(s)
				assertFDGrants(t, g, 64)
			}
		})
	}
}

func TestIncompleteFDScanDiscardsHeadroom(t *testing.T) {
	for _, reason := range []string{"unexpected error", "cancellation"} {
		t.Run(reason, func(t *testing.T) {
			setSingleFDCheck(t, func() (bool, bool) {
				t.Fatal("allocation check ran after an incomplete scan")
				return false, false
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var scanned int
			var s Snapshot
			sampleFDs(&s, ctx, 100, func(string) (*os.File, error) {
				return nil, syscall.EACCES
			}, func(fd uint64) error {
				scanned++
				if fd == 3 {
					if reason == "unexpected error" {
						return syscall.EACCES
					}
					cancel()
				}
				return syscall.EBADF
			})
			if scanned != 4 || !reflect.DeepEqual(s, Snapshot{}) {
				t.Fatalf("incomplete scan checked %d slots and reported %+v", scanned, s)
			}
		})
	}
}

func TestSmallFDLimitRecovery(t *testing.T) {
	exact := sampleFDTable(t, 16, 4, 16, nil)
	if !reflect.DeepEqual(exact, Snapshot{OpenFDs: 4, MaxFDs: 16}) {
		t.Fatalf("fallback count for small limit = %+v", exact)
	}
	for _, tc := range []struct {
		name   string
		sample Snapshot
	}{
		{"exact count", exact},
		{"surplus", Snapshot{ProbeFreeFDs: 12, ProbeReserve: 8, ProbeLimit: 16}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := New(Options{})
			g.RecordSample(Snapshot{OpenFDs: 12, MaxFDs: 16})
			g.ObserveError(syscall.EMFILE)
			for i := range 3 {
				g.RecordSample(tc.sample)
				if d := g.Diagnostics(); d.Emergency || d.Pressured != (i < 2) {
					t.Fatalf("recovery sample %d = %+v", i, d)
				}
			}
			assertFDGrants(t, g, 4)
		})
	}
}

func assertFDGrants(t *testing.T, g *Guard, count int) {
	t.Helper()
	for range count {
		defer take(t, g, ClassFlow).Release()
	}
	_, err := g.Acquire(t.Context(), ClassFlow)
	wantErr(t, err, ErrOverloaded)
}

func TestProbedFDSurplus(t *testing.T) {
	for _, tc := range []struct {
		name    string
		free    uint64
		grants  int
		recover bool
	}{
		{name: "reserve only", free: 16, grants: 0},
		{name: "one spare", free: 17, grants: 1},
		{name: "recovery", free: 32, grants: 16, recover: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Snapshot{ProbeFreeFDs: tc.free, ProbeReserve: 16}
			g := New(Options{})
			if tc.recover {
				g.RecordSample(Snapshot{OpenFDs: 95, MaxFDs: 100})
				g.ObserveError(syscall.EMFILE)
				g.RecordSample(s)
				g.RecordSample(s)
			}
			g.RecordSample(s)
			if d := g.Diagnostics(); d.Emergency != (tc.grants == 0) || d.Pressured != (tc.grants == 0) || d.LastSample.ProbeFreeFDs != tc.free || d.LastSample.ProbeReserve != 16 {
				t.Fatalf("unexpected probe state: %+v", d)
			}
			leases := make([]*Lease, tc.grants)
			for i := range leases {
				leases[i] = take(t, g, ClassFlow)
			}
			_, err := g.Acquire(t.Context(), ClassFlow)
			wantErr(t, err, ErrOverloaded)
			if len(leases) != 0 {
				leases[0].DialDone(true)
				if d := g.Diagnostics(); d.PendingDials != int64(tc.grants-1) || d.UnmeasuredFDs != 1 {
					t.Fatalf("dial completion did not transfer the FD charge: %+v", d)
				}
				_, err := g.Acquire(t.Context(), ClassFlow)
				wantErr(t, err, ErrOverloaded)
				leases[0].Release()
				take(t, g, ClassFlow).Release()
			}
			for _, lease := range leases {
				lease.Release()
			}
			assertUnused(t, g)
		})
	}
}

func TestUnmeasuredFDProbeRecovery(t *testing.T) {
	g := New(Options{})
	scanSeq := g.beginSample()
	g.ObserveError(syscall.EMFILE)
	g.recordSample(Snapshot{ProbeFreeFDs: 32}, scanSeq)
	if !g.Diagnostics().Emergency {
		t.Fatal("a probe started before the fault cleared Emergency")
	}
	g.RecordSample(Snapshot{})
	if !g.Diagnostics().Emergency {
		t.Fatal("missing probe cleared Emergency")
	}
	g.RecordSample(Snapshot{ProbeFreeFDs: 17})
	if d := g.Diagnostics(); !d.Emergency || d.LastSample.ProbeFreeFDs != 17 {
		t.Fatalf("probe below the recovery watermark: %+v", d)
	}
	g.RecordSample(Snapshot{FDProbeOK: true})
	if d := g.Diagnostics(); !d.Emergency || d.LastSample.ProbeFreeFDs != 17 {
		t.Fatalf("allocation success erased the last surplus measurement: %+v", d)
	}
	for i := range 3 {
		g.RecordSample(Snapshot{ProbeFreeFDs: 32})
		if d := g.Diagnostics(); d.Emergency || d.Pressured != (i < 2) {
			t.Fatalf("probe recovery sample %d = %+v", i, d)
		}
	}
}

func TestSingleFDProbeRecovery(t *testing.T) {
	var allocationErr error = syscall.EMFILE
	var checks int
	setSingleFDCheck(t, func() (bool, bool) {
		checks++
		return allocationErr == nil, isFDExhausted(allocationErr)
	})
	sample := func() Snapshot {
		var s Snapshot
		before := checks
		sampleFDs(&s, t.Context(), 0, func(string) (*os.File, error) {
			t.Fatal("opened procfs with an unknown limit")
			return nil, nil
		}, func(uint64) error {
			t.Fatal("scanned descriptor slots with an unknown limit")
			return nil
		})
		if checks != before+1 {
			t.Fatalf("allocation checks per sample = %d, want 1", checks-before)
		}
		return s
	}
	g := New(Options{})
	lease := take(t, g, ClassFlow)
	defer lease.Release()
	lease.DialDone(true)
	g.RecordSample(sample())
	if d := g.Diagnostics(); !d.Emergency || !reflect.DeepEqual(d.LastSample, Snapshot{FDExhausted: true}) {
		t.Fatalf("single-FD probe failed to report exhaustion: %+v", d)
	}
	scanSeq := g.beginSample()
	g.ObserveError(syscall.EMFILE)
	allocationErr = nil
	g.recordSample(sample(), scanSeq)
	if !g.Diagnostics().Emergency {
		t.Fatal("a successful probe started before the fault cleared Emergency")
	}
	allocationErr = syscall.EACCES
	g.RecordSample(sample())
	if !g.Diagnostics().Emergency {
		t.Fatal("an unsuccessful allocation check cleared Emergency")
	}
	allocationErr = nil
	for i := range 3 {
		g.RecordSample(sample())
		if d := g.Diagnostics(); d.Emergency || d.Pressured != (i < 2) || d.UnmeasuredFDs != 1 || !reflect.DeepEqual(d.LastSample, Snapshot{FDProbeOK: true}) {
			t.Fatalf("single-FD recovery sample %d = %+v", i, d)
		}
	}
}

func TestDelayedFDProbeKeepsNewerCharge(t *testing.T) {
	g := New(Options{})
	lease := take(t, g, ClassFlow)
	scanSeq := g.beginSample()
	lease.DialDone(true)
	s := Snapshot{ProbeFreeFDs: 17, ProbeReserve: 16, ProbeLimit: 100}
	g.recordSample(s, scanSeq)
	if d := g.Diagnostics(); d.UnmeasuredFDs != 1 || d.LastSample.ProbeFreeFDs != 17 {
		t.Fatalf("probe lost a newer FD charge: %+v", d)
	}
	_, err := g.Acquire(t.Context(), ClassFlow)
	wantErr(t, err, ErrOverloaded)
	g.RecordSample(Snapshot{})
	if d := g.Diagnostics(); d.UnmeasuredFDs != 1 || !reflect.DeepEqual(d.LastSample, s) || !d.Emergency {
		t.Fatalf("unverified probe lost the last budget or charge: %+v", d)
	}
	g.RecordSample(s)
	if d := g.Diagnostics(); d.UnmeasuredFDs != 0 || d.Emergency {
		t.Fatalf("fresh probe did not retire the older FD charge: %+v", d)
	}
	lease.Release()
	assertUnused(t, g)
}

func TestDelayedFDSampleKeepsNewerState(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, publish := make(chan struct{}), make(chan struct{})
		var samples int
		g := New(Options{Sample: func(ctx context.Context) Snapshot {
			samples++
			s := Snapshot{OpenFDs: 10, MaxFDs: 100}
			switch samples {
			case 2:
				close(started)
				select {
				case <-publish:
				case <-ctx.Done():
				}
			case 3:
				s.OpenFDs++
			}
			return s
		}})
		g.Start(t.Context())
		defer g.Close()
		lease := take(t, g, ClassFlow)
		defer lease.Release()
		<-started
		lease.DialDone(true)
		g.ObserveError(syscall.EMFILE)
		close(publish)
		synctest.Wait()
		if d := g.Diagnostics(); d.UnmeasuredFDs != 1 || !d.Emergency {
			t.Errorf("delayed sample erased a newer charge or fault: %+v", d)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if d := g.Diagnostics(); d.UnmeasuredFDs != 0 || d.Emergency || !d.Pressured || d.LastSample.OpenFDs != 11 {
			t.Errorf("fresh sample did not retire the charge and clear Emergency: %+v", d)
		}
	})
}

func TestLateFDCountKeepsNewerMeasurement(t *testing.T) {
	g := New(Options{})
	older := g.beginSample()
	olderProbe := g.beginSample()
	lease := take(t, g, ClassFlow)
	lease.DialDone(true)
	g.RecordSample(Snapshot{OpenFDs: 16, MaxFDs: 32})
	g.recordSample(Snapshot{OpenFDs: 14, MaxFDs: 32}, older)
	if d := g.Diagnostics(); d.LastSample.OpenFDs != 16 || !d.Emergency {
		t.Fatalf("late sample replaced newer FD measurement: %+v", d)
	}
	g.recordSample(Snapshot{ProbeFreeFDs: 32}, olderProbe)
	if d := g.Diagnostics(); d.LastSample.OpenFDs != 16 || !d.Emergency {
		t.Fatalf("late probe replaced newer FD measurement: %+v", d)
	}
	older = g.beginSample()
	g.RecordSample(Snapshot{ProbeFreeFDs: 32})
	g.recordSample(Snapshot{OpenFDs: 16, MaxFDs: 32}, older)
	if d := g.Diagnostics(); d.LastSample.MaxFDs != 0 || d.LastSample.ProbeFreeFDs != 32 || d.Emergency {
		t.Fatalf("late count replaced newer FD probe: %+v", d)
	}
	lease.Release()
	assertUnused(t, g)
}

func TestUncontendedPressureAdmission(t *testing.T) {
	g := New(Options{})
	press(g)
	if !g.Diagnostics().Pressured {
		t.Fatal("fixture did not enter Pressure")
	}
	allocs := testing.AllocsPerRun(100, func() {
		take(t, g, ClassFlow).Release()
	})
	if allocs > 1 {
		t.Fatalf("uncontended Pressure admission allocated %g times, want at most the lease", allocs)
	}
	assertUnused(t, g)
}

func TestFIFOPacingAndNoWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := New(Options{MaxWaiters: 2})
		incumbent := take(t, g, ClassFlow)
		press(g)
		first := attempt(g, t.Context())
		synctest.Wait()
		second := attempt(g, t.Context())
		synctest.Wait()
		if n := g.Diagnostics().Waiters; n != 2 {
			t.Fatalf("waiters = %d", n)
		}
		for _, class := range []Class{ClassFlow, ClassFlowNoWait} {
			_, err := g.Acquire(t.Context(), class)
			wantErr(t, err, ErrOverloaded)
		}
		incumbent.Release()
		synctest.Wait()
		if len(first) != 1 || len(second) != 0 {
			t.Fatal("release did not wake exactly the FIFO head")
		}
		a := <-first
		wantErr(t, a.err, nil)
		a.lease.Release()
		b := <-second
		wantErr(t, b.err, nil)
		b.lease.Release()
		take(t, g, ClassFlowNoWait).Release()
		holder := take(t, g, ClassFlow)
		queued := attempt(g, t.Context())
		synctest.Wait()
		for range 3 {
			g.RecordSample(spare)
		}
		recovered := <-queued
		wantErr(t, recovered.err, nil)
		recovered.lease.Release()
		holder.Release()
		g.RecordSample(hard)
		_, err := g.Acquire(t.Context(), ClassFlow)
		wantErr(t, err, ErrOverloaded)
	})
}

func TestWaiterCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := New(Options{MaxWait: 50 * time.Millisecond})
		holder := take(t, g, ClassFlow)
		press(g)
		timed := attempt(g, t.Context())
		time.Sleep(50 * time.Millisecond)
		wantErr(t, (<-timed).err, ErrOverloaded)
		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		defer cancel()
		wantErr(t, (<-attempt(g, ctx)).err, context.DeadlineExceeded)
		if d := g.Diagnostics(); d.Waiters != 0 || d.ActiveFlows != 1 || d.PendingDials != 1 {
			t.Fatalf("timeout leaked a waiter or lease: %+v", d)
		}
		pending := attempt(g, t.Context())
		synctest.Wait()
		g.Close()
		g.Close()
		wantErr(t, (<-pending).err, ErrOverloaded)
		holder.Release()
		assertUnused(t, g)
	})
}

func TestCanceledHandoffPassesPermit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := New(Options{})
		for range 25 {
			holder := take(t, g, ClassFlow)
			press(g)
			ctx, cancel := context.WithCancel(t.Context())
			canceled := attempt(g, ctx)
			synctest.Wait()
			next := attempt(g, t.Context())
			synctest.Wait()
			go holder.Release()
			cancel()
			first := <-canceled
			if first.err != nil {
				wantErr(t, first.err, context.Canceled)
			}
			first.lease.Release()
			second := <-next
			wantErr(t, second.err, nil)
			second.lease.Release()
			assertUnused(t, g)
		}
	})
}

func TestProbeReserveAtEmergency(t *testing.T) {
	g := New(Options{ProbeReserve: 2})
	g.RecordSample(Snapshot{MaxFDs: 100, OpenFDs: 95})
	a, b := take(t, g, ClassProbe), take(t, g, ClassProbe)
	if d := g.Diagnostics(); !d.Emergency || d.PendingDials != 0 || d.ActiveProbes != 2 {
		t.Fatalf("probe accounting = %+v", d)
	}
	_, err := g.Acquire(t.Context(), ClassProbe)
	wantErr(t, err, ErrOverloaded)
	a.Release()
	g.RecordSample(Snapshot{MaxFDs: 100, OpenFDs: 96})
	_, err = g.Acquire(t.Context(), ClassProbe)
	wantErr(t, err, ErrOverloaded)
	b.Release()
	assertUnused(t, g)
}

func TestProbeReserveBetweenSamples(t *testing.T) {
	g := New(Options{})
	g.RecordSample(Snapshot{OpenFDs: 83, MaxFDs: 100})
	held := take(t, g, ClassFlow)
	_, err := g.Acquire(t.Context(), ClassFlow)
	wantErr(t, err, ErrOverloaded)
	var probes [8]*Lease
	for i := range probes {
		probes[i] = take(t, g, ClassProbe)
	}
	_, err = g.Acquire(t.Context(), ClassProbe)
	wantErr(t, err, ErrOverloaded)
	if d := g.Diagnostics(); d.Pressured || d.ActiveProbes != 8 || d.PendingDials != 1 {
		t.Fatalf("reserve accounting before pressure sample = %+v", d)
	}
	for _, l := range probes {
		l.Release()
	}
	held.Release()
	assertUnused(t, g)
}

func TestWaitAccept(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := New(Options{})
		wantErr(t, g.WaitAccept(t.Context()), nil)
		for _, want := range []error{nil, context.Canceled, ErrOverloaded} {
			ctx, cancel := context.WithCancel(t.Context())
			ready := make(chan error, 1)
			g.RecordSample(hard)
			go func() { ready <- g.WaitAccept(ctx) }()
			synctest.Wait()
			if len(ready) != 0 {
				t.Fatal("accept ran during Emergency")
			}
			switch want {
			case nil:
				g.RecordSample(low)
			case context.Canceled:
				cancel()
			case ErrOverloaded:
				g.Close()
			}
			wantErr(t, <-ready, want)
			cancel()
		}
	})
}

func TestEmergencyReportsTransitionsWithoutAllocation(t *testing.T) {
	g := New(Options{})
	if g.Emergency() {
		t.Fatal("new guard reported Emergency")
	}
	g.RecordSample(Snapshot{Cgroups: []CgroupMemory{{Path: "/service", CurrentBytes: 95, LimitBytes: 100}}})
	if !g.Emergency() {
		t.Fatal("guard missed the emergency transition")
	}
	if got := testing.AllocsPerRun(100, func() { g.Emergency() }); got != 0 {
		t.Fatalf("emergency check allocated %g times", got)
	}
	g.RecordSample(spare)
	if g.Emergency() || !g.Diagnostics().Pressured {
		t.Fatal("guard did not distinguish Emergency from recovering Pressure")
	}
}

func TestLeaseAccounting(t *testing.T) {
	g := New(Options{})
	g.RecordSample(Snapshot{OpenFDs: 83, MaxFDs: 100})
	l := take(t, g, ClassFlow)
	_, err := g.Acquire(t.Context(), ClassFlow)
	wantErr(t, err, ErrOverloaded)
	if LeaseFromContext(WithLease(t.Context(), l)) != l || LeaseFromContext(t.Context()) != nil {
		t.Fatal("lease context did not round trip")
	}
	l.DialDone(false)
	l.DialDone(true)
	if d := g.Diagnostics(); d.ActiveFlows != 1 || d.PendingDials != 0 || d.UnmeasuredFDs != 0 {
		t.Fatalf("dial accounting = %+v", d)
	}
	take(t, g, ClassFlow).Release()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { l.DialDone(true) })
		wg.Go(l.Release)
	}
	wg.Wait()
	(*Lease)(nil).Release()
	(*Lease)(nil).DialDone(true)
	if !(*Lease)(nil).StartDial()(true) {
		t.Fatal("unguarded dial rejected its socket")
	}
	if release, ok := (*Lease)(nil).TryReserveDial(); !ok || release == nil {
		t.Fatal("an unguarded dial could not reserve")
	} else {
		release()
	}
	assertUnused(t, g)
}

func TestSuccessfulDialRetainsFDCharge(t *testing.T) {
	g := New(Options{})
	g.RecordSample(Snapshot{OpenFDs: 83, MaxFDs: 100})
	l := take(t, g, ClassFlow)
	l.DialDone(true)
	if d := g.Diagnostics(); d.PendingDials != 0 || d.UnmeasuredFDs != 1 {
		t.Fatalf("successful dial accounting = %+v", d)
	}
	_, err := g.Acquire(t.Context(), ClassFlow)
	wantErr(t, err, ErrOverloaded)
	l.Release()
	older := take(t, g, ClassFlow)
	finish := older.StartDial()
	if !finish(true) || finish(true) {
		t.Fatal("started dial did not accept its socket exactly once")
	}
	for _, missing := range []Snapshot{{}, {MaxFDs: 100, FDExhausted: true}} {
		g.RecordSample(missing)
		if d := g.Diagnostics(); d.UnmeasuredFDs != 1 {
			t.Fatalf("failed sample cleared an unmeasured charge: %+v", d)
		}
	}
	g.RecordSample(spare)
	if d := g.Diagnostics(); d.UnmeasuredFDs != 0 {
		t.Fatalf("new measurement did not clear old charges: %+v", d)
	}
	g.RecordSample(spare)
	g.RecordSample(spare)
	newer := take(t, g, ClassFlow)
	newer.DialDone(true)
	older.Release()
	if d := g.Diagnostics(); d.UnmeasuredFDs != 1 {
		t.Fatalf("old lease released a charge from the current FD scan: %+v", d)
	}
	newer.Release()
	assertUnused(t, g)
}

func TestParallelDialReservations(t *testing.T) {
	g := New(Options{})
	g.RecordSample(Snapshot{OpenFDs: 82, MaxFDs: 100})
	l := take(t, g, ClassFlow)
	finish, ok := l.TryReserveDial()
	if !ok || finish == nil {
		t.Fatal("parallel attempt was rejected with FD headroom")
	}
	if d := g.Diagnostics(); d.PendingDials != 2 {
		t.Fatalf("parallel attempt did not reserve another FD: %+v", d)
	}
	if release, ok := l.TryReserveDial(); ok || release != nil {
		t.Fatal("overlapping attempt was admitted without FD headroom")
	}
	_, err := g.Acquire(t.Context(), ClassFlow)
	wantErr(t, err, ErrOverloaded)
	finish()
	finish()
	take(t, g, ClassFlow).Release()
	l.DialDone(false)
	g.RecordSample(hard)
	if release, ok := l.TryReserveDial(); ok || release != nil {
		t.Fatal("overlapping attempt was admitted during Emergency")
	}
	g.Close()
	l.Release()
	assertUnused(t, g)
}

func TestStartedDialOwnsReservationAfterRelease(t *testing.T) {
	g := New(Options{})
	g.RecordSample(Snapshot{OpenFDs: 83, MaxFDs: 100})
	lease := take(t, g, ClassFlow)
	finish := lease.StartDial()
	if lease.StartDial()(true) {
		t.Fatal("duplicate dial accepted a socket")
	}
	lease.DialDone(false)
	lease.Release()
	if finish(true) {
		t.Fatal("revoked dial accepted its socket")
	}
	if d := g.Diagnostics(); d.ActiveFlows != 0 || d.PendingDials != 1 || d.UnmeasuredFDs != 0 {
		t.Fatalf("rejected socket lost its in-flight reservation: %+v", d)
	}
	_, err := g.Acquire(t.Context(), ClassFlow)
	wantErr(t, err, ErrOverloaded)
	if finish(false) || finish(false) {
		t.Fatal("retiring the reservation accepted a socket")
	}
	assertUnused(t, g)

	unused := take(t, g, ClassFlow)
	unused.Release()
	if unused.StartDial()(true) {
		t.Fatal("released lease accepted a new dial")
	}
	assertUnused(t, g)
	take(t, g, ClassFlow).Release()
}

func TestRejectedSocketKeepsWaiterQueuedUntilClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := New(Options{})
		g.RecordSample(Snapshot{OpenFDs: 82, MaxFDs: 100})
		lease := take(t, g, ClassFlow)
		finish := lease.StartDial()
		press(g)
		waiter := attempt(g, t.Context())
		synctest.Wait()
		if g.Diagnostics().Waiters != 1 {
			t.Fatal("flow did not queue behind the started dial")
		}
		releaseOverlap, ok := lease.TryReserveDial()
		if !ok {
			t.Fatal("could not reserve the other available FD slot")
		}
		lease.Release()
		if finish(true) {
			t.Fatal("revoked dial accepted its socket")
		}
		synctest.Wait()
		if d := g.Diagnostics(); d.Waiters != 1 || d.PendingDials != 2 || len(waiter) != 0 {
			t.Fatalf("rejection opened the FD slot before the socket closed: %+v", d)
		}
		finish(false)
		finish(false)
		synctest.Wait()
		if len(waiter) != 1 {
			t.Fatal("socket closure did not wake the waiter")
		}
		admitted := <-waiter
		wantErr(t, admitted.err, nil)
		if d := g.Diagnostics(); d.PendingDials != 2 || d.Waiters != 0 {
			t.Fatalf("handoff charged the wrong reservations: %+v", d)
		}
		admitted.lease.Release()
		releaseOverlap()
		assertUnused(t, g)
	})
}

func assertUnused(t *testing.T, g *Guard) {
	t.Helper()
	if d := g.Diagnostics(); d.ActiveFlows != 0 || d.ActiveProbes != 0 || d.PendingDials != 0 || d.UnmeasuredFDs != 0 || d.Waiters != 0 {
		t.Fatalf("admission accounting leaked: %+v", d)
	}
}

func TestLinuxSamples(t *testing.T) {
	root := t.TempDir()
	for name, value := range map[string]string{
		"memory.max": "8000\n", "memory.current": "2000\n",
		"tenant/memory.high": "2000\n", "tenant/memory.max": "4000\n", "tenant/memory.current": "1960\n",
		"tenant/memory.events": "high 8\noom 2\n", "tenant/worker/memory.events": "high 1\n",
		"tenant/worker/memory.max": "1000\n", "tenant/worker/memory.high": "max\n", "tenant/worker/memory.current": "250\n",
	} {
		path := filepath.Join(root, name)
		wantErr(t, os.MkdirAll(filepath.Dir(path), 0700), nil)
		wantErr(t, os.WriteFile(path, []byte(value), 0600), nil)
	}
	group := unifiedCgroup("6:memory:/legacy\n0::/tenant/worker\n")
	if limit := minCgroupLimit(root, group); limit != 1000 {
		t.Fatalf("minimum cgroup limit = %d", limit)
	}
	var s Snapshot
	sampleCgroups(&s, root, group)
	want := []CgroupMemory{
		{Path: filepath.Join(root, "tenant/worker"), CurrentBytes: 250, LimitBytes: 1000, ReclaimEvents: 1},
		{Path: filepath.Join(root, "tenant"), CurrentBytes: 1960, LimitBytes: 2000, ReclaimEvents: 10},
		{Path: root, CurrentBytes: 2000, LimitBytes: 8000},
	}
	if !slices.Equal(s.Cgroups, want) || s.CgroupCurrentBytes != 1960 || s.CgroupLimitBytes != 2000 || s.CgroupReclaimEvents != 10 {
		t.Fatalf("ancestor samples or highest utilization summary = %+v", s)
	}
	wantErr(t, os.WriteFile(filepath.Join(root, "tenant/memory.current"), []byte("500\n"), 0600), nil)
	s = Snapshot{}
	sampleCgroups(&s, root, group)
	if s.CgroupLimitBytes != 1000 {
		t.Fatalf("summary did not break equal utilization by smaller limit: %+v", s)
	}
	if n := memoryEvents("low 123\nhigh 2\nmax 3\noom 5\noom_kill 7\noom_group_kill 11\n"); n != 17 {
		t.Fatalf("reclaim events = %d", n)
	}
	if total, free := meminfo("MemTotal: 512000 kB\nMemAvailable: 100000 kB\n"); total != 512000<<10 || free != 100000<<10 {
		t.Fatalf("host memory = %d, %d", total, free)
	}
	if total, _ := meminfo("MemTotal: 512000 kB\n"); total != 0 {
		t.Fatal("missing MemAvailable was presented as measured zero")
	}
	t.Setenv("GOMEMLIMIT", "64MiB")
	before := debug.SetMemoryLimit(-1)
	if limit, changed := ConfigureMemoryLimit(); limit != 0 || changed || debug.SetMemoryLimit(-1) != before {
		t.Fatal("explicit GOMEMLIMIT was overridden")
	}
}

func BenchmarkGuardHealthyAcquireRelease(b *testing.B) {
	g := New(Options{})
	g.RecordSample(spare)
	ctx := b.Context()
	b.ReportAllocs()
	for b.Loop() {
		lease, err := g.Acquire(ctx, ClassFlow)
		if err != nil {
			b.Fatal(err)
		}
		lease.Release()
	}
}
