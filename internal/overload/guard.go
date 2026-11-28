// SPDX-License-Identifier: GPL-3.0-or-later

// Package overload gates new authenticated work on resource headroom.
package overload

import (
	"cmp"
	"context"
	"errors"
	"math"
	"os"
	"runtime/metrics"
	"slices"
	"sync"
	"syscall"
	"time"
)

type Class uint8

const (
	ClassFlow Class = iota
	ClassFlowNoWait
	ClassProbe
)

var ErrOverloaded = errors.New("server overloaded")

type CgroupMemory struct {
	Path          string
	CurrentBytes  uint64
	LimitBytes    uint64
	ReclaimEvents uint64
}

type Snapshot struct {
	Time                  time.Time
	GoMemoryBytes         uint64
	GoMemoryLimit         uint64
	CgroupCurrentBytes    uint64
	CgroupLimitBytes      uint64
	CgroupReclaimEvents   uint64
	Cgroups               []CgroupMemory
	HostMemAvailableBytes uint64
	HostMemTotalBytes     uint64
	OpenFDs               uint64
	MaxFDs                uint64
	FDExhausted           bool
	FDProbeOK             bool
	ProbeFreeFDs          uint64
	ProbeReserve          uint64
	ProbeLimit            uint64
}

type Diagnostics struct {
	Pressured     bool
	Emergency     bool
	ActiveFlows   int64
	ActiveProbes  int64
	PendingDials  int64
	UnmeasuredFDs int64
	Waiters       int64
	LastSample    Snapshot
}

type Options struct {
	SampleInterval time.Duration
	MaxWaiters     int
	MaxWait        time.Duration
	ProbeReserve   int
	Sample         func(context.Context) Snapshot
}

type Guard struct {
	mu               sync.Mutex
	opts             Options
	done             chan struct{}
	cancelSampler    context.CancelFunc
	closed           bool
	state            Diagnostics
	emergencyClear   chan struct{}
	fdExhausted      bool
	fdExhaustedSeq   uint64
	fdSeq            uint64
	fdHeadroomSeq    uint64
	hasMeasuredFDs   bool
	hasProbeFDs      bool
	unmeasured       map[uint64]int64
	prevCgroupEvents map[string]uint64
	previousLow      bool
	healthySamples   int
	pressureCap      int64
	waiters          []chan *Lease
	callbacks        map[*func(bool)]struct{}
	notices          []func()
	notifying        bool
}

func New(opts Options) *Guard {
	opts.SampleInterval = cmp.Or(max(0, opts.SampleInterval), time.Second)
	opts.MaxWaiters = cmp.Or(max(0, opts.MaxWaiters), 64)
	opts.MaxWait = cmp.Or(max(0, opts.MaxWait), 2*time.Second)
	opts.ProbeReserve = cmp.Or(max(0, opts.ProbeReserve), 8)
	if opts.Sample == nil {
		opts.Sample = sampleSystem
	}
	return &Guard{opts: opts, done: make(chan struct{}), callbacks: make(map[*func(bool)]struct{})}
}

func (g *Guard) Start(ctx context.Context) {
	g.mu.Lock()
	if g.closed || g.cancelSampler != nil || ctx.Err() != nil {
		g.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	g.cancelSampler = cancel
	g.mu.Unlock()
	sample := func() {
		scanSeq := g.beginSample()
		g.recordSample(g.opts.Sample(ctx), scanSeq)
	}
	sample()
	go func() {
		defer cancel()
		ticker := time.NewTicker(g.opts.SampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if ctx.Err() == nil {
					sample()
				}
			}
		}
	}()
}

func (g *Guard) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed {
		g.closed = true
		g.waiters = nil
		close(g.done)
		if g.cancelSampler != nil {
			g.cancelSampler()
		}
	}
}

// percent avoids overflow even with an unusually large configured limit.
func percent(n, p uint64) uint64 { return n/100*p + n%100*p/100 }

func memoryAt(current, limit, p uint64) bool {
	return limit != 0 && current >= limit-percent(limit, 100-p)
}

func memoryPressure(current, limit uint64, reclaim bool) (hard, low, healthy bool) {
	atRecovery := memoryAt(current, limit, 70)
	return memoryAt(current, limit, 90), memoryAt(current, limit, 80) || reclaim && atRecovery, !atRecovery
}

func (g *Guard) cgroupPressure(s Snapshot) (hard, low, healthy bool) {
	if len(s.Cgroups) == 0 {
		g.prevCgroupEvents = nil
		return memoryPressure(s.CgroupCurrentBytes, s.CgroupLimitBytes,
			s.CgroupReclaimEvents > g.state.LastSample.CgroupReclaimEvents)
	}
	healthy = true
	events := make(map[string]uint64, len(s.Cgroups))
	for _, cgroup := range s.Cgroups {
		atHard, atLow, belowRecovery := memoryPressure(cgroup.CurrentBytes, cgroup.LimitBytes,
			cgroup.ReclaimEvents > g.prevCgroupEvents[cgroup.Path])
		hard, low, healthy = hard || atHard, low || atLow, healthy && belowRecovery
		events[cgroup.Path] = cgroup.ReclaimEvents
	}
	g.prevCgroupEvents = events
	return hard, low, healthy
}

func (g *Guard) fdRoom(reserve uint64) bool {
	s := &g.state.LastSample
	left := s.ProbeFreeFDs
	if s.MaxFDs != 0 {
		if s.OpenFDs >= s.MaxFDs {
			return false
		}
		left = s.MaxFDs - s.OpenFDs
	} else if !g.hasProbeFDs {
		return true
	}
	pending, unmeasured := uint64(g.state.PendingDials), uint64(g.state.UnmeasuredFDs)
	return pending < left && unmeasured < left-pending && reserve < left-pending-unmeasured
}

const defaultFDReserve = 16

func fdFlowReserve(limit uint64) uint64 {
	return min(64, max(defaultFDReserve, limit/20), limit/2)
}

func (g *Guard) flowRoom() bool {
	s := &g.state.LastSample
	if g.hasProbeFDs {
		return g.fdRoom(cmp.Or(s.ProbeReserve, defaultFDReserve))
	}
	return g.fdRoom(fdFlowReserve(s.MaxFDs))
}

func (g *Guard) RecordSample(s Snapshot) {
	g.recordSample(s, g.beginSample())
}

func (g *Guard) beginSample() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fdSeq++
	return g.fdSeq
}

func (g *Guard) recordSample(s Snapshot, scanSeq uint64) {
	g.mu.Lock()
	defer g.notifyAndUnlock()
	if g.closed {
		return
	}
	d := &g.state
	s.Cgroups = slices.Clone(s.Cgroups)
	hard, low, healthy := g.cgroupPressure(s)
	newerFDs := scanSeq > g.fdHeadroomSeq
	freshFDs := newerFDs && s.MaxFDs != 0 && !s.FDExhausted
	freshProbe := newerFDs && !freshFDs && !s.FDExhausted && s.ProbeFreeFDs != 0 && scanSeq > g.fdExhaustedSeq
	switch {
	case freshFDs || freshProbe:
		g.hasMeasuredFDs, g.hasProbeFDs = freshFDs, freshProbe
		g.fdHeadroomSeq = scanSeq
		if freshProbe {
			s.OpenFDs, s.MaxFDs = 0, 0
		}
		// A sample can miss sockets opened after it began.
		for seq, count := range g.unmeasured {
			if seq < scanSeq {
				d.UnmeasuredFDs -= count
				delete(g.unmeasured, seq)
			}
		}
	case g.hasMeasuredFDs || g.hasProbeFDs || !newerFDs:
		s.OpenFDs, s.MaxFDs = d.LastSample.OpenFDs, d.LastSample.MaxFDs
		s.ProbeFreeFDs, s.ProbeReserve = d.LastSample.ProbeFreeFDs, d.LastSample.ProbeReserve
		s.ProbeLimit = d.LastSample.ProbeLimit
	}
	d.LastSample = s
	fdRecovery, fdPressure := percent(s.MaxFDs, 30), percent(s.MaxFDs, 20)
	if g.hasProbeFDs {
		reserve := cmp.Or(s.ProbeReserve, defaultFDReserve)
		if s.ProbeLimit != 0 {
			fdRecovery, fdPressure = percent(s.ProbeLimit, 30), percent(s.ProbeLimit, 20)
		} else {
			fdRecovery, fdPressure = reserve+max(1, reserve/2), reserve+max(1, reserve/4)
		}
	}
	fdHealthy, fdLow := g.fdRoom(fdRecovery), !g.fdRoom(fdPressure)
	if s.FDExhausted {
		g.fdExhausted = true
		g.fdExhaustedSeq = max(g.fdExhaustedSeq, scanSeq)
	} else if scanSeq > g.fdExhaustedSeq {
		headroomOK := (freshFDs || freshProbe) && fdHealthy && g.flowRoom()
		allocationOK := s.FDProbeOK && !g.hasMeasuredFDs && !g.hasProbeFDs
		if headroomOK || allocationOK {
			g.fdExhausted = false
		}
	}
	hard = hard || g.fdExhausted || !g.flowRoom() || memoryAt(s.GoMemoryBytes, s.GoMemoryLimit, 90)
	low = low || fdLow || memoryAt(s.GoMemoryBytes, s.GoMemoryLimit, 80)
	healthy = healthy && fdHealthy && !memoryAt(s.GoMemoryBytes, s.GoMemoryLimit, 70)
	if len(s.Cgroups) == 0 && s.CgroupLimitBytes == 0 && s.HostMemTotalBytes != 0 {
		available, total := s.HostMemAvailableBytes, s.HostMemTotalBytes
		hard = hard || available <= min(64<<20, percent(total, 8))
		low = low || available < min(128<<20, percent(total, 15))
		healthy = healthy && available >= min(192<<20, percent(total, 20))
	}
	if d.Pressured && healthy && !hard {
		g.healthySamples++
	} else {
		g.healthySamples = 0
	}
	pressured := hard || low && g.previousLow || d.Pressured && g.healthySamples < 3
	g.setState(pressured, hard)
	g.previousLow = low
	for g.wakeOne() {
		if d.Pressured {
			break
		}
	}
}

func isFDExhausted(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}

var checkSingleFD = probeSingleFD

func probeSingleFD() (ok, exhausted bool) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		return false, isFDExhausted(err)
	}
	file.Close()
	return true, false
}

func (g *Guard) ObserveError(err error) {
	if !isFDExhausted(err) {
		return
	}
	g.mu.Lock()
	defer g.notifyAndUnlock()
	if !g.closed {
		g.fdExhausted, g.healthySamples = true, 0
		g.fdExhaustedSeq = g.fdSeq
		g.setState(true, true)
	}
}

func (g *Guard) setState(pressured, emergency bool) {
	if emergency && g.emergencyClear == nil {
		g.emergencyClear = make(chan struct{})
	} else if !emergency && g.emergencyClear != nil {
		close(g.emergencyClear)
		g.emergencyClear = nil
	}
	g.state.Emergency = emergency
	if g.state.Pressured == pressured {
		return
	}
	g.state.Pressured = pressured
	if pressured {
		g.pressureCap = max(1, g.state.ActiveFlows)
	}
	for fn := range g.callbacks {
		g.notices = append(g.notices, func() { (*fn)(pressured) })
	}
}

// One caller drains transitions in order. Callbacks may inspect or update the guard.
func (g *Guard) notifyAndUnlock() {
	if g.notifying || len(g.notices) == 0 {
		g.mu.Unlock()
		return
	}
	g.notifying = true
	defer func() {
		g.notifying = false
		g.mu.Unlock()
	}()
	for len(g.notices) != 0 {
		notices := g.notices
		g.notices = nil
		g.mu.Unlock()
		func() {
			defer g.mu.Lock()
			for _, fn := range notices {
				fn()
			}
		}()
	}
}

func (g *Guard) OnPressure(fn func(bool)) func() {
	g.mu.Lock()
	g.callbacks[&fn] = struct{}{}
	g.mu.Unlock()
	return func() {
		g.mu.Lock()
		delete(g.callbacks, &fn)
		g.mu.Unlock()
	}
}

func (g *Guard) canGrant(class Class) bool {
	d := &g.state
	if class == ClassProbe {
		if !d.Pressured && g.flowRoom() {
			return true
		}
		return d.ActiveProbes < int64(g.opts.ProbeReserve) && g.fdRoom(4)
	}
	return class <= ClassFlowNoWait && !d.Emergency && g.flowRoom() && (!d.Pressured || d.ActiveFlows < g.pressureCap)
}

func (g *Guard) grant(class Class) *Lease {
	probe := class == ClassProbe
	if probe {
		g.state.ActiveProbes++
	} else {
		g.state.ActiveFlows++
		g.state.PendingDials++
	}
	return &Lease{guard: g, probe: probe, pending: !probe}
}

func (g *Guard) wakeOne() bool {
	if g.closed || len(g.waiters) == 0 || !g.canGrant(ClassFlow) {
		return false
	}
	ready := g.waiters[0]
	g.waiters[0] = nil
	g.waiters = g.waiters[1:]
	ready <- g.grant(ClassFlow)
	return true
}

func (g *Guard) Acquire(ctx context.Context, class Class) (*Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	g.mu.Lock()
	immediate := class == ClassProbe || len(g.waiters) == 0
	if !g.closed && immediate && g.canGrant(class) {
		lease := g.grant(class)
		g.mu.Unlock()
		return lease, nil
	}
	if g.closed || class != ClassFlow || g.state.Emergency || !g.flowRoom() || len(g.waiters) >= g.opts.MaxWaiters {
		g.mu.Unlock()
		return nil, ErrOverloaded
	}
	ready := make(chan *Lease, 1)
	deadline := time.Now().Add(g.opts.MaxWait)
	g.waiters = append(g.waiters, ready)
	g.wakeOne()
	g.mu.Unlock()
	return g.await(ctx, ready, deadline)
}

func (g *Guard) await(ctx context.Context, ready chan *Lease, deadline time.Time) (*Lease, error) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	var lease *Lease
	select {
	case lease = <-ready:
	case <-ctx.Done():
	case <-timer.C:
	case <-g.done:
	}
	g.mu.Lock()
	if lease == nil {
		// A grant may have raced with the cancellation or timeout.
		select {
		case lease = <-ready:
		default:
			if i := slices.Index(g.waiters, ready); i >= 0 {
				g.waiters = slices.Delete(g.waiters, i, i+1)
				g.wakeOne()
			}
		}
	}
	err := ctx.Err()
	if err == nil && (lease == nil || g.closed || !time.Now().Before(deadline)) {
		err = ErrOverloaded
	}
	g.mu.Unlock()
	if err != nil {
		lease.Release()
		return nil, err
	}
	return lease, nil
}

type Lease struct {
	guard       *Guard
	openSeq     uint64
	probe       bool
	pending     bool
	dialStarted bool
	unmeasured  bool
	released    bool
}

// DialDone retires the initial reservation and charges any socket still open.
func (l *Lease) DialDone(opened bool) {
	if l == nil || l.guard == nil {
		return
	}
	g := l.guard
	g.mu.Lock()
	defer g.mu.Unlock()
	if l.released || l.dialStarted {
		return
	}
	_ = l.finishDial(opened)
}

// StartDial transfers the initial reservation to the dial's completion callback.
// If the callback rejects an open socket, close it and call the callback with false.
func (l *Lease) StartDial() func(opened bool) (accepted bool) {
	if l == nil || l.guard == nil {
		return func(bool) bool { return true }
	}
	g := l.guard
	g.mu.Lock()
	if l.released || !l.pending || l.dialStarted {
		g.mu.Unlock()
		return func(bool) bool { return false }
	}
	l.dialStarted = true
	g.mu.Unlock()
	return func(opened bool) bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		return l.finishDial(opened)
	}
}

// finishDial runs with the guard mutex held.
func (l *Lease) finishDial(opened bool) bool {
	if !l.pending || opened && l.released {
		return false
	}
	g := l.guard
	g.state.PendingDials--
	l.pending, l.dialStarted = false, false
	if !opened {
		g.wakeOne()
		return false
	}
	if g.unmeasured == nil {
		g.unmeasured = make(map[uint64]int64)
	}
	l.openSeq, l.unmeasured = g.fdSeq, true
	g.unmeasured[l.openSeq]++
	g.state.UnmeasuredFDs++
	return true
}

// TryReserveDial reserves headroom for an overlapping attempt. Release it after
// failure, closing its socket, or transferring the socket to the primary dial.
func (l *Lease) TryReserveDial() (release func(), ok bool) {
	if l == nil || l.guard == nil {
		return func() {}, true
	}
	g := l.guard
	g.mu.Lock()
	if g.closed || g.state.Emergency || !g.flowRoom() {
		g.mu.Unlock()
		return nil, false
	}
	g.state.PendingDials++
	g.mu.Unlock()
	return sync.OnceFunc(func() {
		g.mu.Lock()
		g.state.PendingDials--
		g.wakeOne()
		g.mu.Unlock()
	}), true
}

func (l *Lease) Release() {
	if l == nil || l.guard == nil {
		return
	}
	g := l.guard
	g.mu.Lock()
	defer g.mu.Unlock()
	if l.released {
		return
	}
	l.released = true
	if l.pending && !l.dialStarted {
		g.state.PendingDials--
		l.pending = false
	}
	if l.unmeasured {
		if count := g.unmeasured[l.openSeq]; count > 0 {
			g.state.UnmeasuredFDs--
			if count == 1 {
				delete(g.unmeasured, l.openSeq)
			} else {
				g.unmeasured[l.openSeq] = count - 1
			}
		}
		l.unmeasured = false
	}
	if l.probe {
		g.state.ActiveProbes--
	} else {
		g.state.ActiveFlows--
	}
	g.wakeOne()
}

type leaseKey struct{}

func WithLease(ctx context.Context, lease *Lease) context.Context {
	return context.WithValue(ctx, leaseKey{}, lease)
}

func LeaseFromContext(ctx context.Context) *Lease {
	lease, _ := ctx.Value(leaseKey{}).(*Lease)
	return lease
}

func (g *Guard) WaitAccept(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		g.mu.Lock()
		closed, clear := g.closed, g.emergencyClear
		g.mu.Unlock()
		if closed {
			return ErrOverloaded
		}
		if clear == nil {
			return nil
		}
		select {
		case <-clear:
		case <-ctx.Done():
		case <-g.done:
		}
	}
}

func (g *Guard) RetryAfter() time.Duration { return max(time.Second, g.opts.MaxWait) }

func (g *Guard) Emergency() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state.Emergency
}

func (g *Guard) Diagnostics() Diagnostics {
	g.mu.Lock()
	defer g.mu.Unlock()
	d := g.state
	d.Waiters = int64(len(g.waiters))
	d.LastSample.Cgroups = slices.Clone(d.LastSample.Cgroups)
	return d
}

func sampleGoMemory() Snapshot {
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
		{Name: "/gc/gomemlimit:bytes"},
	}
	metrics.Read(samples)
	s := Snapshot{Time: time.Now()}
	total, released := samples[0].Value.Uint64(), samples[1].Value.Uint64()
	s.GoMemoryBytes = total - min(total, released)
	if limit := samples[2].Value.Uint64(); limit < math.MaxInt64 {
		s.GoMemoryLimit = limit
	}
	return s
}
