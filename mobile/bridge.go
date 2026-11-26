// SPDX-License-Identifier: GPL-3.0-or-later

package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"pipe/internal/config"
	"pipe/internal/engine"
	"pipe/internal/failover"
	"pipe/internal/logring"
	"pipe/internal/update"
)

type clientEngine interface {
	Start() error
	Close() error
	ProbeLatency(context.Context, string, bool) (bool, time.Duration, bool, error)
	MeasureRTT(context.Context, string) (time.Duration, bool, error)
	SelectTier(string) error
	RelayState(string) string
	VPNOnline() bool
	RefreshVPNNetwork(reset bool) (bool, error)
}

func createEngine(ctx context.Context, options engine.Options) (clientEngine, error) {
	return engine.New(ctx, options)
}

type vpnStatus struct {
	Running         bool                    `json:"running"`
	Blocked         bool                    `json:"blocked,omitempty"`
	Mode            string                  `json:"mode"`
	Tier            string                  `json:"tier"`
	TierPreference  string                  `json:"tierPreference"`
	RescueAvailable bool                    `json:"rescueAvailable"`
	Server          string                  `json:"server"`
	Relay           string                  `json:"relay"`
	RelayState      string                  `json:"relayState"`
	UpBytes         int64                   `json:"upBytes"`
	DownBytes       int64                   `json:"downBytes"`
	UpRate          int64                   `json:"upBytesPerSecond"`
	DownRate        int64                   `json:"downBytesPerSecond"`
	LastError       string                  `json:"lastError"`
	LatencyMs       *int64                  `json:"latencyMs"`
	Routes          map[string]routeLatency `json:"routes"`
	MeasurementAt   *time.Time              `json:"measurementAt,omitempty"`
	ConnectedSince  int64                   `json:"connectedSince"` // unix milliseconds, 0 when off
}

type routeLatency struct {
	Ms  int64     `json:"ms"`
	OK  bool      `json:"ok"`
	At  time.Time `json:"at"`
	Via string    `json:"via,omitempty"`
}

type bridge struct {
	mu        sync.Mutex
	active    *session
	starting  bool
	updates   []*update.Manager
	newEngine func(context.Context, engine.Options) (clientEngine, error)
	guard     func() // owns the current Android VPN descriptor independent of the engine

	stateMu sync.Mutex
	state   vpnStatus
	owner   *session

	// fakeIP outlives every session (see clientctl.Controller.fakeIP).
	fakeIP *engine.FakeIP
}

type session struct {
	settings
	platform      Platform
	engine        clientEngine
	ctx           context.Context
	cancel        context.CancelFunc
	networkCtx    context.Context
	cancelNetwork context.CancelFunc

	up, down   atomic.Int64
	wake       chan struct{}
	reportDone chan struct{}
	online     atomic.Bool
	controller atomic.Pointer[failover.Controller]
	stopAuto   context.CancelFunc
	autoDone   chan struct{}
	netIPv6    bool

	life    sync.Mutex
	closing bool
	work    sync.WaitGroup // TestRoutes calls
}

// begin registers a background task; it fails once the session is closing.
func (s *session) begin() bool {
	s.life.Lock()
	defer s.life.Unlock()
	if s.closing {
		return false
	}
	s.work.Add(1)
	return true
}

func (b *bridge) start(profile, prefsJSON string, platform Platform) error {
	if platform == nil {
		return errors.New("VPN platform is required")
	}
	next, err := prepare(profile, prefsJSON)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.starting = true
	defer func() { b.starting = false }()
	for _, manager := range b.updates {
		manager.CancelDirect()
	}
	if b.active != nil || b.guard != nil {
		return errors.New("VPN is already running")
	}
	if runtime.GOOS == "android" {
		debug.SetMemoryLimit(32 * 1024 * 1024)
		debug.SetGCPercent(50)
	}
	if b.fakeIP == nil {
		b.fakeIP = &engine.FakeIP{}
	}
	netIPv6 := engine.VPNNetworkIPv6(platform.NetworkState())
	s, release, err := b.buildGuarded(next, platform, netIPv6)
	if err != nil {
		if release != nil {
			release()
		}
		return b.startError(err.Error())
	}
	b.activate(s, release)
	return nil
}

func (b *bridge) buildGuarded(next settings, platform Platform, netIPv6 bool) (s *session, release func(), err error) {
	s, err = b.buildSession(next, platform, func(closeTun func()) {
		release = closeTun
	}, netIPv6)
	return
}

func (b *bridge) buildSession(next settings, platform Platform, holdTun func(func()), netIPv6 bool) (*session, error) {
	client := networkClientOptions(next.client, netIPv6)
	var engineConfig engine.Object
	client.LANDNSServers = func() []netip.AddrPort {
		return engine.VPNNetworkLANDNSServers(platform.NetworkState(), engineConfig)
	}
	if client.Mode == config.Direct {
		client.Rules = nil // Direct means pipe is not used; prefs keep the rules.
	}
	compiled, err := config.BuildClient(client)
	if err != nil {
		return nil, errors.New("VPN configuration is invalid")
	}
	engineConfig = compiled.Config
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{
		settings: next, platform: platform, ctx: ctx, cancel: cancel,
		wake: make(chan struct{}, 1), netIPv6: netIPv6,
	}
	compiled.LogWriter = logs.Writer()
	s.networkCtx, s.cancelNetwork = context.WithCancel(ctx)
	compiled.FakeIP = b.fakeIP
	compiled.VPN = &engine.VPNOptions{
		Platform: platform, PerApp: next.apps.Mode, Packages: next.apps.Packages, HoldTun: holdTun,
		CountBytes: func(up, down int64) {
			s.up.Add(up)
			s.down.Add(down)
		},
	}
	compiled.ObserveTraffic = func() {
		if controller := s.controller.Load(); s.online.Load() && controller != nil {
			controller.ObserveTraffic()
		}
	}
	compiled.ObserveFastDial = func(err error) {
		if controller := s.controller.Load(); s.online.Load() && controller != nil {
			controller.ObserveFastDial(err)
		}
	}
	compiled.ObserveFastStall = func() {
		if controller := s.controller.Load(); s.online.Load() && controller != nil {
			controller.SuspectFastStall()
		}
	}
	instance, err := b.newEngine(ctx, compiled)
	if err != nil {
		cancel()
		return nil, errors.New("VPN engine configuration failed")
	}
	s.engine = instance
	if err := b.enableAuto(s); err != nil {
		_ = s.close()
		return nil, err
	}
	if err := instance.Start(); err != nil {
		_ = s.close()
		return nil, errors.New("Could not establish the Android VPN")
	}
	s.online.Store(instance.VPNOnline())
	return s, nil
}

func (b *bridge) activate(s *session, guard func()) {
	connectedSince := time.Now().UnixMilli()
	routes := map[string]routeLatency{}
	var measuredAt *time.Time
	if previous := b.active; previous != nil {
		b.stateMu.Lock()
		if b.state.Running && b.state.ConnectedSince != 0 {
			connectedSince = b.state.ConnectedSince
		}
		if previous.client.Relay == s.client.Relay && previous.client.IPv6 == s.client.IPv6 && previous.netIPv6 == s.netIPv6 {
			routes, measuredAt = b.state.Routes, b.state.MeasurementAt
		}
		b.stateMu.Unlock()
		_ = previous.close()
		if runtime.GOOS == "android" {
			debug.FreeOSMemory()
		}
	}
	b.active = s
	b.replaceGuard(guard)
	tier := displayedTier(s.client.Mode, s.client.Tier)
	b.stateMu.Lock()
	b.owner = s
	b.state = vpnStatus{
		Running: true, Mode: s.client.Mode, Tier: tier,
		TierPreference: string(s.client.Tier), RescueAvailable: s.client.Profile.CDN != "",
		Server: s.client.Profile.Name, Routes: routes, MeasurementAt: measuredAt,
		LatencyMs: routeMs(routes, tier),
		Relay:     s.relayHost, RelayState: s.engine.RelayState(tier),
		ConnectedSince: connectedSince,
	}
	b.stateMu.Unlock()
	name := s.client.Profile.Name
	if name == "" {
		name = "server"
	}
	logs.Add(logring.Info, "pipe", "Connected to "+name)
	b.resumeAuto(s)
	s.reportDone = make(chan struct{})
	go b.report(s)
	if s.client.Mode != config.Direct && s.online.Load() && s.begin() {
		go func() {
			defer s.work.Done()
			b.connectProbe(s, s.engine, tier)
		}()
	}
}

// connectProbe checks the active tier once after connecting.
func (b *bridge) connectProbe(s *session, instance clientEngine, tier string) {
	ctx, cancel := context.WithTimeout(s.ctx, 8*time.Second)
	defer cancel()
	_, _, _, _ = instance.ProbeLatency(ctx, tier, false)
}

func displayedTier(mode string, tier failover.Tier) string {
	if mode == config.Direct {
		return config.Direct
	}
	if tier == failover.Auto {
		return string(failover.Fast)
	}
	return string(tier)
}

func (b *bridge) startError(message string) error {
	b.stateMu.Lock()
	b.state.LastError = message
	b.stateMu.Unlock()
	return errors.New(message)
}

func (b *bridge) stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopLocked()
}

func (b *bridge) stopLocked() {
	b.endSession(nil, "")
}

func (b *bridge) replaceGuard(next func()) {
	previous := b.guard
	b.guard = next
	if previous != nil {
		previous()
	}
}

func (b *bridge) endSession(guard func(), reason string) {
	s := b.active
	if s == nil && b.guard == nil {
		return
	}
	b.active = nil
	var err error
	if s != nil {
		err = s.close()
	}
	b.replaceGuard(guard)
	b.stateMu.Lock()
	b.owner = nil
	b.state.Running, b.state.Blocked = false, guard != nil
	b.state.Tier = ""
	b.state.Relay, b.state.RelayState = "", ""
	b.state.LatencyMs, b.state.ConnectedSince = nil, 0
	b.state.Routes, b.state.MeasurementAt = map[string]routeLatency{}, nil
	if s != nil {
		b.state.UpBytes, b.state.DownBytes = s.up.Load(), s.down.Load()
	}
	b.state.UpRate, b.state.DownRate = 0, 0
	b.state.LastError = reason
	if err != nil && reason == "" {
		b.state.LastError = "VPN shutdown reported an error"
	}
	b.stateMu.Unlock()
	if s != nil {
		s.platform.OnStatus(b.statusJSON())
	}
	logs.Add(logring.Info, "pipe", "Disconnected")
}

func (s *session) close() error {
	s.life.Lock()
	s.closing = true
	s.life.Unlock()
	s.cancel()
	s.work.Wait()
	s.disableAuto()
	if s.reportDone != nil {
		<-s.reportDone
	}
	err := s.engine.Close()
	s.engine = nil
	return err
}

func (b *bridge) setTier(value string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.active
	if s == nil {
		return errors.New("VPN is not running")
	}
	tier := failover.Tier(value)
	if !validTier(tier, s.client.Profile.CDN != "") {
		return errors.New("tier is unavailable for this profile")
	}
	if tier == s.client.Tier {
		return nil
	}
	s.disableAuto()
	selected := tier
	if selected == failover.Auto {
		selected = failover.Fast
	}
	if err := s.engine.SelectTier(string(selected)); err != nil {
		_ = b.enableAuto(s)
		b.resumeAuto(s)
		return errors.New("VPN tier could not be selected")
	}
	s.client.Tier = tier
	b.update(s, func(status *vpnStatus) {
		status.Tier = displayedTier(s.client.Mode, tier)
		status.RelayState = s.engine.RelayState(status.Tier)
		status.LatencyMs = routeMs(status.Routes, status.Tier)
		status.TierPreference = value
		status.LastError = ""
	})
	s.notify()
	err := b.enableAuto(s)
	b.resumeAuto(s)
	return err
}

func (b *bridge) setMode(mode string) error {
	if !config.ValidMode(mode) {
		return errors.New("mode must be smart, global or direct")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.active
	if s == nil {
		return errors.New("VPN is not running")
	}
	if s.client.Mode == mode {
		return nil
	}
	next := s.settings
	next.client.Mode = mode
	return b.replace(s, next)
}

func (b *bridge) applyPreferences(prefsJSON string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.active
	if s == nil {
		return errors.New("VPN is not running")
	}
	next, err := prepareProfile(s.client.Profile, prefsJSON)
	if err != nil {
		return err
	}
	if next.client.Mode == s.client.Mode && next.client.IPv6 == s.client.IPv6 &&
		next.client.Tier == s.client.Tier && next.client.Relay == s.client.Relay && next.apps.Mode == s.apps.Mode &&
		slices.Equal(next.apps.Packages, s.apps.Packages) &&
		next.client.LogLevel == s.client.LogLevel && slices.Equal(next.client.Rules, s.client.Rules) &&
		next.client.TestAddress == s.client.TestAddress && next.client.TestCAFile == s.client.TestCAFile {
		return nil
	}
	return b.replace(s, next)
}

func (b *bridge) replace(previous *session, next settings) error {
	return b.replaceForNetwork(previous, next, engine.VPNNetworkIPv6(previous.platform.NetworkState()))
}

func (b *bridge) replaceForNetwork(previous *session, next settings, netIPv6 bool) error {
	replacement, guard, err := b.buildGuarded(next, previous.platform, netIPv6)
	if err == nil {
		b.activate(replacement, guard)
		return nil
	}
	if guard == nil {
		return err
	}
	// The most recently established interface owns Android's routes.
	// Retain it across a failed engine start, including a failed rollback.
	restored, rollbackGuard, restoreErr := b.buildGuarded(previous.settings, previous.platform, previous.netIPv6)
	if restoreErr == nil {
		b.activate(restored, rollbackGuard)
		guard()
	} else {
		if rollbackGuard != nil {
			guard()
			guard = rollbackGuard
		}
		b.endSession(guard, err.Error())
	}
	return err
}

func (b *bridge) networkChanged(reset bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s := b.active; s != nil {
		// Offline is not "no IPv6": the TUN stays as it is and the engine
		// pauses until a network returns, so a handoff swaps the TUN at most once.
		state := s.platform.NetworkState()
		if netIPv6 := engine.VPNNetworkIPv6(state); netIPv6 != s.netIPv6 && engine.VPNNetworkOnline(state) {
			_ = b.replaceForNetwork(s, s.settings, netIPv6)
			return
		}
		online, err := s.engine.RefreshVPNNetwork(reset)
		if err != nil {
			return
		}
		s.online.Store(online)
		if reset || !online {
			s.cancelNetwork()
		}
		if !online {
			s.pauseAuto()
			return
		}
		if s.networkCtx.Err() != nil {
			s.networkCtx, s.cancelNetwork = context.WithCancel(s.ctx)
		}
		if reset && s.client.Relay != "" {
			b.refreshRelayState(s)
			s.notify()
		}
		if controller := s.controller.Load(); reset && controller != nil {
			controller.Reset()
		}
		b.resumeAuto(s)
	}
}

func (b *bridge) enableAuto(s *session) error {
	if s.client.Mode == config.Direct || s.client.Tier != failover.Auto {
		return nil
	}
	var extraProbeTime time.Duration
	if s.client.Relay != "" {
		extraProbeTime = engine.RelayFallbackDelay
	}
	controller, err := failover.New(failover.Options{
		Tiers:          failover.Available(s.client.Profile.CDN != ""),
		ExtraProbeTime: extraProbeTime,
		Probe: func(ctx context.Context, tier failover.Tier, burst bool) (bool, error) {
			stalled, _, _, err := s.engine.ProbeLatency(ctx, string(tier), burst)
			return stalled, err
		},
		Select: func(tier failover.Tier) error {
			if err := s.engine.SelectTier(string(tier)); err != nil {
				return err
			}
			var from string
			b.update(s, func(status *vpnStatus) {
				from = status.Tier
				status.Tier = string(tier)
				status.RelayState = s.engine.RelayState(status.Tier)
				status.LatencyMs = routeMs(status.Routes, string(tier))
			})
			if from != "" && from != string(tier) {
				logs.Add(logring.Info, "pipe", "Route switched: "+from+" -> "+string(tier))
			}
			s.notify()
			return nil
		},
	})
	if err != nil {
		return errors.New("VPN failover could not start")
	}
	s.controller.Store(controller)
	return nil
}

func (b *bridge) resumeAuto(s *session) {
	controller := s.controller.Load()
	if !s.online.Load() || controller == nil || s.stopAuto != nil {
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	done := make(chan struct{})
	s.stopAuto, s.autoDone = cancel, done
	go func() {
		defer close(done)
		if err := controller.Run(ctx); err != nil && ctx.Err() == nil {
			b.update(s, func(status *vpnStatus) { status.LastError = "VPN failover could not select a tier" })
			s.notify()
		}
	}()
}

func (s *session) disableAuto() {
	s.controller.Store(nil)
	s.pauseAuto()
}

func (s *session) pauseAuto() {
	if s.stopAuto != nil {
		s.stopAuto()
		<-s.autoDone
		s.stopAuto = nil
	}
}

func (s *session) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (b *bridge) update(s *session, update func(*vpnStatus)) {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	if b.owner == s {
		update(&b.state)
	}
}

func routeMs(routes map[string]routeLatency, tier string) *int64 {
	if r, ok := routes[tier]; ok && r.OK && r.Ms > 0 {
		ms := r.Ms
		return &ms
	}
	return nil
}

// testRoutes measures the application RTT of each available route in parallel.
func (b *bridge) testRoutes() string {
	b.mu.Lock()
	s := b.active
	var instance clientEngine
	if s != nil {
		instance = s.engine
	}
	b.mu.Unlock()
	result := map[string]routeLatency{}
	if s != nil && instance != nil && s.client.Mode != config.Direct && s.begin() {
		defer s.work.Done()
		ctx, cancel := context.WithTimeout(s.ctx, 12*time.Second)
		defer cancel()
		if e, ok := instance.(interface {
			ProbeContext(context.Context) context.Context
		}); ok {
			ctx = e.ProbeContext(ctx)
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, tier := range failover.Available(s.client.Profile.CDN != "") {
			wg.Add(1)
			go func() {
				defer wg.Done()
				probeCtx, stop := context.WithTimeout(ctx, 8*time.Second)
				defer stop()
				rtt, via, err := instance.MeasureRTT(probeCtx, string(tier))
				entry := routeLatency{At: time.Now(), OK: err == nil && probeCtx.Err() == nil}
				if entry.OK && rtt > 0 {
					entry.Ms = max(rtt.Round(time.Millisecond).Milliseconds(), 1)
				}
				if entry.OK && via {
					entry.Via = "relay"
				}
				mu.Lock()
				result[string(tier)] = entry
				mu.Unlock()
			}()
		}
		wg.Wait()
		if s.ctx.Err() == nil {
			at := time.Now()
			b.update(s, func(status *vpnStatus) {
				status.Routes = result
				status.MeasurementAt = &at
				status.LatencyMs = routeMs(result, status.Tier)
			})
			s.notify()
		} else {
			result = map[string]routeLatency{}
		}
	}
	body, _ := json.Marshal(result)
	return string(body)
}

func (b *bridge) statusJSON() string {
	b.stateMu.Lock()
	status := b.state
	if status.Routes != nil {
		status.Routes = maps.Clone(status.Routes)
	} else {
		status.Routes = map[string]routeLatency{}
	}
	if status.LatencyMs != nil {
		v := *status.LatencyMs
		status.LatencyMs = &v
	}
	b.stateMu.Unlock()
	body, _ := json.Marshal(status)
	return string(body)
}

func (b *bridge) refreshRelayState(s *session) {
	b.update(s, func(status *vpnStatus) { status.RelayState = s.engine.RelayState(status.Tier) })
}

func (b *bridge) report(s *session) {
	defer close(s.reportDone)
	last := time.Now()
	var up, down int64
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if s.client.Relay != "" {
			b.refreshRelayState(s)
		}
		s.platform.OnStatus(b.statusJSON())
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
		case now := <-ticker.C:
			newUp, newDown := s.up.Load(), s.down.Load()
			duration := now.Sub(last).Seconds()
			if duration > 0 {
				b.update(s, func(status *vpnStatus) {
					status.UpBytes, status.DownBytes = newUp, newDown
					status.UpRate = int64(float64(newUp-up) / duration)
					status.DownRate = int64(float64(newDown-down) / duration)
				})
				up, down, last = newUp, newDown, now
			}
		}
	}
}
