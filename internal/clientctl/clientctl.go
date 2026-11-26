// SPDX-License-Identifier: GPL-3.0-or-later

// Package clientctl runs the desktop and command-line client sessions.
package clientctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pipe/internal/config"
	"pipe/internal/engine"
	"pipe/internal/failover"
	"pipe/internal/link"
	"pipe/internal/logring"
	"pipe/internal/sysdns"
)

const (
	StateOff        = "off"
	StateConnecting = "connecting"
	StateOn         = "on"
	StateError      = "error"

	probeTimeout      = 8 * time.Second
	IPv6WatchInterval = 10 * time.Second
)

type Options struct {
	Profile  link.Profile  // zero for a session without a proxy profile
	Relay    string        // optional relay code
	Mode     string        // smart|global|direct
	Tier     failover.Tier // auto|fast|stealth|rescue
	IPv6     bool
	Rules    []config.Rule
	Listen   string // loopback addr:port, default 127.0.0.1:7890
	LogLevel string // warn|info|debug
	// TUN also keeps the mixed inbound on Listen unless TUNOnly is set.
	TUN, TUNOnly bool
	// RulesInDirect applies user rules even when the default route is direct.
	RulesInDirect bool
	SystemProxy   bool
	TestCAFile    string
	TestAddress   netip.Addr
	TestHosts     map[string]netip.Addr
}

// UsesProxy reports whether any traffic can use a proxy tier.
func (o Options) UsesProxy() bool {
	return o.Mode != config.Direct || (o.RulesInDirect && slices.ContainsFunc(o.Rules, func(r config.Rule) bool {
		return r.Action == "proxy"
	}))
}

// Settings configure reporting for the controller's lifetime.
// Callbacks must not call lifecycle methods on the controller.
type Settings struct {
	Logs             *logring.Ring
	EngineLogOutput  io.Writer
	OnTier           func(failover.Tier)
	OnRelayStatus    func(host, state string) // status tick for a configured relay
	OnFailoverError  func(error)
	RawErrors        bool // keep underlying engine errors in results and status
	SkipConnectProbe bool
	MaxRules         int // zero leaves the limit to the caller
}

type RouteLatency struct {
	Ms  int64     `json:"ms"`
	OK  bool      `json:"ok"`
	At  time.Time `json:"at"`
	Via string    `json:"via,omitempty"`
}

type Status struct {
	State           string                  `json:"state"`             // off|connecting|on|error
	Guarded         bool                    `json:"guarded,omitempty"` // the drop-only TUN device holds capture
	Profile         string                  `json:"profile"`
	Server          string                  `json:"server"` // host only
	Relay           string                  `json:"relay"`
	RelayState      string                  `json:"relayState"`
	Mode            string                  `json:"mode"`
	TierPreference  string                  `json:"tierPreference"`
	Tier            string                  `json:"tier"` // active route: fast|stealth|rescue|direct|""
	RescueAvailable bool                    `json:"rescueAvailable"`
	IPv6Available   *bool                   `json:"ipv6Available"` // the network has IPv6; null when off
	TUNIPv6         bool                    `json:"tunIPv6"`       // the active TUN has IPv6 capture configured
	LatencyMs       *int64                  `json:"latencyMs"`     // null until measured
	Routes          map[string]RouteLatency `json:"routes"`
	Listen          string                  `json:"listen"`
	UpBytes         int64                   `json:"upBytes"`
	DownBytes       int64                   `json:"downBytes"`
	UpRate          int64                   `json:"upBytesPerSecond"`
	DownRate        int64                   `json:"downBytesPerSecond"`
	ProxyUpRate     int64                   `json:"proxyUpBytesPerSecond"`
	ProxyDownRate   int64                   `json:"proxyDownBytesPerSecond"`
	ConnectedSince  *time.Time              `json:"connectedSince"`
	LastError       string                  `json:"lastError"`
}

// engineAPI is the part of engine.Instance the controller uses.
type engineAPI interface {
	probeEngine
	SelectTier(string) error
	RelayState(tag string) string
	DefaultInterface() string
	OnNetworkChange(reset func()) func()
}

// Controller owns at most one running session.
type Controller struct {
	settings       Settings
	newEngine      func(context.Context, engine.Options) (engineAPI, error)
	landDNSServers func() []netip.AddrPort
	OnStopped      func()

	mu      sync.Mutex // serializes lifecycle operations
	current *session
	ready   func() error // readiness callback (e.g. macOS DNS check) retained across rebuilds
	// The guard is held across a TUN rebuild and can outlive both engines.
	startTUNGuard func() (io.Closer, error)
	tunGuard      io.Closer
	releaseDNS    func()
	// networkIPv6 reports whether the network offers IPv6 (engine.NetworkIPv6).
	networkIPv6 func() bool
	ipv6Seen    int8          // last networkIPv6 result: 0 unknown, 1 yes, -1 no
	ipv6Every   time.Duration // how often a session re-checks networkIPv6
	// fakeIP lives as long as the controller: apps keep fake IPs after a
	// rebuild or a stop, so an address must never point at a new name.
	fakeIP *engine.FakeIP

	stateMu sync.Mutex
	owner   *session
	status  Status
}

func New(logs *logring.Ring) *Controller {
	return NewWithSettings(Settings{Logs: logs, MaxRules: 500})
}

func NewWithSettings(settings Settings) *Controller {
	if settings.Logs == nil {
		settings.Logs = logring.New(0)
	}
	return &Controller{
		settings: settings,
		newEngine: func(ctx context.Context, options engine.Options) (engineAPI, error) {
			return engine.New(ctx, options)
		},
		startTUNGuard: startTUNGuard,
		fakeIP:        &engine.FakeIP{},
		networkIPv6:   engine.NetworkIPv6,
		ipv6Every:     IPv6WatchInterval,
		status:        Status{State: StateOff, Routes: map[string]RouteLatency{}},
	}
}

// SetLANDNSServers supplies DNS servers from the active physical network.
func (c *Controller) SetLANDNSServers(provider func() []netip.AddrPort) {
	c.mu.Lock()
	c.landDNSServers = provider
	c.mu.Unlock()
}

// SetOnStopped sets the callback for a session that ends without Stop. The
// callback runs after engine shutdown and must not call lifecycle methods.
func (c *Controller) SetOnStopped(callback func()) {
	c.mu.Lock()
	c.OnStopped = callback
	c.mu.Unlock()
}

func (c *Controller) notifyStopped() {
	if c.current == nil && c.tunGuard == nil && c.OnStopped != nil {
		c.OnStopped()
	}
}

type session struct {
	opts      Options // immutable; the live tier is in tier
	relayHost string
	netIPv6   bool         // the network had IPv6 when this engine was built
	tier      atomic.Value // failover.Tier
	life      sync.Mutex
	closing   bool
	work      sync.WaitGroup // connect probe and TestRoutes calls
	engine    engineAPI
	ctx       context.Context
	cancel    context.CancelFunc

	up, down           atomic.Int64
	proxyUp, proxyDown atomic.Int64
	controller         atomic.Pointer[failover.Controller]
	stopAuto           context.CancelFunc
	autoDone           chan struct{}
	unregister         func()
	reportDone         chan struct{}
}

// current returns the session options with the live route preference.
func (s *session) current() Options {
	o := s.opts
	o.Tier = s.tier.Load().(failover.Tier)
	return o
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

func (c *Controller) Status() Status {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	s := c.status
	if s.Relay != "" && c.owner != nil {
		s.RelayState = c.owner.engine.RelayState(s.Tier)
	}
	s.Routes = make(map[string]RouteLatency, len(c.status.Routes))
	for k, v := range c.status.Routes {
		s.Routes[k] = v
	}
	if c.status.IPv6Available != nil {
		v := *c.status.IPv6Available
		s.IPv6Available = &v
	}
	if c.status.LatencyMs != nil {
		v := *c.status.LatencyMs
		s.LatencyMs = &v
	}
	if c.status.ConnectedSince != nil {
		v := *c.status.ConnectedSince
		s.ConnectedSince = &v
	}
	return s
}

// DefaultInterface returns the active engine's physical uplink, if available.
func (c *Controller) DefaultInterface() string {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.owner == nil {
		return ""
	}
	return c.owner.engine.DefaultInterface()
}

func (c *Controller) update(s *session, fn func(*Status)) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.owner == s {
		fn(&c.status)
	}
}

func (c *Controller) event(level, format string, args ...any) {
	c.settings.Logs.Add(level, "pipe", fmt.Sprintf(format, args...))
}

func (c *Controller) reportTier(previous, current string) {
	if c.settings.OnTier != nil && current != config.Direct && current != previous {
		c.settings.OnTier(failover.Tier(current))
	}
}

func (c *Controller) normalize(o Options) (Options, error) {
	if o.Mode == "" {
		o.Mode = config.Smart
	}
	if !config.ValidMode(o.Mode) {
		return o, errors.New("Routing mode must be Smart, Global or Direct.")
	}
	if o.Tier == "" {
		o.Tier = failover.Auto
	}
	if !validTier(o.Tier, o.Profile.CDN != "") {
		return o, errors.New("That route is not available for this profile.")
	}
	if o.Listen == "" {
		o.Listen = config.DefaultListen
	}
	if o.LogLevel == "" {
		o.LogLevel = "warn"
	}
	if limit := c.settings.MaxRules; limit > 0 && len(o.Rules) > limit {
		return o, fmt.Errorf("Too many rules (%d at most).", limit)
	}
	o.Rules = slices.Clone(o.Rules)
	o.TestHosts = maps.Clone(o.TestHosts)
	return o, nil
}

func validTier(tier failover.Tier, cdn bool) bool {
	return tier == failover.Auto || slices.Contains(failover.Available(cdn), tier)
}

func displayedTier(o Options) string {
	if !o.UsesProxy() {
		return config.Direct
	}
	if o.Tier == failover.Auto {
		return string(failover.Fast)
	}
	return string(o.Tier)
}

func routeName(tier string) string {
	if tier == "" {
		return ""
	}
	return strings.ToUpper(tier[:1]) + tier[1:]
}

// Start starts the engine, or replaces a running one. It returns once the
// listener is up.
func (c *Controller) Start(opts Options) error {
	return c.StartWithReady(opts, nil)
}

// StartWithReady calls ready after the engine is up, before probes or rebuilds
// can start. If ready returns an error, the engine is closed. The callback
// must not call lifecycle methods.
func (c *Controller) StartWithReady(opts Options, ready func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	opts, err := c.normalize(opts)
	if err != nil {
		return err
	}
	if err := c.protectReplacement(); err != nil {
		return err
	}
	hadSession := c.current != nil
	c.ready = ready
	c.closeCurrent()
	c.stateMu.Lock()
	c.status = Status{State: StateOff, Guarded: c.tunGuard != nil, Routes: map[string]RouteLatency{}}
	c.stateMu.Unlock()
	now := time.Now()
	err = c.launch(opts, &now, 0, 0, "", ready)
	if err != nil && (hadSession || c.tunGuard != nil) {
		return c.failedRebuild(err, nil)
	}
	return err
}

// launch builds and starts a session. Callers hold c.mu and have closed any
// previous session.
func (c *Controller) launch(opts Options, since *time.Time, up, down int64, previousTier string, ready func() error) error {
	c.stateMu.Lock()
	c.owner = nil
	c.status.State = StateConnecting
	c.status.Profile, c.status.Server = opts.Profile.Name, opts.Profile.Host
	c.status.Relay = ""
	c.status.Mode, c.status.TierPreference = opts.Mode, string(opts.Tier)
	c.status.Tier, c.status.RescueAvailable = "", opts.Profile.CDN != ""
	c.status.IPv6Available = nil
	c.status.TUNIPv6 = false
	c.status.Listen = opts.Listen
	if opts.TUN && opts.TUNOnly {
		c.status.Listen = ""
	}
	c.status.LatencyMs, c.status.LastError = nil, ""
	c.status.Routes = map[string]RouteLatency{}
	c.stateMu.Unlock()
	s, err := c.build(opts)
	if err != nil {
		return c.fail(opts, err)
	}
	if ready != nil {
		if err := ready(); err != nil {
			err = errors.Join(err, s.close())
			c.fail(opts, err)
			return err
		}
	}
	if err := c.releaseTUNGuard(); err != nil {
		c.event(logring.Warn, "Could not clean up TUN protection: %s", err)
	}
	s.up.Store(up)
	s.down.Store(down)
	c.current = s
	c.stateMu.Lock()
	c.owner = s
	c.status.State = StateOn
	c.status.Relay = s.relayHost
	tier := displayedTier(opts)
	c.status.Tier = tier
	c.status.ConnectedSince = since
	netIPv6 := s.netIPv6
	c.status.IPv6Available = &netIPv6
	c.status.TUNIPv6 = opts.TUN
	c.stateMu.Unlock()
	c.reportTier(previousTier, tier)
	c.resumeAuto(s)
	s.reportDone = make(chan struct{})
	go c.report(s, up, down)
	go c.watchIPv6(s)
	if !c.settings.SkipConnectProbe && s.begin() {
		go func() {
			defer s.work.Done()
			c.connectProbe(s)
		}()
	}
	return nil
}

// build configures both TUN address families so newly acquired IPv6 cannot
// bypass an active IPv4 session while the interface monitor catches up.
func (c *Controller) build(opts Options) (*session, error) {
	netIPv6 := c.checkIPv6()
	return c.buildFor(opts, netIPv6)
}

func (c *Controller) buildFor(opts Options, netIPv6 bool) (*session, error) {
	useIPv6 := opts.IPv6 && netIPv6
	client := config.ClientOptions{
		Preferences: config.Preferences{Mode: opts.Mode, IPv6: useIPv6, Rules: opts.Rules, TUN: opts.TUN},
		Relay:       opts.Relay,
		Listen:      opts.Listen, Tier: opts.Tier, LogLevel: opts.LogLevel, SystemProxy: opts.SystemProxy,
		TUNListen: !opts.TUNOnly, TUNIPv6: opts.TUN,
		TestCAFile: opts.TestCAFile, TestAddress: opts.TestAddress, TestHosts: opts.TestHosts,
	}
	if opts.Profile.Host != "" {
		client.Profile = &opts.Profile
	}
	if opts.TUN && runtime.GOOS == "darwin" {
		client.LANDNSServers = c.landDNSServers
	}
	if opts.Mode == config.Direct && !opts.RulesInDirect {
		client.Rules = nil
	}
	compiled, err := config.BuildClient(client)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{opts: opts, relayHost: compiled.Relay.Host, netIPv6: netIPv6, ctx: ctx, cancel: cancel}
	s.tier.Store(opts.Tier)
	compiled.FakeIP = c.fakeIP
	compiled.LogWriter = c.settings.Logs.Writer()
	if c.settings.EngineLogOutput != nil {
		compiled.LogWriter = logring.NewPrinter(c.settings.EngineLogOutput, opts.LogLevel)
	}
	compiled.CountBytes = func(up, down int64) {
		s.up.Add(up)
		s.down.Add(down)
	}
	compiled.CountProxyBytes = func(up, down int64) {
		s.proxyUp.Add(up)
		s.proxyDown.Add(down)
	}
	compiled.ObserveTraffic = func() {
		if ctl := s.controller.Load(); ctl != nil {
			ctl.ObserveTraffic()
		}
	}
	compiled.ObserveFastDial = func(err error) {
		if ctl := s.controller.Load(); ctl != nil {
			ctl.ObserveFastDial(err)
		}
	}
	compiled.ObserveFastStall = func() {
		if ctl := s.controller.Load(); ctl != nil {
			ctl.SuspectFastStall()
		}
	}
	instance, err := c.newEngine(ctx, compiled)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("configure client engine: %w", err)
	}
	s.engine = instance
	if err := c.enableAuto(s); err != nil {
		_ = s.close()
		return nil, err
	}
	if err := instance.Start(); err != nil {
		_ = s.close()
		return nil, fmt.Errorf("start client engine: %w", err)
	}
	s.unregister = instance.OnNetworkChange(func() {
		if ctl := s.controller.Load(); ctl != nil {
			ctl.Reset()
		}
		if c.networkIPv6() != s.netIPv6 {
			go c.followIPv6(s)
		}
	})
	return s, nil
}

// checkIPv6 reports whether the network has IPv6 and logs when that changes.
// Callers hold c.mu.
func (c *Controller) checkIPv6() bool {
	has := c.networkIPv6()
	seen := int8(-1)
	if has {
		seen = 1
	}
	if seen != c.ipv6Seen {
		if !has {
			c.event(logring.Info, "This network has no IPv6; Pipe uses IPv4.")
		} else if c.ipv6Seen != 0 {
			c.event(logring.Info, "This network has IPv6 again.")
		}
		c.ipv6Seen = seen
	}
	return has
}

// watchIPv6 re-checks the network every ipv6Every until s closes. Network
// callbacks follow the default interface only, so IPv6 can appear unnoticed
// on another one; the check reads local state and sends nothing.
func (c *Controller) watchIPv6(s *session) {
	watchIPv6(s.ctx, c.ipv6Every, s.netIPv6, c.networkIPv6, func(bool) { c.followIPv6(s) })
}

func watchIPv6(ctx context.Context, every time.Duration, initial bool, networkIPv6 func() bool, changed func(bool)) {
	if every <= 0 {
		every = IPv6WatchInterval
	}
	if networkIPv6 == nil || changed == nil {
		return
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	previous := initial
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := networkIPv6()
			if current != previous {
				previous = current
				if ctx.Err() == nil {
					changed(current)
				}
			}
		}
	}
}

// followIPv6 rebuilds s when the network gained or lost IPv6 since s was built.
func (c *Controller) followIPv6(s *session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == s && c.networkIPv6() != s.netIPv6 {
		next := s.current()
		var ready func() error
		if next.TUN {
			ready = c.ready
		}
		_ = c.replace(next, ready)
	}
}

func (s *session) close() error {
	s.life.Lock()
	s.closing = true
	s.life.Unlock()
	s.cancel()
	s.work.Wait()
	s.pauseAuto()
	s.controller.Store(nil)
	if s.unregister != nil {
		s.unregister()
	}
	if s.reportDone != nil {
		<-s.reportDone
	}
	return s.engine.Close()
}

// closeCurrent stops the running session without touching the status.
func (c *Controller) closeCurrent() {
	if s := c.current; s != nil {
		c.current = nil
		c.stateMu.Lock()
		c.owner = nil
		c.status.ProxyUpRate, c.status.ProxyDownRate = 0, 0
		c.stateMu.Unlock()
		_ = s.close()
	}
}

func (c *Controller) fail(opts Options, err error) error {
	if !c.settings.RawErrors {
		err = errors.New(friendly(err, opts))
	}
	message := err.Error()
	c.stateMu.Lock()
	c.status.State, c.status.LastError = StateError, message
	c.status.Tier, c.status.ConnectedSince = "", nil
	c.stateMu.Unlock()
	c.event(logring.Error, "Could not connect: %s", message)
	return err
}

// friendly maps engine errors to short messages that name no addresses.
func friendly(err error, opts Options) string {
	text := strings.ToLower(err.Error())
	switch {
	case opts.TUN && (strings.Contains(text, "tun") || strings.Contains(text, "utun") || strings.Contains(text, "wintun")) &&
		!strings.Contains(text, "address already in use"):
		return "Pipe Helper couldn't create the TUN device. Another VPN may be using it."
	case strings.Contains(text, "address already in use") || strings.Contains(text, "only one usage of each socket"):
		return fmt.Sprintf("The local port %s is already in use. Choose another port in Settings.", portOf(opts.Listen))
	case strings.Contains(text, "permission denied") || strings.Contains(text, "access permissions"):
		return "Pipe is not allowed to use that local port. Choose another port in Settings."
	case strings.Contains(text, "loopback"):
		return "The local address must be 127.0.0.1 with a port."
	case strings.Contains(text, "tier") && strings.Contains(text, "unavailable"):
		return "That route is not available for this profile."
	case strings.Contains(text, "configure client engine"):
		return "The profile could not be loaded. Check the profile and try again."
	}
	return "Pipe could not start the connection."
}

func portOf(listen string) string {
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		return listen[i+1:]
	}
	return listen
}

// Stop disconnects. It is safe to call when already off.
func (c *Controller) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ready = nil
	if c.current == nil {
		c.stateMu.Lock()
		if c.status.State == StateError {
			c.status.State, c.status.LastError = StateOff, ""
			c.status.Relay = ""
			c.status.TUNIPv6 = false
		}
		c.stateMu.Unlock()
		err := c.releaseTUNGuard()
		if err != nil && !c.settings.RawErrors {
			return errors.New("Pipe stopped, but TUN protection reported a cleanup error.")
		}
		return err
	}
	s := c.current
	c.current = nil
	c.stateMu.Lock()
	c.owner = nil
	up, down := s.up.Load(), s.down.Load()
	c.status.State, c.status.Tier, c.status.LastError = StateOff, "", ""
	c.status.Relay = ""
	c.status.UpBytes, c.status.DownBytes = up, down
	c.status.UpRate, c.status.DownRate = 0, 0
	c.status.ProxyUpRate, c.status.ProxyDownRate = 0, 0
	c.status.ConnectedSince, c.status.LatencyMs, c.status.IPv6Available = nil, nil, nil
	c.status.TUNIPv6 = false
	c.status.Routes = map[string]RouteLatency{}
	c.stateMu.Unlock()
	err := errors.Join(s.close(), c.releaseTUNGuard())
	c.event(logring.Info, "Disconnected")
	if err != nil && !c.settings.RawErrors {
		return errors.New("Pipe stopped, but shutdown reported an error.")
	}
	return err
}

// SetMode switches routing mode live by rebuilding the engine. When off it
// only validates; the caller passes the mode to the next Start.
func (c *Controller) SetMode(mode string) error {
	if !config.ValidMode(mode) {
		return errors.New("Routing mode must be Smart, Global or Direct.")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == nil || c.current.opts.Mode == mode {
		return nil
	}
	next := c.current.current()
	next.Mode = mode
	var ready func() error
	if next.TUN {
		ready = c.ready
	}
	return c.replace(next, ready)
}

// SetTier switches the route preference. The engine is not rebuilt. When off
// it only validates.
func (c *Controller) SetTier(tier string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := failover.Tier(tier)
	s := c.current
	if s == nil {
		return nil
	}
	if !validTier(t, s.opts.Profile.CDN != "") || tier == "" {
		return errors.New("That route is not available for this profile.")
	}
	return c.setTier(s, t)
}

func (c *Controller) setTier(s *session, tier failover.Tier) error {
	if tier == s.current().Tier {
		return nil
	}
	s.pauseAuto()
	s.controller.Store(nil)
	next := s.current()
	next.Tier = tier
	selected := displayedTier(next)
	if next.UsesProxy() {
		if err := s.engine.SelectTier(selected); err != nil {
			_ = c.enableAuto(s)
			c.resumeAuto(s)
			return errors.New("Could not switch route.")
		}
	}
	previous := c.activeTier()
	s.tier.Store(tier)
	c.update(s, func(st *Status) {
		st.TierPreference = string(tier)
		st.Tier = selected
		st.LastError = ""
		st.LatencyMs = latencyFor(st.Routes, selected)
	})
	c.reportTier(previous, selected)
	if previous != selected && next.UsesProxy() {
		c.event(logring.Info, "Route switched: %s → %s (you chose it)", routeName(previous), routeName(selected))
	}
	err := c.enableAuto(s)
	c.resumeAuto(s)
	return err
}

func (c *Controller) activeTier() string {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.status.Tier
}

func latencyFor(routes map[string]RouteLatency, tier string) *int64 {
	if r, ok := routes[tier]; ok && r.OK {
		ms := r.Ms
		return &ms
	}
	return nil
}

// Apply re-applies options to the running session: rules, IPv6, listen
// address, log level, mode and route. Nothing happens when off.
func (c *Controller) Apply(opts Options) error {
	return c.ApplyWithReady(opts, nil)
}

// ApplyWithReady checks readiness before releasing protection on a rebuild or
// rollback. The callback must not call lifecycle methods.
func (c *Controller) ApplyWithReady(opts Options, ready func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.current
	if s == nil {
		return nil
	}
	if ready == nil && opts.TUN {
		ready = c.ready
	} else if ready != nil {
		c.ready = ready
	}
	opts, err := c.normalize(opts)
	if err != nil {
		return err
	}
	old := s.current()
	if opts.Profile != old.Profile || opts.Relay != old.Relay ||
		opts.Mode != old.Mode || opts.IPv6 != old.IPv6 || opts.Listen != old.Listen ||
		opts.LogLevel != old.LogLevel || !slices.Equal(opts.Rules, old.Rules) ||
		opts.TUN != old.TUN || opts.TUNOnly != old.TUNOnly || opts.SystemProxy != old.SystemProxy ||
		opts.RulesInDirect != old.RulesInDirect || opts.TestCAFile != old.TestCAFile ||
		opts.TestAddress != old.TestAddress || !maps.Equal(opts.TestHosts, old.TestHosts) {
		return c.replace(opts, ready)
	}
	if err := c.setTier(s, opts.Tier); err != nil {
		return err
	}
	if ready != nil {
		return ready()
	}
	return nil
}

// replace rebuilds the session, keeping the byte totals and connect time. If
// the new session fails it tries to bring the previous one back.
func (c *Controller) replace(next Options, ready func() error) error {
	previous := c.current
	prevOpts := previous.current()
	if err := c.protectReplacement(); err != nil {
		return err
	}
	c.stateMu.Lock()
	since := c.status.ConnectedSince
	c.stateMu.Unlock()
	up, down := previous.up.Load(), previous.down.Load()
	c.closeCurrent()
	tier := c.activeTier()
	err := c.launch(next, since, up, down, tier, ready)
	if err == nil {
		return nil
	}
	failure := c.Status().LastError
	if rollback := c.launch(prevOpts, since, up, down, tier, ready); rollback != nil {
		return c.failedRebuild(err, rollback)
	}
	c.update(c.current, func(st *Status) { st.LastError = failure })
	return err
}

func (c *Controller) protectReplacement() error {
	if c.current == nil || !c.current.opts.TUN || c.tunGuard != nil {
		return nil
	}
	releaseDNS := sysdns.HoldRestore()
	guard, err := c.startTUNGuard()
	if err != nil {
		releaseDNS()
		message := "Pipe couldn't protect traffic during the TUN rebuild."
		if c.settings.RawErrors {
			err = fmt.Errorf("%s %w", message, err)
		} else {
			err = errors.New(message)
		}
		c.update(c.current, func(st *Status) { st.LastError = err.Error() })
		return err
	}
	c.tunGuard, c.releaseDNS = guard, releaseDNS
	c.stateMu.Lock()
	c.status.Guarded = true
	c.stateMu.Unlock()
	return nil
}

func (c *Controller) releaseTUNGuard() error {
	if c.tunGuard == nil {
		return nil
	}
	err := c.tunGuard.Close()
	c.tunGuard = nil
	c.releaseDNS()
	c.releaseDNS = nil
	c.stateMu.Lock()
	c.status.Guarded = false
	c.stateMu.Unlock()
	return err
}

func (c *Controller) failedRebuild(err, rollback error) error {
	if c.tunGuard == nil {
		c.notifyStopped()
		return err
	}
	message := "Pipe couldn't restore the TUN connection. Network traffic is paused. Reconnect or disconnect to continue."
	if c.settings.RawErrors {
		err = fmt.Errorf("%s %w", message, errors.Join(err, rollback))
	} else {
		err = errors.New(message)
	}
	c.stateMu.Lock()
	c.status.LastError = err.Error()
	c.status.UpRate, c.status.DownRate = 0, 0
	c.status.TUNIPv6 = true
	c.stateMu.Unlock()
	c.event(logring.Error, "%s", err)
	return err
}

func (c *Controller) enableAuto(s *session) error {
	if s.current().Tier != failover.Auto || !s.opts.UsesProxy() {
		return nil
	}
	var extraProbeTime time.Duration
	if s.opts.Relay != "" {
		extraProbeTime = engine.RelayFallbackDelay
	}
	ctl, err := failover.New(failover.Options{
		Tiers:          failover.Available(s.opts.Profile.CDN != ""),
		ExtraProbeTime: extraProbeTime,
		Probe: func(ctx context.Context, tier failover.Tier, burst bool) (bool, error) {
			stalled, latency, via, err := s.engine.ProbeLatency(ctx, string(tier), burst)
			if !burst {
				c.recordRoute(s, string(tier), routeLatency(latency, err == nil && !stalled, via))
			}
			return stalled, err
		},
		Select: func(tier failover.Tier) error {
			if err := s.engine.SelectTier(string(tier)); err != nil {
				return err
			}
			c.switched(s, string(tier))
			return nil
		},
	})
	if err != nil {
		return errors.New("Automatic route switching could not start.")
	}
	s.controller.Store(ctl)
	return nil
}

func (c *Controller) switched(s *session, tier string) {
	var from string
	c.update(s, func(st *Status) {
		from = st.Tier
		st.Tier = tier
		st.LatencyMs = latencyFor(st.Routes, tier)
	})
	if from == "" || from == tier {
		return
	}
	c.reportTier(from, tier)
	reason := routeName(from) + " stopped answering"
	if order(tier) < order(from) {
		reason = routeName(tier) + " is answering again"
	}
	c.event(logring.Info, "Route switched: %s → %s (%s)", routeName(from), routeName(tier), reason)
}

func order(tier string) int {
	return slices.Index([]string{"fast", "stealth", "rescue"}, tier)
}

func (c *Controller) recordRoute(s *session, tier string, entry RouteLatency) {
	c.update(s, func(st *Status) {
		st.Routes[tier] = entry
		if tier == st.Tier {
			st.LatencyMs = latencyFor(st.Routes, tier)
		}
	})
}

func (c *Controller) resumeAuto(s *session) {
	ctl := s.controller.Load()
	if ctl == nil || s.stopAuto != nil {
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	done := make(chan struct{})
	s.stopAuto, s.autoDone = cancel, done
	go func() {
		defer close(done)
		if err := ctl.Run(ctx); err != nil && ctx.Err() == nil {
			c.update(s, func(st *Status) { st.LastError = "Could not switch route automatically." })
			c.event(logring.Warn, "Could not switch route automatically.")
			if c.settings.OnFailoverError != nil {
				c.settings.OnFailoverError(err)
			}
		}
	}()
}

func (s *session) pauseAuto() {
	if s.stopAuto != nil {
		s.stopAuto()
		<-s.autoDone
		s.stopAuto = nil
	}
}

// connectProbe measures the active route once after connecting.
func (c *Controller) connectProbe(s *session) {
	name := s.opts.Profile.Name
	if name == "" {
		name = "server"
	}
	if !s.opts.UsesProxy() {
		c.event(logring.Info, "Connected (direct mode, no route in use)")
		return
	}
	tier := displayedTier(s.current())
	ctx, cancel := context.WithTimeout(s.ctx, probeTimeout)
	defer cancel()
	stalled, latency, via, err := s.engine.ProbeLatency(ctx, tier, false)
	if s.ctx.Err() != nil {
		return
	}
	entry := routeLatency(latency, err == nil && !stalled, via)
	c.recordRoute(s, tier, entry)
	if entry.OK {
		c.event(logring.Info, "Connected to %s via %s (%d ms)", name, routeName(tier), entry.Ms)
		return
	}
	c.event(logring.Info, "Connected to %s via %s (no reply from the server yet)", name, routeName(tier))
}

// TestRoutes probes each available route once and records the result in the
// status. It returns an empty map when not connected.
func (c *Controller) TestRoutes(ctx context.Context) map[string]RouteLatency {
	c.stateMu.Lock()
	s := c.owner
	c.stateMu.Unlock()
	if s == nil || !s.opts.UsesProxy() || !s.begin() {
		return map[string]RouteLatency{}
	}
	defer s.work.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	return probeRoutes(ctx, s.engine, failover.Available(s.opts.Profile.CDN != ""), probeTimeout, func(tier string, entry RouteLatency) {
		c.recordRoute(s, tier, entry)
	})
}

// report publishes byte totals, rates and relay status once a second.
func (c *Controller) report(s *session, up, down int64) {
	defer close(s.reportDone)
	last := time.Now()
	var proxyUp, proxyDown int64
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			newProxyUp, newProxyDown := s.proxyUp.Load(), s.proxyDown.Load()
			newUp, newDown := s.up.Load(), s.down.Load()
			if seconds := now.Sub(last).Seconds(); seconds > 0 {
				var relay, relayState string
				c.update(s, func(st *Status) {
					st.UpBytes, st.DownBytes = newUp, newDown
					st.UpRate = int64(float64(newUp-up) / seconds)
					st.DownRate = int64(float64(newDown-down) / seconds)
					st.ProxyUpRate = int64(float64(newProxyUp-proxyUp) / seconds)
					st.ProxyDownRate = int64(float64(newProxyDown-proxyDown) / seconds)
					if c.settings.OnRelayStatus != nil && st.Relay != "" {
						relay, relayState = st.Relay, s.engine.RelayState(st.Tier)
					}
				})
				if relay != "" {
					c.settings.OnRelayStatus(relay, relayState)
				}
				up, down, last = newUp, newDown, now
				proxyUp, proxyDown = newProxyUp, newProxyDown
			}
		}
	}
}
