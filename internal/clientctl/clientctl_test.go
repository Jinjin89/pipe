// SPDX-License-Identifier: GPL-3.0-or-later

package clientctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/log"

	"pipe/internal/config"
	"pipe/internal/engine"
	"pipe/internal/failover"
	"pipe/internal/link"
	"pipe/internal/logring"
	"pipe/internal/sysdns"
)

type fakeEngine struct {
	mu          sync.Mutex
	options     engine.Options
	startErr    error
	closeErr    error
	selectErr   error
	started     atomic.Bool
	closed      atomic.Bool
	selected    []string
	relayStates map[string]string
	viaRelay    map[string]bool
	uplink      string
	probeBudget chan time.Duration
	latency     map[string]time.Duration
	failTier    map[string]bool
	block       bool // ProbeLatency waits for ctx
	inProbe     atomic.Int32
	resets      func()
}

func (e *fakeEngine) Start() error {
	e.started.Store(e.startErr == nil)
	return e.startErr
}
func (e *fakeEngine) Close() error {
	e.closed.Store(true)
	return e.closeErr
}
func (e *fakeEngine) SelectTier(t string) error {
	if e.selectErr != nil {
		return e.selectErr
	}
	e.mu.Lock()
	e.selected = append(e.selected, t)
	e.mu.Unlock()
	return nil
}
func (e *fakeEngine) RelayState(tag string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.relayStates[tag]
}
func (e *fakeEngine) DefaultInterface() string { return e.uplink }
func (e *fakeEngine) ProbeLatency(ctx context.Context, tier string, _ bool) (bool, time.Duration, bool, error) {
	if e.probeBudget != nil {
		deadline, _ := ctx.Deadline()
		select {
		case e.probeBudget <- time.Until(deadline):
		default:
		}
	}
	if e.block {
		e.inProbe.Add(1)
		<-ctx.Done()
		if e.closed.Load() {
			panic("probe outlived engine.Close")
		}
		return false, 0, false, ctx.Err()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failTier[tier] {
		return false, 0, e.viaRelay[tier], errors.New("unreachable")
	}
	return false, e.latency[tier], e.viaRelay[tier], nil
}
func (e *fakeEngine) OnNetworkChange(reset func()) func() { e.resets = reset; return func() {} }

type harness struct {
	c       *Controller
	logs    *logring.Ring
	mu      sync.Mutex
	engines []*fakeEngine
	next    func(*fakeEngine)
	err     error
}

func newHarness() *harness {
	h := &harness{logs: logring.New(100)}
	h.c = New(h.logs)
	h.c.startTUNGuard = func() (io.Closer, error) { return testGuard(func() error { return nil }), nil }
	h.c.newEngine = func(_ context.Context, o engine.Options) (engineAPI, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.err != nil {
			return nil, h.err
		}
		e := &fakeEngine{options: o, latency: map[string]time.Duration{
			"fast": 42 * time.Millisecond, "stealth": 90 * time.Millisecond, "rescue": 200 * time.Millisecond,
		}}
		if h.next != nil {
			h.next(e)
		}
		h.engines = append(h.engines, e)
		return e, nil
	}
	return h
}

func (h *harness) engineCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.engines)
}

func (h *harness) engine(i int) *fakeEngine {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.engines[i]
}

func opts() Options {
	return Options{Profile: link.Profile{Name: "phone", Host: "origin.example", CDN: "cdn.example"}, IPv6: true}
}

func (h *harness) messages() string {
	entries, _ := h.logs.Since(0, 0)
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Message + "\n")
	}
	return b.String()
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestControllerRelayThroughRebuilds(t *testing.T) {
	const host = "relay.example"
	h := newHarness()
	var network atomic.Bool
	h.c.networkIPv6 = network.Load
	h.next = func(e *fakeEngine) { e.relayStates = map[string]string{"stealth": "via"} }
	o := opts()
	o.Relay, o.Tier = host+":8444", failover.Stealth
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	defer h.c.Stop()
	checkRelay := func(index int, port uint16) {
		t.Helper()
		if got := h.engine(index).options.Relay; got.Host != host || got.StealthPort != port {
			t.Fatalf("engine %d relay %+v, want host %q and port %d", index, got, host, port)
		}
		if st := h.c.Status(); st.Relay != host || st.RelayState != "via" {
			t.Fatalf("relay status %+v", st)
		}
	}
	checkRelay(0, 8444)

	network.Store(true)
	h.engine(0).resets()
	waitFor(t, "IPv6 rebuild", func() bool {
		st := h.c.Status()
		return h.engineCount() == 2 && st.IPv6Available != nil && *st.IPv6Available
	})
	checkRelay(1, 8444)

	o.Relay = host + ":8445"
	if err := h.c.Apply(o); err != nil || h.engineCount() != 3 || !h.engine(1).closed.Load() {
		t.Fatalf("relay change did not restart: %v", err)
	}
	checkRelay(2, 8445)
	if err := h.c.SetTier("rescue"); err != nil {
		t.Fatal(err)
	}
	if st := h.c.Status(); st.Tier != "rescue" || st.Relay != host || st.RelayState != "" {
		t.Fatalf("status after selecting an unrelayed tier: %+v", st)
	}

	o.Relay, o.Tier = "", failover.Stealth
	if err := h.c.Apply(o); err != nil || h.engineCount() != 4 {
		t.Fatalf("turning off the relay did not restart: %v", err)
	}
	if st := h.c.Status(); st.Relay != "" || st.RelayState != "" || h.engine(3).options.Relay.Host != "" {
		t.Fatalf("status with relay off: %+v", st)
	}
}

func TestControllerReportsRelayStatus(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const host = "2001:db8::9"
		h := newHarness()
		h.c.networkIPv6 = func() bool { return false }
		h.c.settings.SkipConnectProbe = true
		o := opts()
		o.Relay, o.Tier = "["+host+"]:8444", failover.Stealth
		h.next = func(e *fakeEngine) { e.relayStates = map[string]string{"stealth": "pending"} }
		type report struct{ host, state string }
		reports := make(chan report, 1)
		h.c.settings.OnRelayStatus = func(host, state string) {
			select {
			case reports <- report{host, state}:
			default:
			}
		}
		if err := h.c.Start(o); err != nil {
			t.Fatal(err)
		}
		defer h.c.Stop()
		check := func(want string) {
			t.Helper()
			if st := h.c.Status(); st.Relay != host || st.RelayState != want {
				t.Fatalf("relay status %+v, want %q", st, want)
			}
			select {
			case got := <-reports:
				if got != (report{host, want}) {
					t.Fatalf("reported %+v, want %q", got, want)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("missing relay status update")
			}
		}
		if body, err := json.Marshal(h.c.Status()); err != nil || !strings.Contains(string(body), `"relayState":"pending"`) {
			t.Fatalf("relay status JSON %s: %v", body, err)
		}
		check("pending")
		e := h.engine(0)
		for _, state := range []string{"via", "direct", "pending"} {
			e.mu.Lock()
			e.relayStates["stealth"] = state
			e.mu.Unlock()
			check(state)
		}
		if err := h.c.SetTier("rescue"); err != nil {
			t.Fatal(err)
		}
		check("")
		if err := h.c.Stop(); err != nil {
			t.Fatal(err)
		}
		if st := h.c.Status(); st.Relay != "" || st.RelayState != "" {
			t.Fatalf("relay status after stop: %+v", st)
		}
	})
}

func TestControllerRelayAddsProbeTime(t *testing.T) {
	for _, tc := range []struct {
		name, relay string
		wantExtra   time.Duration
	}{
		{"no relay", "", 0},
		{"with relay", "relay.example", engine.RelayFallbackDelay},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newHarness()
				h.c.networkIPv6 = func() bool { return false }
				h.c.settings.SkipConnectProbe = true
				budgets := make(chan time.Duration, 1)
				h.next = func(e *fakeEngine) { e.probeBudget = budgets }
				o := opts()
				o.Relay = tc.relay
				if err := h.c.Start(o); err != nil {
					t.Fatal(err)
				}
				defer h.c.Stop()
				h.engine(0).options.ObserveTraffic()
				select {
				case got := <-budgets:
					if want := 1800*time.Millisecond + tc.wantExtra; got != want {
						t.Fatalf("probe budget %v, want %v", got, want)
					}
				case <-time.After(time.Second):
					t.Fatal("missing failover probe")
				}
			})
		})
	}
}

func TestStartStopLifecycle(t *testing.T) {
	h := newHarness()
	if st := h.c.Status(); st.State != "off" || st.Routes == nil {
		t.Fatalf("initial %+v", st)
	}
	if err := h.c.Start(opts()); err != nil {
		t.Fatal(err)
	}
	st := h.c.Status()
	if st.State != "on" || st.Profile != "phone" || st.Server != "origin.example" || st.Mode != "smart" ||
		st.TierPreference != "auto" || st.Tier != "fast" || !st.RescueAvailable || st.Listen != config.DefaultListen || st.ConnectedSince == nil {
		t.Fatalf("status %+v", st)
	}
	if h.engines[0].options.VPN != nil {
		t.Fatal("desktop engine must not use a VPN platform")
	}
	if h.engines[0].options.LogWriter == nil || h.engines[0].options.CountBytes == nil {
		t.Fatal("log writer and byte counter must be wired")
	}
	waitFor(t, "connect probe", func() bool { st := h.c.Status(); return st.LatencyMs != nil })
	if ms := *h.c.Status().LatencyMs; ms != 42 {
		t.Fatalf("latency %d", ms)
	}
	waitFor(t, "connect log", func() bool { return strings.Contains(h.messages(), "Connected to phone via Fast (42 ms)") })
	if err := h.c.Stop(); err != nil {
		t.Fatal(err)
	}
	st = h.c.Status()
	if st.State != "off" || st.Tier != "" || st.ConnectedSince != nil || !h.engines[0].closed.Load() {
		t.Fatalf("after stop %+v", st)
	}
	if !strings.Contains(h.messages(), "Disconnected") {
		t.Fatal("missing Disconnected event")
	}
	if err := h.c.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestWatchIPv6ReportsChangesAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var available atomic.Bool
	available.Store(true)
	changes := make(chan bool, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchIPv6(ctx, 5*time.Millisecond, false, available.Load, func(value bool) { changes <- value })
	}()
	select {
	case got := <-changes:
		if !got {
			t.Fatal("expected IPv6 to appear")
		}
	case <-time.After(time.Second):
		t.Fatal("IPv6 change was not reported")
	}
	available.Store(false)
	select {
	case got := <-changes:
		if got {
			t.Fatal("expected IPv6 to disappear")
		}
	case <-time.After(time.Second):
		t.Fatal("IPv6 removal was not reported")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watcher did not stop with its context")
	}
}

func TestBytesAndRates(t *testing.T) {
	h := newHarness()
	if err := h.c.Start(opts()); err != nil {
		t.Fatal(err)
	}
	count := h.engines[0].options.CountBytes
	count(1000, 0)
	count(0, 5000)
	waitFor(t, "rates", func() bool {
		st := h.c.Status()
		return st.UpBytes == 1000 && st.DownBytes == 5000 && st.UpRate > 0 && st.DownRate > 0
	})
	h.c.Stop()
	if st := h.c.Status(); st.UpBytes != 1000 || st.DownRate != 0 {
		t.Fatalf("after stop %+v", st)
	}
}

func TestProxyRatesAcrossSessionChanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness()
		h.c.networkIPv6 = func() bool { return false }
		h.c.settings.SkipConnectProbe = true
		h.next = func(e *fakeEngine) { e.uplink = "uplink0" }
		o := opts()
		o.Tier = failover.Fast
		if err := h.c.Start(o); err != nil {
			t.Fatal(err)
		}
		defer h.c.Stop()
		if got := h.c.DefaultInterface(); got != "uplink0" {
			t.Fatalf("active uplink %q, want uplink0", got)
		}
		tick := func() {
			synctest.Wait()
			time.Sleep(time.Second)
			synctest.Wait()
		}
		live := h.engine(0).options
		live.CountBytes(1_000, 5_000)
		live.CountProxyBytes(200, 300)
		tick()
		if st := h.c.Status(); st.UpRate != 1_000 || st.DownRate != 5_000 || st.ProxyUpRate != 200 || st.ProxyDownRate != 300 {
			t.Fatalf("unexpected byte rates %+v", st)
		}
		o.Mode = config.Global
		if err := h.c.Apply(o); err != nil {
			t.Fatal(err)
		}
		if st := h.c.Status(); st.ProxyUpRate != 0 || st.ProxyDownRate != 0 {
			t.Fatalf("proxy rates survived a rebuild: %+v", st)
		}
		live = h.engine(1).options
		live.CountBytes(600, 800)
		tick()
		if st := h.c.Status(); st.UpBytes != 1_600 || st.DownBytes != 5_800 || st.UpRate != 600 || st.DownRate != 800 || st.ProxyUpRate != 0 || st.ProxyDownRate != 0 {
			t.Fatalf("unexpected status after direct-only traffic: %+v", st)
		}
		live.CountBytes(150, 250)
		live.CountProxyBytes(150, 250)
		tick()
		if st := h.c.Status(); st.ProxyUpRate != 150 || st.ProxyDownRate != 250 {
			t.Fatalf("unexpected proxy rates after rebuild: %+v", st)
		}
		if err := h.c.Stop(); err != nil {
			t.Fatal(err)
		}
		if st := h.c.Status(); st.ProxyUpRate != 0 || st.ProxyDownRate != 0 || h.c.DefaultInterface() != "" {
			t.Fatalf("active proxy rates or uplink after stop: %+v", st)
		}
	})
}

func TestStartErrorIsFriendly(t *testing.T) {
	h := newHarness()
	h.next = func(e *fakeEngine) {
		e.startErr = errors.New("start inbound/mixed[mixed-in]: listen tcp 127.0.0.1:7890: bind: address already in use")
	}
	err := h.c.Start(opts())
	if err == nil || !strings.Contains(err.Error(), "port 7890 is already in use") {
		t.Fatalf("error %v", err)
	}
	st := h.c.Status()
	if st.State != "error" || st.LastError != err.Error() || strings.Contains(st.LastError, "127.0.0.1") {
		t.Fatalf("status %+v", st)
	}
	if !h.engines[0].closed.Load() {
		t.Fatal("failed engine must be closed")
	}
	h.next = nil
	if err := h.c.Start(opts()); err != nil || h.c.Status().State != "on" || h.c.Status().LastError != "" {
		t.Fatalf("retry: %v %+v", err, h.c.Status())
	}
}

func TestRawEngineErrors(t *testing.T) {
	h := newHarness()
	h.c.settings.RawErrors = true
	h.c.networkIPv6 = func() bool { return false }
	o := opts()
	o.TUN, o.SystemProxy = true, true
	if err := h.c.Start(o); err == nil || err.Error() != "--tun and --system-proxy are mutually exclusive" {
		t.Fatalf("conflicting flags: %v", err)
	}

	o.SystemProxy = false
	h.next = func(e *fakeEngine) { e.startErr = fmt.Errorf("configure tun interface: %w", os.ErrPermission) }
	err := h.c.Start(o)
	if !errors.Is(err, os.ErrPermission) || !strings.Contains(err.Error(), "configure tun interface") {
		t.Fatalf("TUN startup: %v", err)
	}
	if st := h.c.Status(); st.State != StateError || st.LastError != err.Error() || !h.engine(0).closed.Load() {
		t.Fatalf("TUN startup status: %+v", st)
	}

	failure := errors.New("close TUN failed")
	h.next = func(e *fakeEngine) { e.closeErr = failure }
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	if err := h.c.Stop(); !errors.Is(err, failure) {
		t.Fatalf("TUN shutdown: %v", err)
	}
}

func TestInvalidOptions(t *testing.T) {
	h := newHarness()
	bad := opts()
	bad.Mode = "weird"
	if h.c.Start(bad) == nil {
		t.Fatal("accepted bad mode")
	}
	bad = opts()
	bad.Profile.CDN = ""
	bad.Tier = failover.Rescue
	if h.c.Start(bad) == nil {
		t.Fatal("accepted rescue without CDN")
	}
	if h.c.Status().State != "off" {
		t.Fatalf("state %s", h.c.Status().State)
	}
}

func TestRuleLimitConfigurable(t *testing.T) {
	o := opts()
	o.Rules = make([]config.Rule, 501)
	if _, err := New(nil).normalize(o); err == nil {
		t.Fatal("desktop rule limit was lost")
	}
	if _, err := NewWithSettings(Settings{}).normalize(o); err != nil {
		t.Fatalf("caller-managed rule limit: %v", err)
	}
}

func TestStartWithReadyErrorClosesEngine(t *testing.T) {
	h := newHarness()
	want := errors.New("post-start setup failed")
	err := h.c.StartWithReady(opts(), func() error {
		e := h.engine(0)
		if !e.started.Load() || e.closed.Load() {
			t.Error("ready ran without an open engine")
		}
		if got := h.c.Status().Listen; got != config.DefaultListen {
			t.Errorf("ready sees listen address %q, want %q", got, config.DefaultListen)
		}
		return want
	})
	if !errors.Is(err, want) || h.c.Status().State != StateError || !h.engine(0).closed.Load() {
		t.Fatalf("start returned %v with status %+v", err, h.c.Status())
	}
}

func TestControllerClientOptions(t *testing.T) {
	h := newHarness()
	var out bytes.Buffer
	h.c.settings.EngineLogOutput = &out
	h.c.settings.SkipConnectProbe = true
	h.next = func(e *fakeEngine) { e.block = true }
	o := opts()
	o.LogLevel, o.TestCAFile = "info", "test-ca.pem"
	o.SystemProxy = true
	o.TestAddress = netip.MustParseAddr("10.1.2.3")
	o.TestHosts = map[string]netip.Addr{"test.example": netip.MustParseAddr("192.0.2.1")}
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	defer h.c.Stop()
	e := h.engine(0)
	inbounds := e.options.Config["inbounds"].([]engine.Object)
	if len(inbounds) != 1 || inbounds[0]["type"] != "mixed" || inbounds[0]["set_system_proxy"] != true {
		t.Fatalf("inbounds %+v", inbounds)
	}
	for _, ob := range e.options.Config["outbounds"].([]engine.Object) {
		switch ob["tag"] {
		case "fast", "stealth", "rescue":
			if ob["server"] != o.TestAddress.String() || ob["tls"].(engine.Object)["certificate_path"] != o.TestCAFile {
				t.Errorf("test override lost on %s", ob["tag"])
			}
		}
	}
	e.options.LogWriter.WriteMessage(log.LevelInfo, "INFO[0000] engine started")
	e.options.LogWriter.WriteMessage(log.LevelDebug, "DEBUG[0000] quiet")
	if got := out.String(); got != "info: engine started\n" {
		t.Fatalf("engine log %q", got)
	}
	if err := h.c.Apply(o); err != nil || h.engineCount() != 1 {
		t.Fatalf("equal options rebuilt: %v", err)
	}
	o.TestHosts["test.example"] = netip.MustParseAddr("192.0.2.2")
	if err := h.c.Apply(o); err != nil || h.engineCount() != 2 {
		t.Fatalf("changed test hosts did not rebuild: %v", err)
	}
	for i, want := range []string{"192.0.2.1", "192.0.2.2"} {
		e := h.engine(i)
		servers := e.options.Config["dns"].(engine.Object)["servers"].([]engine.Object)
		found := false
		for _, server := range servers {
			if server["tag"] == engine.TestHostsTag {
				found = server["predefined"].(map[string]netip.Addr)["test.example"].String() == want
			}
		}
		if !found {
			t.Errorf("engine %d lost test host %s", i, want)
		}
	}
	if err := h.c.Stop(); err != nil {
		t.Fatal(err)
	}
	if h.engine(0).inProbe.Load() != 0 || h.engine(1).inProbe.Load() != 0 {
		t.Fatal("ran a connect probe without application traffic")
	}
}

func TestTUNOnlyControlsMixedInbound(t *testing.T) {
	h := newHarness()
	o := opts()
	o.TUN, o.TUNOnly = true, true
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	defer h.c.Stop()
	if in := h.engine(0).options.Config["inbounds"].([]engine.Object); len(in) != 1 || in[0]["type"] != "tun" {
		t.Fatalf("TUN-only inbounds %+v", in)
	}
	o.TUNOnly = false
	if err := h.c.Apply(o); err != nil || h.engineCount() != 2 {
		t.Fatalf("failed to add a mixed inbound: %v", err)
	}
	if in := h.engine(1).options.Config["inbounds"].([]engine.Object); len(in) != 2 || in[1]["type"] != "mixed" {
		t.Fatalf("TUN and mixed inbounds %+v", in)
	}
	o.SystemProxy = true
	if err := h.c.Apply(o); err == nil || h.c.Status().State != StateOn {
		t.Fatalf("TUN plus system proxy: %v, status %+v", err, h.c.Status())
	}
}

func TestSetModeRebuildsAndKeepsTotals(t *testing.T) {
	h := newHarness()
	if err := h.c.Start(opts()); err != nil {
		t.Fatal(err)
	}
	h.engines[0].options.CountBytes(10, 20)
	since := *h.c.Status().ConnectedSince
	if err := h.c.SetMode("global"); err != nil {
		t.Fatal(err)
	}
	if len(h.engines) != 2 || !h.engines[0].closed.Load() {
		t.Fatalf("engines %d", len(h.engines))
	}
	st := h.c.Status()
	if st.Mode != "global" || st.State != "on" || !st.ConnectedSince.Equal(since) {
		t.Fatalf("status %+v", st)
	}
	h.engines[1].options.CountBytes(1, 1)
	waitFor(t, "totals carried", func() bool { st := h.c.Status(); return st.UpBytes == 11 && st.DownBytes == 21 })
	if err := h.c.SetMode("bogus"); err == nil {
		t.Fatal("accepted bogus mode")
	}
	if err := h.c.SetMode("direct"); err != nil {
		t.Fatal(err)
	}
	if st := h.c.Status(); st.Tier != "direct" {
		t.Fatalf("tier %q", st.Tier)
	}
}

func TestSetModeFailureRollsBack(t *testing.T) {
	h := newHarness()
	if err := h.c.Start(opts()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	h.next = func(e *fakeEngine) {
		calls++
		if calls == 1 {
			e.startErr = errors.New("boom")
		}
	}
	if err := h.c.SetMode("global"); err == nil {
		t.Fatal("expected failure")
	}
	st := h.c.Status()
	if st.State != "on" || st.Mode != "smart" || st.LastError == "" {
		t.Fatalf("status %+v", st)
	}
}

func TestOnStoppedRunsWhenReplaceAndRollbackFail(t *testing.T) {
	h := newHarness()
	stopped := make(chan struct{}, 1)
	h.c.SetOnStopped(func() { stopped <- struct{}{} })
	if err := h.c.Start(opts()); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.err = errors.New("engine unavailable")
	h.mu.Unlock()
	if err := h.c.SetMode("global"); err == nil {
		t.Fatal("expected rebuild failure")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("OnStopped was not called")
	}
	if st := h.c.Status(); st.State != StateError || !h.engine(0).closed.Load() {
		t.Fatalf("session was not stopped after failed rollback: %+v", st)
	}
}

type testGuard func() error

func (f testGuard) Close() error { return f() }

type guardDNS struct {
	sysdns.Backend
	server string
}

func (d *guardDNS) Capture() (json.RawMessage, error) { return json.Marshal(d.server) }

func (d *guardDNS) Extend(saved json.RawMessage) (json.RawMessage, error) { return saved, nil }

func (d *guardDNS) Apply(json.RawMessage) error {
	d.server = sysdns.TUNDNSAddress
	return nil
}

func (d *guardDNS) Restore(snapshot json.RawMessage) (json.RawMessage, error) {
	return nil, json.Unmarshal(snapshot, &d.server)
}

func TestTUNReplacementKeepsCaptureAndDNSUntilReadyOrStop(t *testing.T) {
	for _, test := range []struct {
		name string
		fail int
	}{
		{"replacement starts", 0},
		{"rollback starts", 1},
		{"explicit stop after failed rollback", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness()
			dns := &guardDNS{server: "192.168.1.1"}
			manager := sysdns.New(dns, filepath.Join(t.TempDir(), "dns.armed"))
			defer manager.Restore()
			defer h.c.Stop()
			o := opts()
			o.TUN = true
			if err := h.c.StartWithReady(o, manager.Set); err != nil {
				t.Fatal(err)
			}

			guarded, released, stopped := false, false, false
			h.c.SetOnStopped(func() { stopped = true })
			h.c.startTUNGuard = func() (io.Closer, error) {
				if h.engine(0).closed.Load() {
					t.Error("old capture closed before the guard was installed")
				}
				guarded = true
				return testGuard(func() error {
					if test.fail < 2 && !h.engine(test.fail+1).started.Load() {
						t.Error("guard released before capture resumed")
					}
					if err := manager.Restore(); !errors.Is(err, sysdns.ErrTUNProtected) {
						t.Errorf("DNS restore during guard cleanup returned %v", err)
					}
					guarded, released = false, true
					return nil
				}), nil
			}
			var starts int
			h.next = func(e *fakeEngine) {
				if !guarded || !h.engines[0].closed.Load() {
					t.Error("engine rebuild began without a guard covering the old capture")
				}
				if err := manager.Restore(); !errors.Is(err, sysdns.ErrTUNProtected) {
					t.Errorf("DNS restore during rebuild returned %v", err)
				}
				starts++
				if starts <= test.fail {
					e.startErr = errors.New("test engine could not start")
				}
			}
			err := h.c.SetMode(config.Global)
			if (err != nil) != (test.fail != 0) {
				t.Errorf("rebuild error = %v", err)
			}
			if test.fail == 2 {
				status := h.c.Status()
				if released || stopped || !guarded || status.State != StateError || !status.Guarded ||
					!strings.Contains(status.LastError, "Network traffic is paused") {
					t.Errorf("failed rollback lost protection or error state: %v", status)
				}
				if err := manager.Restore(); !errors.Is(err, sysdns.ErrTUNProtected) {
					t.Errorf("failed rollback allowed DNS restoration: %v", err)
				}
			} else if !released || guarded || h.c.Status().State != StateOn || h.c.Status().Guarded {
				t.Error("working capture did not replace the guard")
			}
			if dns.server != "172.19.0.2" {
				t.Errorf("system DNS during rebuild = %q", dns.server)
			}
			if err := h.c.Stop(); err != nil {
				t.Fatal(err)
			}
			if err := manager.Restore(); err != nil {
				t.Fatal(err)
			}
			if guarded || !released || dns.server != "192.168.1.1" || h.c.Status().TUNIPv6 || h.c.Status().Guarded {
				t.Errorf("Stop did not release the guard and restore the original resolver")
			}
		})
	}
}

func TestTUNApplyDNSFailureKeepsGuardUntilReady(t *testing.T) {
	h := newHarness()
	o := opts()
	o.TUN = true
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	defer h.c.Stop()
	o.Mode = config.Global
	var attempts int
	err := h.c.ApplyWithReady(o, func() error {
		attempts++
		if !h.c.Status().Guarded {
			t.Error("DNS readiness ran after releasing the guard")
		}
		return errors.New("DNS setup failed")
	})
	if st := h.c.Status(); err == nil || attempts != 2 || !st.Guarded || st.State != StateError {
		t.Fatalf("failed DNS on apply and rollback: attempts=%d status=%+v error=%v", attempts, st, err)
	}
	if err := h.c.StartWithReady(o, func() error {
		if !h.c.Status().Guarded {
			t.Error("fresh connection released the guard before readiness")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if st := h.c.Status(); st.Guarded || st.State != StateOn {
		t.Fatalf("successful connection left the guard holding capture: %+v", st)
	}
}

func TestUnchangedTUNApplyKeepsEngineOnDNSFailure(t *testing.T) {
	h := newHarness()
	o := opts()
	o.TUN = true
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	defer h.c.Stop()
	dnsErr := errors.New("fixture DNS reapply failed")
	if err := h.c.ApplyWithReady(o, func() error { return dnsErr }); !errors.Is(err, dnsErr) {
		t.Fatalf("unchanged Apply returned %v", err)
	}
	if st := h.c.Status(); st.State != StateOn || st.Guarded || h.engineCount() != 1 || h.engine(0).closed.Load() {
		t.Fatalf("failed reapply changed the active engine: %+v", st)
	}
}

func TestTUNRebuildKeepsLiveEngineWhenGuardCannotStart(t *testing.T) {
	h := newHarness()
	o := opts()
	o.TUN = true
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	defer h.c.Stop()
	h.c.startTUNGuard = func() (io.Closer, error) { return nil, errors.New("no guard routes available") }
	if err := h.c.SetMode(config.Global); err == nil {
		t.Fatal("rebuilt without a guard")
	}
	if h.engine(0).closed.Load() || h.engineCount() != 1 || h.c.Status().State != StateOn {
		t.Fatal("guard failure closed working capture")
	}
}

func TestTUNGuardCapturesBothFamiliesWithMoreSpecificRoutes(t *testing.T) {
	options, err := guardTUNOptions()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		addresses []string
		routes    []netip.Prefix
	}{
		{[]string{"192.0.2.1", sysdns.TUNDNSAddress}, options.Inet4RouteAddress},
		{[]string{"2001:db8::1", "fdfe:dcba:9876::2"}, options.Inet6RouteAddress},
	} {
		for _, raw := range test.addresses {
			addr := netip.MustParseAddr(raw)
			if !slices.ContainsFunc(test.routes, func(route netip.Prefix) bool {
				return route.Bits() > 0 && route.Contains(addr)
			}) {
				t.Errorf("guard has no specific route covering %s", addr)
			}
		}
	}
}

func TestSetTierIsLive(t *testing.T) {
	h := newHarness()
	if err := h.c.Start(opts()); err != nil {
		t.Fatal(err)
	}
	if err := h.c.SetTier("stealth"); err != nil {
		t.Fatal(err)
	}
	if len(h.engines) != 1 {
		t.Fatal("SetTier rebuilt the engine")
	}
	e := h.engines[0]
	if got := e.selected[len(e.selected)-1]; got != "stealth" {
		t.Fatalf("selected %v", e.selected)
	}
	st := h.c.Status()
	if st.TierPreference != "stealth" || st.Tier != "stealth" {
		t.Fatalf("status %+v", st)
	}
	if !strings.Contains(h.messages(), "Route switched: Fast → Stealth") {
		t.Fatalf("log: %s", h.messages())
	}
	if err := h.c.SetTier("auto"); err != nil {
		t.Fatal(err)
	}
	if h.c.current.controller.Load() == nil {
		t.Fatal("auto must re-enable failover")
	}
	if h.c.SetTier("nope") == nil {
		t.Fatal("accepted a bad tier")
	}
}

func TestFailoverSwitchLogsAndUpdates(t *testing.T) {
	h := newHarness()
	if err := h.c.Start(opts()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "probe", func() bool { return h.c.Status().LatencyMs != nil })
	s := h.c.current
	if err := s.engine.SelectTier("stealth"); err != nil {
		t.Fatal(err)
	}
	h.c.switched(s, "stealth")
	st := h.c.Status()
	if st.Tier != "stealth" || st.LatencyMs != nil {
		t.Fatalf("status %+v", st)
	}
	h.c.recordRoute(s, "stealth", routeLatency(90*time.Millisecond, true, false))
	if ms := h.c.Status().LatencyMs; ms == nil || *ms != 90 {
		t.Fatalf("latency %v", ms)
	}
	if !strings.Contains(h.messages(), "Route switched: Fast → Stealth (Fast stopped answering)") {
		t.Fatalf("log: %s", h.messages())
	}
}

func TestTestRoutes(t *testing.T) {
	h := newHarness()
	if got := h.c.TestRoutes(context.Background()); len(got) != 0 {
		t.Fatalf("off: %v", got)
	}
	h.next = func(e *fakeEngine) { e.failTier = map[string]bool{"stealth": true} }
	if err := h.c.Start(opts()); err != nil {
		t.Fatal(err)
	}
	got := h.c.TestRoutes(context.Background())
	if len(got) != 3 || !got["fast"].OK || got["fast"].Ms != 42 || got["stealth"].OK || !got["rescue"].OK || got["rescue"].Ms != 200 {
		t.Fatalf("routes %+v", got)
	}
	st := h.c.Status()
	if len(st.Routes) != 3 || st.Routes["stealth"].OK || st.LatencyMs == nil || *st.LatencyMs != 42 {
		t.Fatalf("status %+v", st)
	}
	no := opts()
	no.Profile.CDN = ""
	if err := h.c.Start(no); err != nil {
		t.Fatal(err)
	}
	if got := h.c.TestRoutes(context.Background()); len(got) != 2 {
		t.Fatalf("no rescue: %v", got)
	}
}

func TestApplyRebuildsOnlyWhenNeeded(t *testing.T) {
	h := newHarness()
	o := opts()
	if err := h.c.Apply(o); err != nil || len(h.engines) != 0 {
		t.Fatalf("apply while off: %v", err)
	}
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	same := opts()
	same.Tier = failover.Fast
	if err := h.c.Apply(same); err != nil || len(h.engines) != 1 || h.c.Status().Tier != "fast" || h.c.Status().TierPreference != "fast" {
		t.Fatalf("tier-only apply: %v %d", err, len(h.engines))
	}
	rules := same
	rules.Rules = []config.Rule{{Field: "process_name", Match: "curl", Action: "direct"}}
	if err := h.c.Apply(rules); err != nil || len(h.engines) != 2 {
		t.Fatalf("rules apply: %v %d", err, len(h.engines))
	}
	if st := h.c.Status(); st.State != "on" || st.TierPreference != "fast" {
		t.Fatalf("status %+v", st)
	}
	rules.LogLevel = "info"
	if err := h.c.Apply(rules); err != nil || len(h.engines) != 3 {
		t.Fatalf("log level apply: %v", err)
	}
}

func TestDirectModeSkipsFailover(t *testing.T) {
	h := newHarness()
	o := opts()
	o.Mode = "direct"
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	if st := h.c.Status(); st.Tier != "direct" {
		t.Fatalf("tier %q", st.Tier)
	}
	if h.c.current.controller.Load() != nil {
		t.Fatal("failover must not run in direct mode")
	}
	waitFor(t, "log", func() bool { return strings.Contains(h.messages(), "Connected (direct mode") })
	if got := h.c.TestRoutes(context.Background()); len(got) != 0 {
		t.Fatalf("direct: %v", got)
	}
}

func TestEngineConfigureFailure(t *testing.T) {
	h := newHarness()
	h.err = errors.New("bad config at 203.0.113.9")
	err := h.c.Start(opts())
	if err == nil || strings.Contains(err.Error(), "203.0.113.9") {
		t.Fatalf("error %v", err)
	}
	if strings.Contains(h.messages(), "203.0.113.9") {
		t.Fatal("log leaked the raw error")
	}
}

func hasUserRule(e *fakeEngine) bool {
	rules := e.options.Config["route"].(engine.Object)["rules"].([]engine.Object)
	for _, r := range rules {
		if r["domain"] == "example.com" {
			return true
		}
	}
	return false
}

func TestDirectModeIgnoresButKeepsRules(t *testing.T) {
	h := newHarness()
	o := opts()
	o.Rules = []config.Rule{{Field: "domain", Match: "example.com", Action: "proxy"}}
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	if !hasUserRule(h.engines[0]) {
		t.Fatal("rule missing in smart mode")
	}
	if err := h.c.SetMode("direct"); err != nil {
		t.Fatal(err)
	}
	if hasUserRule(h.engines[1]) || h.c.Status().Tier != "direct" {
		t.Fatal("direct mode must ignore rules")
	}
	if err := h.c.SetMode("smart"); err != nil {
		t.Fatal(err)
	}
	if !hasUserRule(h.engines[2]) {
		t.Fatal("rules lost after direct -> smart")
	}
	o.Mode = "direct"
	if err := h.c.Start(o); err != nil || hasUserRule(h.engines[3]) || len(h.c.current.opts.Rules) != 1 {
		t.Fatalf("start in direct: %v", err)
	}
}

func TestDirectModeCanApplyRules(t *testing.T) {
	h := newHarness()
	o := Options{Mode: config.Direct, RulesInDirect: true,
		Rules: []config.Rule{{Field: "domain", Match: "example.com", Action: "block"}}}
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	defer h.c.Stop()
	if !hasUserRule(h.engine(0)) || h.c.Status().Tier != config.Direct || h.c.current.controller.Load() != nil {
		t.Fatal("profile-free direct mode did not apply the block rule")
	}
	o.Rules[0].Action = "proxy"
	o.Profile = opts().Profile
	if err := h.c.Apply(o); err != nil {
		t.Fatal(err)
	}
	if !hasUserRule(h.engine(1)) || h.c.Status().Tier != "fast" || h.c.current.controller.Load() == nil {
		t.Fatal("a proxy rule in direct mode must enable the configured tiers and failover")
	}
}

func TestApplyDetectsProfileKeyChange(t *testing.T) {
	h := newHarness()
	o := opts()
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	o.Profile.Seed[0] = 9
	if err := h.c.Apply(o); err != nil || len(h.engines) != 2 {
		t.Fatalf("key change did not rebuild: %v %d", err, len(h.engines))
	}
}

func TestStopDuringTestRoutes(t *testing.T) {
	h := newHarness()
	h.next = func(e *fakeEngine) { e.block = true }
	if err := h.c.Start(opts()); err != nil {
		t.Fatal(err)
	}
	e := h.engines[0]
	done := make(chan map[string]RouteLatency)
	go func() { done <- h.c.TestRoutes(context.Background()) }()
	waitFor(t, "probes in flight", func() bool { return e.inProbe.Load() >= 3 })
	if err := h.c.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		for _, r := range got {
			if r.OK {
				t.Fatal("cancelled probe reported ok")
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TestRoutes did not return after Stop")
	}
	if !e.closed.Load() {
		t.Fatal("engine not closed")
	}
}

func TestEventsNeverLogHost(t *testing.T) {
	h := newHarness()
	o := opts()
	o.Profile.Name = ""
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "connect log", func() bool { return strings.Contains(h.messages(), "Connected to server via") })
	if strings.Contains(h.messages(), "origin.example") {
		t.Fatal("host logged")
	}
}

func TestFriendlyTUNFailureComesBeforePortMessages(t *testing.T) {
	tun := Options{TUN: true, Listen: "127.0.0.1:7890"}
	want := "Pipe Helper couldn't create the TUN device. Another VPN may be using it."
	if got := friendly(errors.New("start service: initialize inbound[0]: configure tun interface: device busy"), tun); got != want {
		t.Fatalf("got %q", got)
	}
	if got := friendly(errors.New("configure tun interface: permission denied"), tun); got != want {
		t.Fatalf("got %q", got)
	}
	if got := friendly(errors.New("listen tcp 127.0.0.1:7890: bind: address already in use"), tun); !strings.Contains(got, "already in use") {
		t.Fatalf("got %q", got)
	}
	if got := friendly(errors.New("configure tun interface: permission denied"), Options{}); strings.Contains(got, "TUN") {
		t.Fatalf("non-TUN options must not get the TUN message: %q", got)
	}
}

func engineHasIPv6(e *fakeEngine) bool {
	for _, ob := range e.options.Config["outbounds"].([]engine.Object) {
		if ob["tag"] == "direct" {
			return ob["domain_resolver"].(engine.Object)["strategy"] != "ipv4_only"
		}
	}
	return false
}

func tunHasIPv6(e *fakeEngine) bool {
	return len(e.options.Config["inbounds"].([]engine.Object)[0]["address"].([]string)) == 2
}

// The engine follows the network: IPv6 inside the TUN exactly when the network
// has it, Pipe's own IPv6 only when the user also allows it.
func TestIPv6FollowsTheNetwork(t *testing.T) {
	h := newHarness()
	var network atomic.Bool
	h.c.networkIPv6 = network.Load
	o := opts()
	o.TUN = true
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	defer h.c.Stop()
	if h.engineCount() != 1 || !tunHasIPv6(h.engine(0)) || engineHasIPv6(h.engine(0)) {
		t.Fatal("TUN must capture IPv6 before the physical network gains it")
	}
	if st := h.c.Status(); st.IPv6Available == nil || *st.IPv6Available {
		t.Fatalf("status %+v", st)
	}
	const none = "This network has no IPv6; Pipe uses IPv4."
	h.engine(0).resets() // a network change that keeps IPv4 only
	time.Sleep(50 * time.Millisecond)
	if h.engineCount() != 1 || strings.Count(h.messages(), none) != 1 {
		t.Fatalf("unchanged network rebuilt or logged again: %d engines\n%s", h.engineCount(), h.messages())
	}
	network.Store(true)
	h.engine(0).resets()
	waitFor(t, "IPv6 rebuild", func() bool {
		st := h.c.Status()
		return h.engineCount() == 2 && st.IPv6Available != nil && *st.IPv6Available
	})
	if !tunHasIPv6(h.engine(1)) || !engineHasIPv6(h.engine(1)) || !h.engine(0).closed.Load() {
		t.Fatal("a network with IPv6 must rebuild with IPv6")
	}
	if st := h.c.Status(); st.IPv6Available == nil || !*st.IPv6Available || !strings.Contains(h.messages(), "This network has IPv6 again.") {
		t.Fatalf("status %+v\n%s", st, h.messages())
	}
	o.IPv6 = false // the user's switch: the TUN still carries IPv6, Pipe doesn't use it
	if err := h.c.Apply(o); err != nil {
		t.Fatal(err)
	}
	if last := h.engine(h.engineCount() - 1); !tunHasIPv6(last) || engineHasIPv6(last) {
		t.Fatal("IPv6 off must keep the TUN's IPv6 route and stop using IPv6")
	}
	if body, _ := json.Marshal(h.c.Status()); !strings.Contains(string(body), `"ipv6Available":true`) {
		t.Fatalf("status JSON %s", body)
	}
}

// IPv6 that appears without a network callback is found by the periodic check.
func TestIPv6PeriodicCheck(t *testing.T) {
	h := newHarness()
	var network atomic.Bool
	h.c.networkIPv6, h.c.ipv6Every = network.Load, 10*time.Millisecond
	o := opts()
	o.TUN = true
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	defer h.c.Stop()
	time.Sleep(50 * time.Millisecond)
	if h.engineCount() != 1 {
		t.Fatalf("unchanged network rebuilt: %d engines", h.engineCount())
	}
	network.Store(true)
	waitFor(t, "periodic IPv6 rebuild", func() bool {
		st := h.c.Status()
		return h.engineCount() == 2 && st.IPv6Available != nil && *st.IPv6Available
	})
	time.Sleep(50 * time.Millisecond)
	if h.engineCount() != 2 || !tunHasIPv6(h.engine(1)) {
		t.Fatalf("expected one rebuild with IPv6: %d engines", h.engineCount())
	}
}

func TestTUNRefusesUnprotectedIPv6Fallback(t *testing.T) {
	h := newHarness()
	h.c.networkIPv6, h.c.ipv6Every = func() bool { return true }, 10*time.Millisecond
	h.next = func(e *fakeEngine) {
		if tunHasIPv6(e) {
			e.startErr = errors.New("add IPv6 address: permission denied")
		}
	}
	o := opts()
	o.TUN = true
	if err := h.c.Start(o); err == nil || h.engineCount() != 1 || h.c.Status().State == StateOn {
		h.c.Stop()
		t.Fatalf("IPv6 capture failure result: %v, %d engines", err, h.engineCount())
	}
}

func TestTierNotificationsFollowAutoAndRebuild(t *testing.T) {
	h := newHarness()
	var network atomic.Bool
	h.c.networkIPv6 = network.Load
	tiers := make(chan failover.Tier, 5)
	h.c.settings.OnTier = func(tier failover.Tier) { tiers <- tier }
	h.next = func(e *fakeEngine) { e.failTier = map[string]bool{"fast": true} }
	checkTier := func(want failover.Tier) {
		t.Helper()
		select {
		case got := <-tiers:
			if got != want || h.c.Status().Tier != string(want) {
				t.Fatalf("tier event %q, status %+v, want %q", got, h.c.Status(), want)
			}
		case <-time.After(time.Second):
			t.Fatalf("missing tier event %q", want)
		}
	}
	readyCalls := 0
	if err := h.c.StartWithReady(opts(), func() error {
		readyCalls++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	defer h.c.Stop()
	checkTier(failover.Fast)
	h.engine(0).options.ObserveTraffic()
	checkTier(failover.Stealth)
	network.Store(true)
	h.engine(0).resets()
	checkTier(failover.Fast)
	if !h.engine(0).closed.Load() || h.engineCount() != 2 || !h.engine(1).started.Load() || readyCalls != 1 {
		t.Fatal("rebuild must close the previous engine, start the new engine and keep setup once per start")
	}
	if err := h.c.SetTier("rescue"); err != nil {
		t.Fatal(err)
	}
	checkTier(failover.Rescue)
}

func TestFailoverErrorNotification(t *testing.T) {
	h := newHarness()
	want := errors.New("could not select tier")
	h.next = func(e *fakeEngine) {
		e.failTier = map[string]bool{"fast": true}
		e.selectErr = want
	}
	failures := make(chan error, 1)
	h.c.settings.OnFailoverError = func(err error) { failures <- err }
	if err := h.c.Start(opts()); err != nil {
		t.Fatal(err)
	}
	defer h.c.Stop()
	h.engine(0).options.ObserveTraffic()
	select {
	case got := <-failures:
		if !errors.Is(got, want) || h.c.Status().LastError == "" {
			t.Fatalf("failover error %v, status %+v", got, h.c.Status())
		}
	case <-time.After(time.Second):
		t.Fatal("missing automatic selection error")
	}
}

// A network change that arrives after Stop must not rebuild anything.
func TestIPv6ChangeAfterStop(t *testing.T) {
	h := newHarness()
	var network atomic.Bool
	h.c.networkIPv6 = network.Load
	if err := h.c.Start(opts()); err != nil {
		t.Fatal(err)
	}
	if err := h.c.Stop(); err != nil {
		t.Fatal(err)
	}
	network.Store(true)
	h.engine(0).resets()
	time.Sleep(50 * time.Millisecond)
	if h.engineCount() != 1 || h.c.Status().State != StateOff || h.c.Status().IPv6Available != nil {
		t.Fatalf("closed session rebuilt: %d engines, %+v", h.engineCount(), h.c.Status())
	}
}

// Apps cache fake IPs, so every engine the controller builds shares one table.
func TestSessionsShareFakeIP(t *testing.T) {
	h := newHarness()
	o := opts()
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	o.IPv6 = !o.IPv6
	if err := h.c.Apply(o); err != nil {
		t.Fatal(err)
	}
	first, second := h.engine(0).options.FakeIP, h.engine(h.engineCount()-1).options.FakeIP
	if first == nil || first != second || h.engineCount() < 2 {
		t.Fatalf("rebuild did not share the fake-IP table: %p %p (%d engines)", first, second, h.engineCount())
	}
	if err := h.c.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := h.c.Start(o); err != nil {
		t.Fatal(err)
	}
	if next := h.engine(h.engineCount() - 1).options.FakeIP; next != first {
		t.Fatalf("stop and start must keep the fake-IP table: %p %p", first, next)
	}
}
