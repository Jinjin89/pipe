// SPDX-License-Identifier: GPL-3.0-or-later

// Package engine contains the adapter for the pinned sing-box runtime.
package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	ruleAssets "pipe/assets/rules"
	"pipe/internal/overload"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

const (
	SharedCertificate        = "pipe-shared"
	RealityFrontTag          = "reality-front"
	ProbeDomain              = "pipe-probe.invalid"
	ProbePath                = "/.well-known/pipe-check"
	ProbeBurstSize           = 64 * 1024
	TestHostsTag             = "test-hosts"
	WebSocketEarlyDataLimit  = 2048
	WebSocketEarlyDataHeader = "Sec-WebSocket-Protocol"
)

// Object is a JSON option object. The adapter validates it with sing-box's
// versioned option decoder before it opens any listeners.
type Object map[string]any

type Options struct {
	Config           Object
	RuleSets         []string
	GetCertificate   func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	Server           bool
	DeviceIDs        []string
	Overload         *overload.Guard
	ObserveFastDial  func(error)
	ObserveTraffic   func()
	ObserveFastStall func()
	VPN              *VPNOptions
	Relay            Relay
	// DisableRelayCooldown lets each dial in a single-use probe engine try
	// the relay independently.
	DisableRelayCooldown bool
	// FakeIP, when set, is shared with every engine built with it, so
	// replacing the engine keeps the fake IPs apps have cached.
	FakeIP *FakeIP
	// CountBytes receives payload byte counts for every routed connection,
	// for mixed and TUN inbounds alike. VPNOptions.CountBytes still works.
	CountBytes func(up, down int64)
	// CountProxyBytes receives routed payload byte counts for Fast, Stealth,
	// and Rescue.
	CountProxyBytes func(up, down int64)
	// LogWriter receives sing-box log lines at or above the configured log
	// level. When set, sing-box writes nothing to stderr.
	LogWriter log.PlatformWriter
	// LANDNSServers provides resolver addresses from the active physical network.
	LANDNSServers func() []netip.AddrPort
}

type Instance struct {
	box       *box.Box
	ctx       context.Context
	reloads   map[string]*reloadableInbound
	sessions  *deviceSessions
	vpn       *vpnPlatform
	relay     *relayState
	closeOnce sync.Once
	closeErr  error
}

func New(ctx context.Context, options Options) (*Instance, error) {
	instance := &Instance{reloads: make(map[string]*reloadableInbound)}
	if options.Server {
		instance.sessions = newDeviceSessions(options.DeviceIDs, options.Overload)
	} else {
		instance.relay = newRelayState(options.Relay)
	}
	if options.VPN != nil {
		instance.vpn = &vpnPlatform{options: *options.VPN}
		registry := service.RegistryFromContext(ctx)
		if registry == nil {
			registry = service.NewRegistry()
		} else {
			registry = registry.Clone()
		}
		ctx = service.ContextWithRegistry(ctx, &vpnRegistry{Registry: registry, platform: instance.vpn})
		ctx = service.ContextWith[adapter.PlatformInterface](ctx, instance.vpn)
	}
	in := inbound.NewRegistry()
	mixed.RegisterInbound(in)
	direct.RegisterInbound(in)
	tun.RegisterInbound(in)
	registerInbound(in, instance.reloads, instance.sessions, C.TypeVLESS, vless.NewInbound)
	registerInbound(in, instance.reloads, instance.sessions, C.TypeVMess, vmess.NewInbound)
	out := outbound.NewRegistry()
	if options.Server {
		outbound.Register(out, InMemoryProbe, newProbeOutbound)
	}
	block.RegisterOutbound(out)
	group.RegisterSelector(out)
	registerOutbounds(out, options, instance.relay)
	registerQUIC(in, out, instance.reloads, options, instance.relay, instance.sessions)
	if instance.relay != nil && instance.relay.stealth {
		outbound.Register(out, relayTCPType, instance.relay.newTCPOutbound)
	}
	dnsTransport := dns.NewTransportRegistry()
	local.RegisterTransport(dnsTransport)
	hosts.RegisterTransport(dnsTransport)
	transport.RegisterHTTPS(dnsTransport)
	dns.RegisterTransport(dnsTransport, BootstrapDNSType, newBootstrapDNS)
	dns.RegisterTransport[struct{}](dnsTransport, LANDNSType, func(ctx context.Context, logger log.ContextLogger, tag string, _ struct{}) (adapter.DNSTransport, error) {
		return newLANDNS(ctx, logger, tag, options.LANDNSServers, tunAddresses(options.Config))
	})
	if options.FakeIP != nil {
		dns.RegisterTransport[option.FakeIPDNSServerOptions](dnsTransport, C.DNSTypeFakeIP, options.FakeIP.newTransport)
	} else {
		fakeip.RegisterTransport(dnsTransport)
	}
	certificates := certificate.NewRegistry()
	if options.GetCertificate != nil {
		certificate.Register(certificates, SharedCertificate,
			func(_ context.Context, _ log.ContextLogger, tag string, _ struct{}) (adapter.CertificateProviderService, error) {
				return &sharedCertificate{tag: tag, getCertificate: options.GetCertificate}, nil
			})
	}
	instance.ctx = box.Context(ctx, in, out, endpoint.NewRegistry(), dnsTransport, boxService.NewRegistry(), certificates)
	decoded, err := instance.decode(options.Config)
	if err != nil {
		return nil, err
	}
	if instance.relay != nil {
		instance.relay.noCooldown = options.DisableRelayCooldown
		instance.relay.configure(&decoded)
	}
	if options.Server {
		// Even WARN/ERROR from sing-box may contain addresses. The server
		// emits lifecycle warnings itself and discards engine log messages.
		decoded.Log = &option.LogOptions{Level: "warn", Output: os.DevNull}
	} else if options.LogWriter != nil {
		level := "warn"
		if decoded.Log != nil && decoded.Log.Level != "" {
			level = decoded.Log.Level
		}
		decoded.Log = &option.LogOptions{Level: level, Output: os.DevNull}
	} else if instance.vpn != nil {
		decoded.Log = &option.LogOptions{Disabled: true}
	}
	if len(options.RuleSets) > 0 {
		if decoded.Route == nil {
			decoded.Route = &option.RouteOptions{}
		}
		for _, name := range options.RuleSets {
			set, err := readRuleSet(name)
			if err != nil {
				return nil, fmt.Errorf("load embedded rule set %s: %w", name, err)
			}
			decoded.Route.RuleSet = append(decoded.Route.RuleSet, set)
		}
	}
	// Do not set box.Options.PlatformLogWriter: it forces ./cache.db.
	instance.box, err = box.New(box.Options{Options: decoded, Context: instance.ctx})
	if err != nil {
		return nil, err
	}
	if instance.relay != nil && instance.vpn == nil && (instance.relay.fast || instance.relay.stealth) {
		// Register before any OnNetworkChange subscribers.
		instance.relay.watchNetwork(instance.box.Network().InterfaceMonitor())
	}
	if options.LogWriter != nil && !options.Server {
		if factory := service.FromContext[log.Factory](instance.ctx); factory != nil {
			// Platform writers see every level, so filter here.
			factory.AttachPlatformWriter(newLevelWriter(options.LogWriter, decoded.Log.Level))
		}
	}
	if !options.Server && options.ObserveTraffic != nil {
		instance.box.Router().AppendTracker(&trafficTracker{
			observe: options.ObserveTraffic, suspectStall: options.ObserveFastStall,
		})
	}
	if options.VPN != nil && options.VPN.CountBytes != nil {
		instance.box.Router().AppendTracker(newUsageTracker(options.VPN.CountBytes, nil))
	}
	if options.CountBytes != nil || options.CountProxyBytes != nil {
		instance.box.Router().AppendTracker(newUsageTracker(options.CountBytes, options.CountProxyBytes))
	}
	return instance, nil
}

func (i *Instance) decode(config Object) (option.Options, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return option.Options{}, err
	}
	decoded, err := SJSON.UnmarshalExtendedContext[option.Options](i.ctx, data)
	if err != nil || i.vpn == nil {
		return decoded, err
	}
	for _, inbound := range decoded.Inbounds {
		if options, ok := inbound.Options.(*option.TunInboundOptions); ok && options.InterfaceName == "" {
			// An empty name makes sing-box enumerate interfaces before
			// opening the platform TUN. Android's fd supplies the real name.
			options.InterfaceName = "pipe-vpn"
		}
	}
	return decoded, nil
}

func readRuleSet(name string) (option.RuleSet, error) {
	data, err := ruleAssets.Files.ReadFile(name + ".srs")
	if err != nil {
		return option.RuleSet{}, err
	}
	compat, err := srs.Read(bytes.NewReader(data), false)
	if err != nil {
		return option.RuleSet{}, err
	}
	rules, err := compat.Upgrade()
	if err != nil {
		return option.RuleSet{}, err
	}
	return option.RuleSet{Type: C.RuleSetTypeInline, Tag: []string{name}, InlineOptions: rules}, nil
}

func (i *Instance) Start() error {
	if err := i.box.Start(); err != nil {
		return err
	}
	if i.vpn != nil {
		// Publish the platform default after sing-box's initial network check.
		i.vpn.applyNetwork(i.ctx, false)
	}
	return nil
}

func (i *Instance) Close() error {
	i.closeOnce.Do(func() {
		if i.relay != nil && i.relay.stopMonitor != nil {
			i.relay.stopMonitor()
		}
		var revoked []*session
		if i.sessions != nil {
			revoked = i.sessions.revokeDisallowed(nil)
		}
		i.closeErr = i.box.Close()
		closeSessions(revoked)
	})
	return i.closeErr
}

func (i *Instance) selector() *group.Selector {
	if i.box == nil {
		return nil
	}
	proxy, _ := i.box.Outbound().Outbound("proxy")
	selector, _ := proxy.(*group.Selector)
	return selector
}

func (i *Instance) SelectTier(tier string) error {
	if selector := i.selector(); selector != nil && selector.SelectOutbound(tier) {
		return nil
	}
	return fmt.Errorf("tier %q is unavailable", tier)
}

func (i *Instance) OnNetworkChange(reset func()) func() {
	monitor := i.box.Network().InterfaceMonitor()
	if monitor == nil {
		return func() {}
	}
	callback := monitor.RegisterCallback(func(_ *control.Interface, _ int) { reset() })
	return func() { monitor.UnregisterCallback(callback) }
}

// DefaultInterface returns the physical uplink selected by the running
// engine's interface monitor, or an empty string when one is unavailable.
func (i *Instance) DefaultInterface() string {
	if i == nil || i.box == nil {
		return ""
	}
	monitor := i.box.Network().InterfaceMonitor()
	if monitor == nil {
		return ""
	}
	if iface := monitor.DefaultInterface(); iface != nil {
		return iface.Name
	}
	return ""
}

func (i *Instance) VPNOnline() bool { return i.vpn.monitor.DefaultInterface() != nil }

func (i *Instance) RefreshVPNNetwork(reset bool) (bool, error) {
	if err := i.vpn.network.UpdateInterfaces(); err != nil {
		return i.VPNOnline(), err
	}
	return i.vpn.applyNetwork(i.ctx, reset), nil
}

// Probe establishes an HTTP connection to the server's decoy using the
// specified outbound, independent of the active tier and client DNS rules.
func (i *Instance) Probe(ctx context.Context, tier string, burst bool) (stalled bool, err error) {
	stalled, _, _, err = i.ProbeLatency(ctx, tier, burst)
	return stalled, err
}

// ProbeLatency measures from the start of the dial to the end of the probe
// response. Via is true when a successful probe traveled through a relay.
func (i *Instance) ProbeLatency(ctx context.Context, tier string, burst bool) (stalled bool, latency time.Duration, via bool, err error) {
	start := time.Now()
	conn, err := i.dialProbe(ctx, tier)
	if err != nil {
		return false, 0, false, err
	}
	stalled, err = probeHTTP(ctx, conn, burst)
	return stalled, time.Since(start), err == nil && probeViaRelay(conn), err
}

func (i *Instance) dialProbe(ctx context.Context, tier string) (net.Conn, error) {
	dialer, found := i.box.Outbound().Outbound(tier)
	if !found {
		return nil, fmt.Errorf("tier %q is unavailable", tier)
	}
	return dialer.DialContext(context.WithValue(ctx, probeContextKey{}, true), "tcp", M.ParseSocksaddrHostPort(ProbeDomain, 80))
}

// MeasureRTT measures the median of three round trips on one authenticated
// stream after a warm-up. A legacy single reply can establish reachability.
func (i *Instance) MeasureRTT(ctx context.Context, tier string) (time.Duration, bool, error) {
	conn, err := i.dialProbe(ctx, tier)
	if err != nil {
		return 0, false, err
	}
	rtt, err := measureProbeRTT(ctx, conn)
	return rtt, err == nil && probeViaRelay(conn), err
}

// ProbeContext lets a user-started probe use this engine's outbounds with its
// own cancellation and deadline.
func (i *Instance) ProbeContext(ctx context.Context) context.Context {
	return service.ContextWithRegistry(ctx, service.RegistryFromContext(i.ctx))
}

func measureProbeRTT(ctx context.Context, conn net.Conn) (time.Duration, error) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	input := &io.LimitedReader{R: conn, N: 16 << 10}
	reader := bufio.NewReader(input)
	var samples [3]time.Duration
	for round := range 4 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ProbeDomain+ProbePath, nil)
		if err != nil {
			return 0, err
		}
		req.Close = round == len(samples)
		start := time.Now()
		if err := req.Write(conn); err != nil {
			return 0, err
		}
		res, err := http.ReadResponse(reader, req)
		if err != nil {
			return 0, err
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, 3))
		if err != nil || res.StatusCode != http.StatusOK || string(body) != "OK" || input.N == 0 {
			return 0, fmt.Errorf("invalid latency probe reply")
		}
		elapsed := time.Since(start)
		_ = res.Body.Close()
		if round == 0 && res.Close {
			return 0, nil
		}
		if round > 0 {
			samples[round-1] = max(elapsed, time.Nanosecond)
		}
	}
	slices.Sort(samples[:])
	return samples[1], nil
}

func probeViaRelay(conn net.Conn) bool {
	if _, ok := common.Cast[relayedProbeConn](conn); ok {
		return true
	}
	// A Fast stream inherits the context of its authenticated QUIC session.
	if stream, ok := common.Cast[interface{ Context() context.Context }](conn); ok {
		return stream.Context().Value(fastRelayContextKey{}) != nil
	}
	return false
}

type probeContextKey struct{}
type fastRelayContextKey struct{}
type relayedProbeConn struct{ net.Conn }

func probeHTTP(ctx context.Context, conn net.Conn, burst bool) (bool, error) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		// Early WebSockets delegate cancellation to Close.
		_ = conn.SetDeadline(deadline)
	}
	path := ProbePath
	if burst {
		path += "?burst=1"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ProbeDomain+path, nil)
	if err != nil {
		return false, err
	}
	request.Close = true
	if err := request.Write(conn); err != nil {
		return false, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("probe HTTP status %d", response.StatusCode)
	}
	want := int64(2)
	if burst {
		want = ProbeBurstSize
	}
	_, err = io.CopyN(io.Discard, response.Body, want)
	if err != nil {
		return os.IsTimeout(err) || ctx.Err() == context.DeadlineExceeded, err
	}
	return false, nil
}

type sharedCertificate struct {
	tag            string
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

func (p *sharedCertificate) Type() string { return SharedCertificate }
func (p *sharedCertificate) Tag() string  { return p.tag }
func (p *sharedCertificate) Start(adapter.StartStage, *adapter.Scope) error {
	return nil
}
func (p *sharedCertificate) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.getCertificate(hello)
}

func registerOutbounds(registry *outbound.Registry, options Options, relay *relayState) {
	outbound.Register(registry, C.TypeDirect,
		func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, opts option.DirectOutboundOptions) (adapter.Outbound, error) {
			base, err := direct.NewOutbound(ctx, router, logger, tag, opts)
			if err != nil || !options.Server || tag != "direct" {
				return base, err
			}
			return newServerGuardedOutbound(base, func(_ string, destination M.Socksaddr) error {
				return publicDestination(destination)
			}, options.Overload), nil
		})
	registerSlowTier(registry, C.TypeVLESS, relay.newStealthOutbound)
	registerSlowTier(registry, C.TypeVMess, vmess.NewOutbound)
}
