// SPDX-License-Identifier: GPL-3.0-or-later
//go:build with_quic

package engine

import (
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxdialer "github.com/sagernet/sing-box/common/dialer"
	boxtls "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	boxhysteria2 "github.com/sagernet/sing-box/protocol/hysteria2"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func newFastOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, opts option.Hysteria2OutboundOptions, relay *relayState) (fastOutbound, error) {
	server := opts.ServerOptions.Build()
	if !relay.enabledFast(tag, opts) {
		relay = nil
	}
	if (!server.IsDomain() && relay == nil) || opts.Realm != nil || opts.Obfs != nil {
		base, err := boxhysteria2.NewOutbound(ctx, router, logger, tag, opts)
		if err != nil {
			return nil, err
		}
		return base.(*boxhysteria2.Outbound), nil
	}
	if opts.TLS == nil || !opts.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	config, err := boxtls.NewClient(ctx, logger, opts.Server, *opts.TLS)
	if err != nil {
		return nil, err
	}
	dialer, err := boxdialer.New(ctx, opts.DialerOptions, server.IsDomain())
	if err != nil {
		return nil, err
	}
	ports, err := hysteria.ParsePorts(opts.ServerPorts)
	if err != nil {
		return nil, err
	}
	packetDialer := &fastPacketDialer{
		Dialer:         dialer,
		lookup:         newFastLookup(ctx, dialer),
		server:         server,
		relay:          relay,
		lifetime:       ctx,
		ports:          ports,
		hopInterval:    time.Duration(opts.HopInterval),
		hopIntervalMax: time.Duration(opts.HopIntervalMax),
	}
	if relay != nil && relay.fastPorts != "" {
		packetDialer.relayPorts, err = hysteria.ParsePorts([]string{relay.fastPorts})
		if err != nil {
			return nil, E.Cause(err, "relay Fast ports")
		}
	}
	if relay != nil && relay.host.IsDomain() {
		via, err := relay.relayDialer(ctx, dialer, opts.DialerOptions, server)
		if err != nil {
			packetDialer.relayLookup = func(context.Context, string) ([]netip.Addr, error) { return nil, err }
		} else if server.IsDomain() && hasResolver(opts.DialerOptions) {
			packetDialer.relayLookup = packetDialer.lookup
		} else {
			packetDialer.relayLookup = newFastLookup(ctx, via)
		}
	}
	network := opts.Network.Build()
	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context:       ctx,
		Dialer:        packetDialer,
		Logger:        logger,
		BrutalDebug:   opts.BrutalDebug,
		ServerAddress: server,
		SendBPS:       uint64(opts.UpMbps * hysteria.MbpsToBps),
		ReceiveBPS:    uint64(opts.DownMbps * hysteria.MbpsToBps),
		Password:      opts.Password,
		TLSConfig:     &fastQUICConfig{Config: config},
		QUICOptions: qtls.QUICOptions{
			IdleTimeout:             opts.IdleTimeout.Build(),
			KeepAlivePeriod:         opts.KeepAlivePeriod.Build(),
			StreamReceiveWindow:     opts.StreamReceiveWindow.Value(),
			ConnectionReceiveWindow: opts.ConnectionReceiveWindow.Value(),
			MaxConcurrentStreams:    opts.MaxConcurrentStreams,
			InitialPacketSize:       opts.InitialPacketSize,
			DisablePathMTUDiscovery: opts.DisablePathMTUDiscovery,
		},
		UDPDisabled:  !slices.Contains(network, N.NetworkUDP),
		BBRProfile:   opts.BBRProfile,
		ChromeParrot: !opts.DisableChromeParrot,
	})
	if err != nil {
		return nil, err
	}
	return &fastHysteriaOutbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeHysteria2, tag, network, opts.DialerOptions),
		client:  client,
		logger:  logger,
		relay:   relay,
	}, nil
}

type fastLookup func(context.Context, string) ([]netip.Addr, error)

func newFastLookup(ctx context.Context, dialer N.Dialer) fastLookup {
	dns := service.FromContext[adapter.DNSRouter](ctx)
	query := sync.OnceValues(func() (*adapter.DNSQueryOptions, error) {
		return fastServerQuery(dialer)
	})
	return func(ctx context.Context, name string) ([]netip.Addr, error) {
		options, err := query()
		if options == nil {
			return nil, err
		}
		return dns.Lookup(log.ContextWithOverrideLevel(ctx, log.LevelDebug), name, *options)
	}
}

func fastServerQuery(dialer N.Dialer) (*adapter.DNSQueryOptions, error) {
	if detour, ok := dialer.(*boxdialer.DetourDialer); ok {
		target, err := detour.Dialer()
		if err != nil {
			return nil, err
		}
		dialer = target
	}
	resolver, ok := dialer.(boxdialer.ResolveDialer)
	if !ok {
		// Send the name to a detour configured to resolve it remotely.
		return nil, nil
	}
	query := resolver.QueryOptions()
	return &query, nil
}

type fastHysteriaOutbound struct {
	outbound.Adapter
	client *hysteria2.Client
	logger log.ContextLogger
	relay  *relayState
}

func (o *fastHysteriaOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
		return o.client.DialConn(ctx, destination)
	case N.NetworkUDP:
		conn, err := o.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), nil
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (o *fastHysteriaOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return o.client.ListenPacket(ctx)
}

func (o *fastHysteriaOutbound) MultiplexEnabled() bool {
	return true
}

func (o *fastHysteriaOutbound) InterfaceUpdated(context.Context) {
	if o.relay != nil {
		o.relay.interfaceUpdated("fast")
	}
	o.client.CloseWithError(E.New("network changed"))
}

func (o *fastHysteriaOutbound) SetKeepIdleConnections(keep bool) {
	o.client.SetKeepIdleConnections(keep)
}

func (o *fastHysteriaOutbound) CloseIdleConnections() {
	o.client.CloseIdleConnections()
}

func (o *fastHysteriaOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error { return o.client.CloseWithError(os.ErrClosed) })
	}
	return nil
}

type fastPacketDialer struct {
	N.Dialer
	lookup         fastLookup
	server         M.Socksaddr
	relay          *relayState
	relayLookup    fastLookup
	lifetime       context.Context
	ports          []uint16
	relayPorts     []uint16
	hopInterval    time.Duration
	hopIntervalMax time.Duration
}

func (d *fastPacketDialer) DialContext(ctx context.Context, network string, server M.Socksaddr) (net.Conn, error) {
	if d.relay != nil && server == d.server && N.NetworkName(network) == N.NetworkUDP {
		return &fastDialConn{dial: func(ctx context.Context, authenticate fastAuthenticate) (fastAuth, error) {
			return dialRelay(ctx, d.relay, "fast", func(ctx context.Context, viaRelay bool) (fastAuth, error) {
				endpoint, lookup, ports := server, d.lookup, d.ports
				if viaRelay {
					endpoint, lookup, ports = d.relay.endpoint(d.relay.fastPort), d.relayLookup, d.relayPorts
					// The login can be shared by multiple callers. Mark the session itself.
					ctx = context.WithValue(ctx, fastRelayContextKey{}, true)
				}
				families, err := fastFamilies(ctx, endpoint, lookup)
				if err != nil {
					return fastAuth{}, err
				}
				return d.offerGroup(ctx, network, endpoint, families, ports, authenticate)
			}, fastAuth.close)
		}}, nil
	}
	families, err := fastFamilies(ctx, server, d.lookup)
	if err != nil {
		return nil, err
	}
	if len(families[1]) == 0 {
		conn, err := d.dialFamily(ctx, network, server, families[0], d.ports)
		if err != nil {
			return nil, err
		}
		return &fastDialConn{Conn: conn}, nil
	}
	return &fastDialConn{dial: func(ctx context.Context, authenticate fastAuthenticate) (fastAuth, error) {
		return d.offerGroup(ctx, network, server, families, d.ports, authenticate)
	}}, nil
}

func fastFamilies(ctx context.Context, endpoint M.Socksaddr, lookup fastLookup) ([2][]netip.Addr, error) {
	var families [2][]netip.Addr
	if !endpoint.IsDomain() {
		return families, nil
	}
	addresses, err := lookup(ctx, endpoint.Fqdn)
	if err != nil || len(addresses) == 0 {
		return families, err
	}
	preferredIPv6 := addresses[0].Unmap().Is6()
	for _, address := range addresses {
		address = address.Unmap()
		family := 0
		if address.Is6() != preferredIPv6 {
			family = 1
		}
		families[family] = append(families[family], address)
	}
	return families, nil
}

func (d *fastPacketDialer) offerGroup(ctx context.Context, network string, endpoint M.Socksaddr, families [2][]netip.Addr, ports []uint16, authenticate fastAuthenticate) (fastAuth, error) {
	attempt := func(ctx context.Context, family int) (fastAuth, error) {
		socket, err := d.dialFamily(ctx, network, endpoint, families[family], ports)
		if err != nil {
			return fastAuth{}, err
		}
		return authenticate(ctx, socket)
	}
	if len(families[1]) == 0 {
		return attempt(ctx, 0)
	}
	return raceFastAuth(ctx, attempt)
}

func (d *fastPacketDialer) dialFamily(ctx context.Context, network string, server M.Socksaddr, addresses []netip.Addr, ports []uint16) (net.Conn, error) {
	dial := func(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
		if len(addresses) == 0 || destination.IsIP() {
			return d.Dialer.DialContext(ctx, network, destination)
		}
		return N.DialSerial(ctx, d.Dialer, network, destination, addresses)
	}
	if len(ports) == 0 {
		return dial(ctx, server)
	}
	first := true
	return hysteria.NewHopConn(func(destination M.Socksaddr) (net.Conn, error) {
		if first {
			first = false
			return dial(ctx, destination)
		}
		// HopConn pins the first socket's IP. Later hops use the client lifetime.
		return dial(d.lifetime, destination)
	}, server, ports, d.hopInterval, d.hopIntervalMax)
}
