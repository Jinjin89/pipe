// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxdialer "github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/vless"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const relayTCPType = "pipe-relay-tcp"

type relayTCPOptions struct {
	option.DialerOptions
	server M.Socksaddr
}

func (r *relayState) configure(options *option.Options) {
	r.bootstrap = r.bootstrapResolver(options)
	var fast, stealth bool
	for _, outbound := range options.Outbounds {
		switch dial := outbound.Options.(type) {
		case *option.Hysteria2OutboundOptions:
			fast = fast || r.enabledFast(outbound.Tag, *dial)
		case *option.VLESSOutboundOptions:
			if r.stealth && outbound.Tag == "stealth" && canRelayStealth(*dial) {
				r.stealthDetour = relayDetourTag(options)
				options.Outbounds = append(options.Outbounds, option.Outbound{
					Type: relayTCPType, Tag: r.stealthDetour, Options: &relayTCPOptions{
						DialerOptions: dial.DialerOptions, server: dial.ServerOptions.Build(),
					},
				})
				stealth = true
			}
		}
	}
	r.fast, r.stealth = fast, stealth
}

func canRelayStealth(options option.VLESSOutboundOptions) bool {
	tls := options.TLS
	// Pipe's plain REALITY VLESS path authenticates each physical connection.
	return tls != nil && tls.Enabled && (tls.Engine == "" || tls.Engine == C.TLSEngineGo) &&
		tls.Reality != nil && tls.Reality.Enabled &&
		options.Transport == nil && (options.Multiplex == nil || !options.Multiplex.Enabled)
}

func (r *relayState) enabledFast(tag string, options option.Hysteria2OutboundOptions) bool {
	return r != nil && r.fast && tag == "fast" && options.Realm == nil && options.Obfs == nil &&
		options.TLS != nil && options.TLS.Enabled && len(options.TLS.CertificatePublicKeySHA256) > 0
}

func relayDetourTag(options *option.Options) string {
	tag := relayTCPType
	for suffix := 1; ; suffix++ {
		if !slices.ContainsFunc(options.Outbounds, func(o option.Outbound) bool { return o.Tag == tag }) &&
			!slices.ContainsFunc(options.Endpoints, func(e option.Endpoint) bool { return e.Tag == tag }) {
			return tag
		}
		tag = relayTCPType + "-" + strconv.Itoa(suffix)
	}
}

func (r *relayState) bootstrapResolver(options *option.Options) *option.DomainResolveOptions {
	if !r.host.IsDomain() || options.DNS == nil {
		return nil
	}
	name := mDNS.CanonicalName(r.host.Fqdn)
	for _, server := range options.DNS.Servers {
		bootstrap, ok := server.Options.(*bootstrapDNSOptions)
		if !ok || server.Tag == "" || !slices.ContainsFunc(bootstrap.Hosts, func(host string) bool {
			return mDNS.CanonicalName(host) == name
		}) {
			continue
		}
		resolver := &option.DomainResolveOptions{Server: server.Tag, DisableCache: true}
		if options.Route != nil && options.Route.DefaultDomainResolver != nil {
			resolver.Strategy = options.Route.DefaultDomainResolver.Strategy
		}
		return resolver
	}
	return nil
}

func hasResolver(options option.DialerOptions) bool {
	return options.DomainResolver != nil && options.DomainResolver.Server != ""
}

func (r *relayState) relayDialer(ctx context.Context, direct N.Dialer, options option.DialerOptions, server M.Socksaddr) (N.Dialer, error) {
	if !r.host.IsDomain() {
		return direct, nil
	}
	if !hasResolver(options) {
		if r.bootstrap == nil {
			return nil, errors.New("relay hostname needs a proxy bootstrap resolver")
		}
		options.DomainResolver = r.bootstrap
	} else if server.IsDomain() {
		return direct, nil
	}
	return boxdialer.New(ctx, options, true)
}

func (r *relayState) newStealthOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.VLESSOutboundOptions) (adapter.Outbound, error) {
	direct, err := vless.NewOutbound(ctx, router, logger, tag, options)
	if err != nil || r == nil || tag != "stealth" || r.stealthDetour == "" {
		return direct, err
	}
	// Both VLESS dials verify the same REALITY key before returning an early stream.
	options.DialerOptions = option.DialerOptions{Detour: r.stealthDetour}
	relayed, err := vless.NewOutbound(ctx, router, logger, tag, options)
	if err != nil {
		return nil, err
	}
	return &relayStealthOutbound{Outbound: direct.(*vless.Outbound), viaRelay: relayed.(*vless.Outbound), state: r}, nil
}

type relayStealthOutbound struct {
	*vless.Outbound
	viaRelay *vless.Outbound
	state    *relayState
}

func (o *relayStealthOutbound) Dependencies() []string {
	return append(slices.Clone(o.Outbound.Dependencies()), o.viaRelay.Dependencies()...)
}

func (o *relayStealthOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if err := o.Outbound.Start(stage, scope); err != nil {
		return err
	}
	return o.viaRelay.Start(stage, scope)
}

func (o *relayStealthOutbound) InterfaceUpdated(ctx context.Context) {
	o.state.interfaceUpdated("stealth")
	o.Outbound.InterfaceUpdated(ctx)
	o.viaRelay.InterfaceUpdated(ctx)
}

func (o *relayStealthOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return dialRelay(ctx, o.state, o.Tag(), func(ctx context.Context, viaRelay bool) (net.Conn, error) {
		if viaRelay {
			conn, err := o.viaRelay.DialContext(ctx, network, destination)
			if err == nil && ctx.Value(probeContextKey{}) != nil {
				conn = relayedProbeConn{conn}
			}
			return conn, err
		}
		return o.Outbound.DialContext(ctx, network, destination)
	}, func(conn net.Conn) { conn.Close() })
}

func (o *relayStealthOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return dialRelay(ctx, o.state, o.Tag(), func(ctx context.Context, viaRelay bool) (net.PacketConn, error) {
		if viaRelay {
			return o.viaRelay.ListenPacket(ctx, destination)
		}
		return o.Outbound.ListenPacket(ctx, destination)
	}, func(conn net.PacketConn) { conn.Close() })
}

func (r *relayState) newTCPOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options relayTCPOptions) (adapter.Outbound, error) {
	direct, err := boxdialer.New(ctx, options.DialerOptions, options.server.IsDomain())
	if err != nil {
		return nil, err
	}
	via, relayErr := r.relayDialer(ctx, direct, options.DialerOptions, options.server)
	return &relayTCPOutbound{
		Adapter:  outbound.NewAdapterWithDialerOptions(relayTCPType, tag, []string{N.NetworkTCP}, options.DialerOptions),
		Dialer:   direct,
		server:   options.server,
		endpoint: r.endpoint(r.stealthPort),
		viaRelay: via,
		relayErr: relayErr,
	}, nil
}

type relayTCPOutbound struct {
	outbound.Adapter
	N.Dialer
	server   M.Socksaddr
	endpoint M.Socksaddr
	viaRelay N.Dialer
	relayErr error
}

func (o *relayTCPOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination != o.server || N.NetworkName(network) != N.NetworkTCP {
		return o.Dialer.DialContext(ctx, network, destination)
	}
	if o.relayErr != nil {
		return nil, o.relayErr
	}
	return o.viaRelay.DialContext(ctx, network, o.endpoint)
}
