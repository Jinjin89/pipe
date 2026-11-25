// SPDX-License-Identifier: GPL-3.0-or-later
//go:build with_quic

package engine

import (
	"context"
	"errors"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	M "github.com/sagernet/sing/common/metadata"
)

func registerQUIC(in *inbound.Registry, out *outbound.Registry, reloads map[string]*reloadableInbound, options Options, relay *relayState) {
	registerInbound(in, reloads, options.Server, C.TypeHysteria2, hysteria2.NewInbound)
	outbound.Register(out, C.TypeHysteria2,
		func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, opts option.Hysteria2OutboundOptions) (adapter.Outbound, error) {
			base, err := newFastOutbound(ctx, router, logger, tag, opts, relay)
			if err != nil {
				return nil, err
			}
			wrapped := &observedFast{fastOutbound: base, observe: options.ObserveFastDial}
			if relay.enabledFast(tag, opts) {
				wrapped.relay = relay
			}
			return wrapped, nil
		})
}

type fastOutbound interface {
	adapter.OutboundWithMultiplex
	adapter.InterfaceUpdateListener
	adapter.IdleConnectionKeeper
	adapter.Lifecycle
}

// observedFast is the Fast tier: it sends requestedName and reports dial
// results to the failover controller when there is one.
type observedFast struct {
	fastOutbound
	observe func(error)
	relay   *relayState
}

func (o *observedFast) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	destination, err := requestedName(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	conn, err := o.fastOutbound.DialContext(ctx, network, destination)
	o.report(ctx, err)
	return conn, err
}

func (o *observedFast) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return listenFastPacket(ctx, destination, o.fastOutbound.ListenPacket, o.report)
}

func (o *observedFast) report(ctx context.Context, err error) {
	if o.observe == nil && o.relay == nil {
		return
	}
	ctxErr := ctx.Err()
	// A probe can stop waiting before sing-quic finishes its shared login.
	if o.relay != nil && ctxErr == context.DeadlineExceeded && errors.Is(err, context.DeadlineExceeded) {
		o.relay.fastWaitTimedOut()
	}
	if o.observe != nil && !errors.Is(ctxErr, context.Canceled) && !errors.Is(err, context.Canceled) && ctx.Value(probeContextKey{}) == nil {
		o.observe(err)
	}
}
