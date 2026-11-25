// SPDX-License-Identifier: GPL-3.0-or-later
//go:build with_quic

package engine

import (
	"context"
	"net"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func requestedPacketName(ctx context.Context, destination M.Socksaddr) (M.Socksaddr, error) {
	if !destination.IsIP() {
		return destination, nil
	}
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		return destination, nil
	}
	switch {
	case metadata.Destination.IsFqdn() && metadata.Destination.Port == destination.Port &&
		slices.Contains(metadata.DestinationAddresses, destination.Addr):
		if destination.Addr != metadata.DestinationAddresses[0] {
			return destination, errNamedOnce
		}
		return metadata.Destination, nil
	// QUIC sniffing marks the protocol before it parses the name: only a
	// finished sniff means Domain came from this flow, not the reverse-mapping cache.
	case metadata.InboundType == C.TypeTun && metadata.Destination == destination &&
		metadata.Protocol == C.ProtocolQUIC && metadata.SniffError == nil && M.IsDomainName(metadata.Domain):
		return M.Socksaddr{Fqdn: metadata.Domain, Port: destination.Port}, nil
	}
	return destination, nil
}

func listenFastPacket(
	ctx context.Context,
	destination M.Socksaddr,
	listen func(context.Context, M.Socksaddr) (net.PacketConn, error),
	report func(context.Context, error),
) (net.PacketConn, error) {
	requested, err := requestedPacketName(ctx, destination)
	if err != nil {
		return nil, err
	}
	conn, err := listen(ctx, requested)
	if report != nil {
		report(ctx, err)
	}
	if err != nil || requested == destination {
		return conn, err
	}
	return &fastNamedPacketConn{
		PacketConn: conn,
		packets:    bufio.NewPacketConn(conn),
		original:   destination.Unwrap(),
		name:       requested,
	}, nil
}

// fastNamedPacketConn restores the original IP on replies so sing-box's NAT can match them.
type fastNamedPacketConn struct {
	net.PacketConn
	packets  N.NetPacketConn
	original M.Socksaddr
	name     M.Socksaddr
}

var _ net.PacketConn = (*fastNamedPacketConn)(nil)
var _ N.NetPacketConn = (*fastNamedPacketConn)(nil)

func (c *fastNamedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil && M.SocksaddrFromNet(addr) == c.name {
		addr = c.original.UDPAddr()
	}
	return n, addr, err
}

func (c *fastNamedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if M.SocksaddrFromNet(addr).Unwrap() == c.original {
		addr = c.name
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *fastNamedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.packets.ReadPacket(buffer)
	if err == nil && destination == c.name {
		destination = c.original
	}
	return destination, err
}

func (c *fastNamedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if destination.Unwrap() == c.original {
		destination = c.name
	}
	return c.packets.WritePacket(buffer, destination)
}
