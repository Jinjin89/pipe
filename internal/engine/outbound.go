// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxdialer "github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	errNamedOnce          = errors.New("dialed once by name")
	errPrivateDestination = errors.New("restricted server destination")
	errQUICDisabled       = errors.New("UDP port 443 is disabled on this tier")
	nat64WellKnownPrefix  = netip.MustParsePrefix("64:ff9b::/96")
	blockedNetworks       = [...]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),       // this network
		netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
		netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
		netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
		netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast
		netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
		netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
		netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
		netip.MustParsePrefix("240.0.0.0/4"),     // reserved
		netip.MustParsePrefix("::/96"),           // deprecated IPv4-compatible addresses
		netip.MustParsePrefix("64:ff9b::/96"),    // checked separately against embedded IPv4
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("::ffff:0:0:0/96"), // IPv4 translation
		netip.MustParsePrefix("2002::/16"),       // 6to4
		netip.MustParsePrefix("2001::/32"),       // Teredo
		netip.MustParsePrefix("2001:db8::/32"),   // documentation
		netip.MustParsePrefix("3fff::/20"),       // documentation
		netip.MustParsePrefix("100::/64"),        // discard-only
		netip.MustParsePrefix("fec0::/10"),       // site-local
	}
)

func publicDestination(destination M.Socksaddr) error {
	if !PublicDestination(destination.Addr) {
		return errPrivateDestination
	}
	return nil
}

// PublicDestination is the address guard used by all server forwarding paths.
func PublicDestination(address netip.Addr) bool {
	if address.Zone() != "" {
		return false
	}
	if nat64WellKnownPrefix.Contains(address) {
		translated := address.As16()
		var ipv4 [4]byte
		copy(ipv4[:], translated[12:])
		return PublicDestination(netip.AddrFrom4(ipv4))
	}
	ip := address.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, prefix := range blockedNetworks {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// requestedName returns the destination a proxy tier sends the server for a
// TCP connection: a name whenever the connection has one, so the server
// resolves it itself and never gets an address it can't use (IPv6 when it has
// none, or a wrong answer from a censored resolver). Two cases:
//
//   - The connection has a name, but the router looked it up for the user's IP
//     rules and dials the addresses one by one: send the name on the first,
//     and skip the rest with errNamedOnce, so a failure is dialed and
//     reported to failover once.
//   - A TUN connection to an address the app found around Pipe's DNS (a
//     browser's own DNS over HTTPS, a LAN resolver, a cache from before TUN):
//     send the TLS name the app asked for, as for every app that uses Pipe's
//     fake-IP DNS. SOCKS and HTTP clients choose the address they send, and a
//     plain HTTP Host can name anything (a proxy, a local name), so both keep
//     the address.
//
// Only the connection being dialed counts: other dials carry a context named
// for something else (a DNS over HTTPS lookup through the proxy carries the
// name being looked up), and the router's reverse-mapping cache can name an
// address the app chose itself, so the TLS name must come from the
// connection's own first bytes.
func requestedName(ctx context.Context, network string, destination M.Socksaddr) (M.Socksaddr, error) {
	if !destination.IsIP() || N.NetworkName(network) != N.NetworkTCP {
		return destination, nil
	}
	metadata := adapter.ContextFrom(ctx)
	switch {
	case metadata == nil:
	case metadata.Destination.IsFqdn() && metadata.Destination.Port == destination.Port &&
		slices.Contains(metadata.DestinationAddresses, destination.Addr):
		if destination.Addr != metadata.DestinationAddresses[0] {
			return destination, errNamedOnce
		}
		return metadata.Destination, nil
	case metadata.InboundType == C.TypeTun && metadata.Destination == destination &&
		metadata.Protocol == C.ProtocolTLS && M.IsDomainName(metadata.Domain):
		return M.Socksaddr{Fqdn: metadata.Domain, Port: destination.Port}, nil
	}
	return destination, nil
}

func rejectQUIC(network string, destination M.Socksaddr) error {
	if N.NetworkName(network) == N.NetworkUDP && destination.Port == 443 {
		return errQUICDisabled
	}
	return nil
}

func registerSlowTier[T any](registry *outbound.Registry, kind string, create outbound.ConstructorFunc[T]) {
	outbound.Register(registry, kind, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options T) (adapter.Outbound, error) {
		base, err := create(ctx, router, logger, tag, options)
		if err != nil {
			return nil, err
		}
		return &guardedOutbound{Outbound: base, guard: rejectQUIC, byName: true}, nil
	})
}

// Keep standard outbound calls behind the destination guard.
type guardedOutbound struct {
	adapter.Outbound
	guard           func(string, M.Socksaddr) error
	routeCheck      func(context.Context, M.Socksaddr) error
	restrictPackets bool
	byName          bool // a proxy tier: send requestedName
}

// Preserve direct's parallel dial path after filtering each candidate.
type guardedParallelOutbound struct {
	*guardedOutbound
}

var _ boxdialer.ParallelNetworkDialer = (*guardedParallelOutbound)(nil)

func newServerGuardedOutbound(base adapter.Outbound, guard func(string, M.Socksaddr) error) adapter.Outbound {
	wrapped := &guardedOutbound{Outbound: base, restrictPackets: true, guard: guard}
	if _, ok := base.(boxdialer.ParallelNetworkDialer); ok {
		return &guardedParallelOutbound{guardedOutbound: wrapped}
	}
	return wrapped
}

func (o *guardedOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if lifecycle, ok := o.Outbound.(adapter.Lifecycle); ok {
		return lifecycle.Start(stage, scope)
	}
	return nil
}

func (o *guardedOutbound) InterfaceUpdated(ctx context.Context) {
	if listener, ok := o.Outbound.(adapter.InterfaceUpdateListener); ok {
		listener.InterfaceUpdated(ctx)
	}
}

func (o *guardedOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if o.byName {
		var err error
		if destination, err = requestedName(ctx, network, destination); err != nil {
			return nil, err
		}
	}
	if err := o.guard(network, destination); err != nil {
		return nil, err
	}
	return o.Outbound.DialContext(ctx, network, destination)
}

func (o *guardedOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := o.guard(N.NetworkUDP, destination); err != nil {
		return nil, err
	}
	if o.restrictPackets && destination.IsIP() {
		routeCheck := o.routeCheck
		if routeCheck == nil {
			routeCheck = checkUDPDestinationRoute
		}
		if err := routeCheck(ctx, destination); err != nil {
			return nil, err
		}
	}
	conn, err := o.Outbound.ListenPacket(ctx, destination)
	if err != nil || !o.restrictPackets {
		return conn, err
	}
	return &publicPacketConn{PacketConn: conn, guard: o.guard}, nil
}

func (o *guardedOutbound) allowedAddresses(network string, destination M.Socksaddr, candidates []netip.Addr) ([]netip.Addr, error) {
	if len(candidates) == 0 && destination.IsIP() {
		candidates = []netip.Addr{destination.Addr}
	}
	if len(candidates) == 0 {
		if err := o.guard(network, destination); err != nil {
			return nil, err
		}
		return nil, errors.New("no destination addresses")
	}
	allowed := make([]netip.Addr, 0, len(candidates))
	var rejected error
	for _, address := range candidates {
		if err := o.guard(network, M.SocksaddrFrom(address, destination.Port)); err != nil {
			if rejected == nil {
				rejected = err
			}
			continue
		}
		allowed = append(allowed, address)
	}
	if len(allowed) == 0 {
		if rejected != nil {
			return nil, rejected
		}
		return nil, errors.New("no destination addresses")
	}
	return allowed, nil
}

func (o *guardedParallelOutbound) DialParallelNetwork(ctx context.Context, network string, destination M.Socksaddr, candidates []netip.Addr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	addresses, err := o.allowedAddresses(network, destination, candidates)
	if err != nil {
		return nil, err
	}
	base, ok := o.Outbound.(boxdialer.ParallelNetworkDialer)
	if !ok {
		return nil, errors.New("outbound does not support parallel network dialing")
	}
	return base.DialParallelNetwork(ctx, network, destination, addresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
}

func (o *guardedParallelOutbound) ListenSerialNetworkPacket(ctx context.Context, destination M.Socksaddr, candidates []netip.Addr, _ *C.NetworkStrategy, _ []C.InterfaceType, _ []C.InterfaceType, _ time.Duration) (net.PacketConn, netip.Addr, error) {
	addresses, err := o.allowedAddresses(N.NetworkUDP, destination, candidates)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	var failures []error
	for _, address := range addresses {
		candidate := M.SocksaddrFrom(address, destination.Port)
		conn, err := o.ListenPacket(ctx, candidate)
		if err == nil {
			return conn, address, nil
		}
		failures = append(failures, err)
	}
	return nil, netip.Addr{}, errors.Join(failures...)
}

func checkUDPDestinationRoute(ctx context.Context, destination M.Socksaddr) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, N.NetworkUDP, destination.String())
	if err != nil {
		return err
	}
	return conn.Close()
}

type publicPacketConn struct {
	net.PacketConn
	guard func(string, M.Socksaddr) error
}

func (c *publicPacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	if err := c.guard(N.NetworkUDP, M.SocksaddrFromNet(addr)); err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(payload, addr)
}
