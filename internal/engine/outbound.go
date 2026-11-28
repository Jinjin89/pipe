// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"cmp"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"time"

	"pipe/internal/overload"

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
	serverPolicy    *EgressPolicy
	overload        *overload.Guard
	restrictPackets bool
	byName          bool // a proxy tier: send requestedName
}

// Preserve direct's parallel dial path after filtering each candidate.
type guardedParallelOutbound struct {
	*guardedOutbound
}

var _ boxdialer.ParallelNetworkDialer = (*guardedParallelOutbound)(nil)

func newServerGuardedOutbound(base adapter.Outbound, guard func(string, M.Socksaddr) error, pressure *overload.Guard) adapter.Outbound {
	wrapped := &guardedOutbound{Outbound: base, restrictPackets: true, guard: guard, overload: pressure}
	if _, ok := base.(boxdialer.ParallelNetworkDialer); ok {
		return &guardedParallelOutbound{guardedOutbound: wrapped}
	}
	return wrapped
}

func (o *guardedOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize && o.restrictPackets {
		// Request transports can replace their context. Capture the policy
		// from the instance's lifecycle before any inbound starts forwarding.
		o.serverPolicy = egressPolicy(scope.Context())
	}
	if lifecycle, ok := o.Outbound.(adapter.Lifecycle); ok {
		return lifecycle.Start(stage, scope)
	}
	return nil
}

func (o *guardedOutbound) policyFor(ctx context.Context) *EgressPolicy {
	if o.serverPolicy != nil {
		return o.serverPolicy
	}
	return egressPolicy(ctx)
}

func (o *guardedOutbound) InterfaceUpdated(ctx context.Context) {
	if o.restrictPackets {
		o.policyFor(ctx).Invalidate()
	}
	if listener, ok := o.Outbound.(adapter.InterfaceUpdateListener); ok {
		listener.InterfaceUpdated(ctx)
	}
}

func (o *guardedOutbound) check(network string, destination M.Socksaddr, allows func(netip.Addr) bool) error {
	if err := o.guard(network, destination); err != nil {
		return err
	}
	if o.restrictPackets && !allows(destination.Addr) {
		return errPrivateDestination
	}
	return nil
}

func (o *guardedOutbound) observeDialError(err error) {
	if err != nil && o.overload != nil {
		o.overload.ObserveError(err)
	}
}

// Complete the reservation after closing any socket returned by a canceled or failed dial.
func finishOutboundDial[T io.Closer](ctx context.Context, finish func(bool) bool, conn *T, err *error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		*err = ctxErr
	}
	socket := io.Closer(*conn)
	if *err == nil && socket != nil && finish(true) {
		return
	}
	if socket != nil {
		_ = socket.Close()
		var zero T
		*conn = zero
		if *err == nil {
			*err = cmp.Or(ctx.Err(), errDeviceRevoked)
		}
	}
	finish(false)
}

func (o *guardedOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (conn net.Conn, err error) {
	finish := overload.LeaseFromContext(ctx).StartDial()
	defer finishOutboundDial(ctx, finish, &conn, &err)
	if o.byName {
		if destination, err = requestedName(ctx, network, destination); err != nil {
			return nil, err
		}
	}
	policy := o.policyFor(ctx)
	allows := policy.Allows
	if o.restrictPackets && N.NetworkName(network) == N.NetworkTCP {
		allows = policy.AllowsFresh
	}
	if err := o.check(network, destination, allows); err != nil {
		return nil, err
	}
	if o.restrictPackets {
		destination = M.SocksaddrFrom(destination.Addr.Unmap(), destination.Port)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err = o.Outbound.DialContext(ctx, network, destination)
	o.observeDialError(err)
	return conn, err
}

func (o *guardedOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (conn net.PacketConn, err error) {
	finish := overload.LeaseFromContext(ctx).StartDial()
	defer finishOutboundDial(ctx, finish, &conn, &err)
	return o.listenPacket(ctx, destination)
}

func (o *guardedOutbound) listenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	policy := o.policyFor(ctx)
	if err := o.check(N.NetworkUDP, destination, policy.Allows); err != nil {
		return nil, err
	}
	if o.restrictPackets && destination.IsIP() {
		destination = M.SocksaddrFrom(destination.Addr.Unmap(), destination.Port)
		routeCheck := o.routeCheck
		if routeCheck == nil {
			routeCheck = checkUDPDestinationRoute
		}
		if err := routeCheck(ctx, destination); err != nil {
			o.observeDialError(err)
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := o.Outbound.ListenPacket(ctx, destination)
	o.observeDialError(err)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	if !o.restrictPackets {
		return conn, nil
	}
	return &publicPacketConn{PacketConn: conn, guard: o.guard, policy: policy}, nil
}

func (o *guardedOutbound) allowedAddresses(ctx context.Context, network string, destination M.Socksaddr, candidates []netip.Addr) ([]netip.Addr, error) {
	policy := o.policyFor(ctx)
	allows := policy.Allows
	if o.restrictPackets && N.NetworkName(network) == N.NetworkTCP {
		allows = policy.freshCheck()
	}
	if len(candidates) == 0 && destination.IsIP() {
		candidates = []netip.Addr{destination.Addr}
	}
	if len(candidates) == 0 {
		if err := o.check(network, destination, allows); err != nil {
			return nil, err
		}
		return nil, errors.New("no destination addresses")
	}
	allowed := make([]netip.Addr, 0, len(candidates))
	var rejected error
	for _, address := range candidates {
		if err := o.check(network, M.SocksaddrFrom(address, destination.Port), allows); err != nil {
			if rejected == nil {
				rejected = err
			}
			continue
		}
		allowed = append(allowed, address.Unmap())
	}
	if len(allowed) == 0 {
		if rejected != nil {
			return nil, rejected
		}
		return nil, errors.New("no destination addresses")
	}
	return allowed, nil
}

func (o *guardedParallelOutbound) DialParallelNetwork(ctx context.Context, network string, destination M.Socksaddr, candidates []netip.Addr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (conn net.Conn, err error) {
	lease := overload.LeaseFromContext(ctx)
	primaryFinish := lease.StartDial()
	addresses, err := o.allowedAddresses(ctx, network, destination, candidates)
	if err != nil {
		primaryFinish(false)
		return nil, err
	}
	base, ok := o.Outbound.(boxdialer.ParallelNetworkDialer)
	if !ok {
		primaryFinish(false)
		return nil, errors.New("outbound does not support parallel network dialing")
	}
	if err := ctx.Err(); err != nil {
		primaryFinish(false)
		return nil, err
	}
	if !o.restrictPackets || len(addresses) <= 1 {
		defer finishOutboundDial(ctx, primaryFinish, &conn, &err)
		conn, err = base.DialParallelNetwork(ctx, network, destination, addresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
		o.observeDialError(err)
		return conn, err
	}
	policy := o.policyFor(ctx)
	allows := policy.Allows
	if N.NetworkName(network) == N.NetworkTCP {
		allows = policy.AllowsFresh
	}
	delay := fallbackDelay
	if delay <= 0 {
		delay = 300 * time.Millisecond
	}
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type attemptResult struct {
		conn net.Conn
		err  error
	}
	results := make(chan attemptResult, len(addresses))
	var inFlight, next int
	var extra []func()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	var tick <-chan time.Time
	launchNext := func() {
		tick = nil
		if next == len(addresses) || ctx.Err() != nil {
			return
		}
		if inFlight > 0 {
			release, ok := lease.TryReserveDial()
			if !ok {
				// Wait for a completion before trying another address.
				return
			}
			extra = append(extra, release)
		}
		idx, addr := next, addresses[next]
		next++
		inFlight++
		go func() {
			if idx > 0 {
				if err := o.check(network, M.SocksaddrFrom(addr, destination.Port), allows); err != nil {
					results <- attemptResult{err: err}
					return
				}
			}
			if err := dialCtx.Err(); err != nil {
				results <- attemptResult{err: err}
				return
			}
			conn, err := base.DialParallelNetwork(dialCtx, network, destination, []netip.Addr{addr}, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
			o.observeDialError(err)
			results <- attemptResult{conn: conn, err: err}
		}()
		if next < len(addresses) {
			timer.Reset(delay)
			tick = timer.C
		}
	}
	drain := func(remaining int, slots []func(), finish func(bool) bool) {
		if remaining == 0 {
			return
		}
		go func() {
			for i := range remaining {
				if result := <-results; result.conn != nil {
					_ = result.conn.Close()
				}
				if i < len(slots) {
					slots[i]()
				}
			}
			if finish != nil {
				finish(false)
			}
		}()
	}
	var failures []error
	launchNext()
	for inFlight > 0 {
		select {
		case res := <-results:
			if err := ctx.Err(); err != nil {
				// Return promptly even if closing the just-completed socket blocks.
				results <- res
				drain(inFlight, extra, primaryFinish)
				return nil, err
			}
			if res.err == nil {
				if res.conn == nil {
					primaryFinish(false)
				} else if !primaryFinish(true) {
					results <- res
					drain(inFlight, extra, primaryFinish)
					return nil, cmp.Or(ctx.Err(), errDeviceRevoked)
				}
				drain(inFlight-1, extra, nil)
				return res.conn, nil
			}
			if res.conn != nil {
				_ = res.conn.Close()
			}
			inFlight--
			if n := len(extra); n > 0 {
				// The remaining attempts share the primary slot and n-1 extras.
				extra[n-1]()
				extra[n-1] = nil
				extra = extra[:n-1]
			}
			failures = append(failures, res.err)
			launchNext()
		case <-tick:
			launchNext()
		case <-ctx.Done():
			drain(inFlight, extra, primaryFinish)
			return nil, ctx.Err()
		}
	}
	primaryFinish(false)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.Join(failures...)
}

func (o *guardedParallelOutbound) ListenSerialNetworkPacket(ctx context.Context, destination M.Socksaddr, candidates []netip.Addr, _ *C.NetworkStrategy, _ []C.InterfaceType, _ []C.InterfaceType, _ time.Duration) (conn net.PacketConn, address netip.Addr, err error) {
	finish := overload.LeaseFromContext(ctx).StartDial()
	defer func() {
		finishOutboundDial(ctx, finish, &conn, &err)
		if err != nil {
			address = netip.Addr{}
		}
	}()
	addresses, err := o.allowedAddresses(ctx, N.NetworkUDP, destination, candidates)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	var failures []error
	for _, address := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, netip.Addr{}, err
		}
		candidate := M.SocksaddrFrom(address, destination.Port)
		conn, err := o.listenPacket(ctx, candidate)
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
	guard  func(string, M.Socksaddr) error
	policy *EgressPolicy
}

func (c *publicPacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	if err := c.guard(N.NetworkUDP, destination); err != nil {
		return 0, err
	}
	if !c.policy.Allows(destination.Addr) {
		return 0, errPrivateDestination
	}
	return c.PacketConn.WriteTo(payload, addr)
}
