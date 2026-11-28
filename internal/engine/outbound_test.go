// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"pipe/internal/overload"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type dialRecorder struct {
	adapter.Outbound
	got M.Socksaddr
}

func (d *dialRecorder) DialContext(_ context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	d.got = destination
	return nil, errors.New("recorded")
}

func TestProxyTiersSendTheRequestedName(t *testing.T) {
	address := M.ParseSocksaddrHostPort("2a03:2880:f10a:83:face:b00c:0:25de", 443)
	conn := func(protocol, domain string, destination M.Socksaddr) context.Context {
		return adapter.WithContext(t.Context(), &adapter.InboundContext{
			InboundType: C.TypeTun, Destination: destination, Protocol: protocol, Domain: domain,
		})
	}
	named := conn(C.ProtocolTLS, "www.example.com", address)
	name := M.ParseSocksaddrHostPort("www.example.com", 443)
	resolver := M.ParseSocksaddrHostPort("1.1.1.1", 443)
	// A SOCKS or TUN connection by name whose addresses the router looked up
	// for the user's IP rules: sing-box then dials each address.
	looked := adapter.WithContext(t.Context(), &adapter.InboundContext{
		InboundType: C.TypeMixed, Destination: name,
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.1"), address.Addr},
	})
	for _, tc := range []struct {
		label       string
		ctx         context.Context
		network     string
		destination M.Socksaddr
		want        M.Socksaddr
	}{
		{"TLS name", named, "tcp", address, name},
		{"plain HTTP Host keeps the address", conn(C.ProtocolHTTP, "www.example.com", address), "tcp", address, address},
		{"name looked up for IP rules", looked, "tcp", M.ParseSocksaddrHostPort("192.0.2.1", 443), name},
		{"name looked up, other address", looked, "tcp", M.ParseSocksaddrHostPort("203.0.113.7", 443), M.ParseSocksaddrHostPort("203.0.113.7", 443)},
		{"name looked up, other port", looked, "tcp", M.ParseSocksaddrHostPort("2a03:2880:f10a:83:face:b00c:0:25de", 80), M.ParseSocksaddrHostPort("2a03:2880:f10a:83:face:b00c:0:25de", 80)},
		{"UDP keeps the address", named, "udp", address, address},
		{"SOCKS keeps the chosen address", adapter.WithContext(t.Context(), &adapter.InboundContext{
			InboundType: C.TypeMixed, Destination: address, Protocol: C.ProtocolTLS, Domain: "www.example.com",
		}), "tcp", address, address},
		{"nothing sniffed", t.Context(), "tcp", address, address},
		{"cached name, no sniff", conn("", "www.example.com", address), "tcp", address, address},
		{"DNS query context", conn(C.ProtocolDNS, "www.example.com", address), "tcp", address, address},
		{"another dial (DoH) in a named context", named, "tcp", resolver, resolver},
		{"TLS without a name", conn(C.ProtocolTLS, "", address), "tcp", address, address},
		{"sniffed address", conn(C.ProtocolTLS, "203.0.113.9", address), "tcp", address, address},
		{"already a name", named, "tcp", M.ParseSocksaddrHostPort("other.example", 80), M.ParseSocksaddrHostPort("other.example", 80)},
	} {
		if got, err := requestedName(tc.ctx, tc.network, tc.destination); got != tc.want || err != nil {
			t.Errorf("%s: got %v (%v), want %v", tc.label, got, err, tc.want)
		}
	}

	// sing-box dials looked-up addresses one by one: only the first dials,
	// by name; the rest are skipped without a dial.
	if _, err := requestedName(looked, "tcp", address); !errors.Is(err, errNamedOnce) {
		t.Fatalf("second looked-up address: got %v, want errNamedOnce", err)
	}
	skipped := &dialRecorder{}
	if _, err := (&guardedOutbound{Outbound: skipped, guard: rejectQUIC, byName: true}).DialContext(looked, "tcp", address); !errors.Is(err, errNamedOnce) || skipped.got.IsValid() {
		t.Fatalf("slow tier dialed a second looked-up address: %v %v", err, skipped.got)
	}

	tier := &dialRecorder{}
	_, _ = (&guardedOutbound{Outbound: tier, guard: rejectQUIC, byName: true}).DialContext(named, "tcp", address)
	if tier.got != name {
		t.Fatalf("slow tier sent %v, want %v", tier.got, name)
	}
	// The server's own direct outbound dials exactly what it is given.
	direct := &dialRecorder{}
	_, _ = (&guardedOutbound{Outbound: direct, guard: func(string, M.Socksaddr) error { return nil }}).DialContext(named, "tcp", address)
	if direct.got != address {
		t.Fatalf("server direct dialed %v, want %v", direct.got, address)
	}
}

type parallelDialRecorder struct {
	dialRecorder
	parallelCalls   int
	parallelAddrs   []netip.Addr
	chosenAddress   netip.Addr
	peer            net.Conn
	packetAddresses []M.Socksaddr
	failFirst       func()
}

func (d *parallelDialRecorder) DialParallelNetwork(_ context.Context, _ string, _ M.Socksaddr, addresses []netip.Addr, _ *C.NetworkStrategy, _ []C.InterfaceType, _ []C.InterfaceType, _ time.Duration) (net.Conn, error) {
	d.parallelCalls++
	d.parallelAddrs = append([]netip.Addr(nil), addresses...)
	if d.failFirst != nil && d.parallelCalls == 1 {
		d.failFirst()
		return nil, errors.New("first candidate failed")
	}
	if len(addresses) == 0 {
		return nil, errors.New("parallel dial received no addresses")
	}
	d.chosenAddress = addresses[0]
	conn, peer := net.Pipe()
	d.peer = peer
	return conn, nil
}

func (d *parallelDialRecorder) ListenSerialNetworkPacket(_ context.Context, _ M.Socksaddr, _ []netip.Addr, _ *C.NetworkStrategy, _ []C.InterfaceType, _ []C.InterfaceType, _ time.Duration) (net.PacketConn, netip.Addr, error) {
	return nil, netip.Addr{}, errors.New("unexpected delegated packet listen")
}

func (d *parallelDialRecorder) ListenPacket(_ context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.packetAddresses = append(d.packetAddresses, destination)
	return &packetConnRecorder{}, nil
}

type packetConnRecorder struct{ net.PacketConn }

func (*packetConnRecorder) Close() error { return nil }

func (*packetConnRecorder) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}

func TestGuardedDirectParallelDialFiltersCandidates(t *testing.T) {
	guardCalls := 0
	guard := func(_ string, destination M.Socksaddr) error {
		guardCalls++
		if !PublicDestination(destination.Addr) {
			return errPrivateDestination
		}
		return nil
	}
	base := &parallelDialRecorder{}
	wrapped := newServerGuardedOutbound(base, guard, nil)
	parallel, ok := wrapped.(interface {
		DialParallelNetwork(context.Context, string, M.Socksaddr, []netip.Addr, *C.NetworkStrategy, []C.InterfaceType, []C.InterfaceType, time.Duration) (net.Conn, error)
	})
	if !ok {
		t.Fatal("server guard hid the base outbound's parallel dialer")
	}
	public4 := netip.MustParseAddr("8.8.8.8")
	public6 := netip.MustParseAddr("2001:4860:4860::8888")
	policy := NewEgressPolicy()
	policy.interfaces = func() ([]net.Addr, error) { return nil, nil }
	ctx := WithEgressPolicy(t.Context(), policy)
	conn, err := parallel.DialParallelNetwork(ctx, "tcp", M.Socksaddr{Fqdn: "example.com", Port: 443}, []netip.Addr{
		netip.MustParseAddr("10.0.0.1"), public4, public6,
	}, nil, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if conn == nil {
		t.Fatal("parallel outbound did not connect")
	}
	defer conn.Close()
	defer base.peer.Close()
	if guardCalls != 3 {
		t.Fatalf("guard checked %d candidates, want all 3", guardCalls)
	}
	if base.parallelCalls != 1 || !slices.Equal(base.parallelAddrs, []netip.Addr{public4}) {
		t.Fatalf("parallel dial got %v in %d calls", base.parallelAddrs, base.parallelCalls)
	}
	if base.chosenAddress != public4 {
		t.Fatalf("connected through %s, want first public candidate %s", base.chosenAddress, public4)
	}
}

func TestGuardedDirectParallelDialRechecksDelayedCandidate(t *testing.T) {
	public4 := netip.MustParseAddr("8.8.8.8")
	public6 := netip.MustParseAddr("2001:4860:4860::8888")
	localNow := false
	policy := NewEgressPolicy()
	policy.interfaces = func() ([]net.Addr, error) {
		if localNow {
			return []net.Addr{&net.IPNet{IP: public6.AsSlice(), Mask: net.CIDRMask(128, 128)}}, nil
		}
		return nil, nil
	}
	base := &parallelDialRecorder{
		failFirst: func() { localNow = true },
	}
	wrapped := newServerGuardedOutbound(base, func(_ string, destination M.Socksaddr) error {
		return publicDestination(destination)
	}, nil)
	parallel := wrapped.(interface {
		DialParallelNetwork(context.Context, string, M.Socksaddr, []netip.Addr, *C.NetworkStrategy, []C.InterfaceType, []C.InterfaceType, time.Duration) (net.Conn, error)
	})
	ctx := WithEgressPolicy(t.Context(), policy)
	if _, err := parallel.DialParallelNetwork(ctx, "tcp", M.Socksaddr{Fqdn: "example.com", Port: 443}, []netip.Addr{public4, public6}, nil, nil, nil, 0); err == nil {
		t.Fatal("delayed candidate that became local was dialed")
	}
	if base.parallelCalls != 1 || !slices.Equal(base.parallelAddrs, []netip.Addr{public4}) {
		t.Fatalf("delayed local candidate reached dialer: %v (%d calls)", base.parallelAddrs, base.parallelCalls)
	}
}

func TestGuardedDirectParallelDialRejectsAllCandidates(t *testing.T) {
	base := &parallelDialRecorder{}
	wrapped := newServerGuardedOutbound(base, func(_ string, destination M.Socksaddr) error {
		return publicDestination(destination)
	}, nil)
	parallel := wrapped.(interface {
		DialParallelNetwork(context.Context, string, M.Socksaddr, []netip.Addr, *C.NetworkStrategy, []C.InterfaceType, []C.InterfaceType, time.Duration) (net.Conn, error)
	})
	_, err := parallel.DialParallelNetwork(t.Context(), "tcp", M.Socksaddr{Fqdn: "example.com", Port: 443}, []netip.Addr{
		netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::1"),
	}, nil, nil, nil, 0)
	if err == nil {
		t.Fatal("all rejected candidates returned no error")
	}
	if base.parallelCalls != 0 {
		t.Fatalf("parallel dial ran %d times for rejected candidates", base.parallelCalls)
	}
}

func TestServerEgressRejectsLocalAndConfiguredCandidates(t *testing.T) {
	base := &parallelDialRecorder{}
	wrapped := newServerGuardedOutbound(base, func(_ string, destination M.Socksaddr) error {
		return publicDestination(destination)
	}, nil).(*guardedParallelOutbound)
	policy := NewEgressPolicy(netip.MustParseAddr("11.2.3.4"))
	policy.interfaces = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.IPv4(11, 9, 8, 7), Mask: net.CIDRMask(24, 32)}}, nil
	}
	ctx := WithEgressPolicy(t.Context(), policy)
	dst := M.Socksaddr{Fqdn: "fixture.example", Port: 443}
	blocked := []netip.Addr{netip.MustParseAddr("::ffff:11.2.3.4"), netip.MustParseAddr("64:ff9b::b09:807")}
	if conn, err := wrapped.DialParallelNetwork(ctx, "tcp", dst, blocked, nil, nil, nil, 0); err == nil {
		conn.Close()
		base.peer.Close()
		t.Fatal("restricted address reached the fixture dialer")
	}
	if conn, _, err := wrapped.ListenSerialNetworkPacket(ctx, dst, blocked, nil, nil, nil, 0); err == nil {
		conn.Close()
		t.Fatal("restricted address reached the fixture packet socket")
	}
	if base.parallelCalls != 0 || len(base.packetAddresses) != 0 {
		t.Fatal("restricted addresses should never be dialed")
	}
}

func TestEgressPolicyCachesInterfaceLookups(t *testing.T) {
	policy := NewEgressPolicy()
	loads := 0
	policy.interfaces = func() ([]net.Addr, error) {
		loads++
		return nil, nil
	}
	for range 20 {
		if !policy.Allows(netip.MustParseAddr("11.0.0.80")) {
			t.Fatal("the fixture's external address was blocked")
		}
	}
	if loads != 1 {
		t.Fatalf("interface enumerations = %d, want 1", loads)
	}
}

func TestServerEgressInterfaceUpdateInvalidatesCache(t *testing.T) {
	address := netip.MustParseAddr("11.0.0.80")
	policy := NewEgressPolicy()
	now := time.Now()
	policy.now = func() time.Time { return now }
	var addresses []net.Addr
	policy.interfaces = func() ([]net.Addr, error) { return addresses, nil }
	if !policy.Allows(address) {
		t.Fatal("initial nonlocal address was blocked")
	}
	addresses = []net.Addr{&net.IPAddr{IP: address.AsSlice()}}
	out := &guardedOutbound{Outbound: new(dialRecorder), serverPolicy: policy, restrictPackets: true}
	out.InterfaceUpdated(t.Context())
	if policy.Allows(address) {
		t.Fatal("interface update left the previous address snapshot in use")
	}
}

func TestServerEgressFreshTCPKeepsUDPCached(t *testing.T) {
	address := netip.MustParseAddr("11.0.0.80")
	destination := M.SocksaddrFrom(address, 80)
	policy := NewEgressPolicy()
	now := time.Now()
	policy.now = func() time.Time { return now }
	var addresses []net.Addr
	loads := 0
	policy.interfaces = func() ([]net.Addr, error) {
		loads++
		return addresses, nil
	}
	base := new(parallelDialRecorder)
	out := newServerGuardedOutbound(base, func(_ string, destination M.Socksaddr) error {
		return publicDestination(destination)
	}, nil).(*guardedParallelOutbound)
	out.routeCheck = func(context.Context, M.Socksaddr) error { return nil }
	ctx := WithEgressPolicy(t.Context(), policy)
	packets, err := out.ListenPacket(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	addresses = []net.Addr{&net.IPAddr{IP: address.AsSlice()}}
	payload := []byte("datagram")
	if n, err := packets.WriteTo(payload, destination.UDPAddr()); n != len(payload) || err != nil {
		t.Fatalf("UDP stopped using the cached snapshot: %d, %v", n, err)
	}
	if _, err := out.DialContext(ctx, "tcp", destination); !errors.Is(err, errPrivateDestination) || base.got.IsValid() {
		t.Fatalf("TCP dial used the cached snapshot: %v", err)
	}
	external := netip.MustParseAddr("11.0.0.81")
	name := M.Socksaddr{Fqdn: "fixture.example", Port: 80}
	conn, err := out.DialParallelNetwork(ctx, "tcp", name, []netip.Addr{address, external}, nil, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	base.peer.Close()
	if !slices.Equal(base.parallelAddrs, []netip.Addr{external}) {
		t.Fatalf("parallel TCP dial got %v, want %v", base.parallelAddrs, external)
	}
	if _, err := packets.WriteTo(payload, destination.UDPAddr()); err != nil || loads != 3 {
		t.Fatalf("want one interface scan per TCP dial and one for UDP, got %d scans and %v", loads, err)
	}
	now = now.Add(egressRefreshInterval)
	if _, err := packets.WriteTo(payload, destination.UDPAddr()); !errors.Is(err, errPrivateDestination) {
		t.Fatalf("UDP missed the new address after cache expiry: %v", err)
	}
}

func TestServerEgressPolicySurvivesRequestContextReplacement(t *testing.T) {
	address := netip.MustParseAddr("11.0.0.81")
	policy := NewEgressPolicy(address)
	base := new(dialRecorder)
	out := newServerGuardedOutbound(base, func(_ string, destination M.Socksaddr) error {
		return publicDestination(destination)
	}, nil).(*guardedOutbound)
	scope := adapter.NewScope(WithEgressPolicy(t.Context(), policy), nil)
	defer scope.Close()
	if err := out.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	requestPolicy := NewEgressPolicy()
	requestPolicy.interfaces = func() ([]net.Addr, error) { return nil, nil }
	request := WithEgressPolicy(t.Context(), requestPolicy)
	_, err := out.DialContext(request, "tcp", M.SocksaddrFrom(address, 443))
	if !errors.Is(err, errPrivateDestination) || base.got.IsValid() {
		t.Fatalf("outbound lost its startup policy when the request context changed: %v", err)
	}
}

func TestEgressPolicyRefreshesAndFailsClosed(t *testing.T) {
	policy := NewEgressPolicy()
	now := time.Now()
	policy.now = func() time.Time { return now }
	destination := netip.MustParseAddr("11.0.0.80")
	ifAddrs := []net.Addr{}
	var loadErr error
	policy.interfaces = func() ([]net.Addr, error) { return ifAddrs, loadErr }
	if !policy.Allows(destination) {
		t.Fatal("initial nonlocal address was blocked")
	}
	anycast := netip.MustParseAddr("11.0.0.82")
	ifAddrs = []net.Addr{
		&net.IPNet{IP: destination.AsSlice(), Mask: net.CIDRMask(32, 32)},
		&net.IPAddr{IP: anycast.AsSlice()},
	}
	now = now.Add(egressRefreshInterval)
	if policy.Allows(destination) || policy.Allows(anycast) {
		t.Fatal("refreshed set missed a new interface address")
	}
	loadErr = errors.New("interface loader failed")
	now = now.Add(egressRefreshInterval)
	external := netip.MustParseAddr("11.0.0.81")
	if policy.Allows(external) {
		t.Fatal("a failed refresh allowed forwarding")
	}
	loadErr = nil
	now = now.Add(egressRefreshInterval)
	if !policy.Allows(external) {
		t.Fatal("a successful refresh did not restore forwarding")
	}
}

func TestGuardedDirectPacketSkipsUnroutableAddress(t *testing.T) {
	v4 := netip.MustParseAddr("8.8.8.8")
	v6 := netip.MustParseAddr("2001:4860:4860::8888")
	unreachable := errors.New("network is unreachable")
	var routeChecks []netip.Addr
	base := &parallelDialRecorder{}
	wrapped := newServerGuardedOutbound(base, func(_ string, destination M.Socksaddr) error {
		return publicDestination(destination)
	}, nil).(*guardedParallelOutbound)
	wrapped.routeCheck = func(_ context.Context, destination M.Socksaddr) error {
		routeChecks = append(routeChecks, destination.Addr)
		if destination.Addr == v4 {
			return unreachable
		}
		return nil
	}
	policy := NewEgressPolicy()
	policy.interfaces = func() ([]net.Addr, error) { return nil, nil }
	ctx := WithEgressPolicy(t.Context(), policy)
	conn, destination, err := wrapped.ListenSerialNetworkPacket(ctx, M.Socksaddr{Fqdn: "example.com", Port: 53}, []netip.Addr{v4, v6}, nil, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if conn == nil || destination != v6 {
		t.Fatalf("got packet connection %v for %v, want IPv6 %v", conn, destination, v6)
	}
	if !slices.Equal(routeChecks, []netip.Addr{v4, v6}) {
		t.Fatalf("route checks were %v", routeChecks)
	}
	if len(base.packetAddresses) != 1 || base.packetAddresses[0].Addr != v6 {
		t.Fatalf("packet socket destinations were %v, want only %v", base.packetAddresses, v6)
	}
}

type overloadOutboundRecorder struct {
	parallelDialRecorder
	dial    func(netip.Addr) error
	newConn func(netip.Addr) net.Conn
	listen  func(netip.Addr) error
}

func (d *overloadOutboundRecorder) DialContext(_ context.Context, _ string, dest M.Socksaddr) (net.Conn, error) {
	if err := d.dial(dest.Addr); err != nil {
		return nil, err
	}
	if d.newConn != nil {
		return d.newConn(dest.Addr), nil
	}
	conn, peer := net.Pipe()
	_ = peer.Close()
	return conn, nil
}

func (d *overloadOutboundRecorder) DialParallelNetwork(ctx context.Context, network string, dest M.Socksaddr, addresses []netip.Addr, _ *C.NetworkStrategy, _ []C.InterfaceType, _ []C.InterfaceType, _ time.Duration) (net.Conn, error) {
	return d.DialContext(ctx, network, M.SocksaddrFrom(addresses[0], dest.Port))
}

func (d *overloadOutboundRecorder) ListenPacket(_ context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	if err := d.listen(dest.Addr); err != nil {
		return nil, err
	}
	return &packetConnRecorder{}, nil
}

func admissionDialContext(t *testing.T, guard *overload.Guard) context.Context {
	t.Helper()
	lease, err := guard.Acquire(t.Context(), overload.ClassFlow)
	requireSessionOK(t, err)
	t.Cleanup(lease.Release)
	policy := NewEgressPolicy()
	policy.interfaces = func() ([]net.Addr, error) { return nil, nil }
	return WithEgressPolicy(overload.WithLease(t.Context(), lease), policy)
}

func TestOutboundAdmissionReservationRetiresOnReturn(t *testing.T) {
	for _, operation := range []struct {
		name string
		call func(*guardedParallelOutbound, context.Context, M.Socksaddr) (io.Closer, error)
	}{
		{"direct dial", func(o *guardedParallelOutbound, ctx context.Context, dest M.Socksaddr) (io.Closer, error) {
			return o.DialContext(ctx, "tcp", dest)
		}},
		{"parallel dial", func(o *guardedParallelOutbound, ctx context.Context, dest M.Socksaddr) (io.Closer, error) {
			return o.DialParallelNetwork(ctx, "tcp", dest, []netip.Addr{dest.Addr}, nil, nil, nil, 0)
		}},
		{"direct packet listen", func(o *guardedParallelOutbound, ctx context.Context, dest M.Socksaddr) (io.Closer, error) {
			return o.ListenPacket(ctx, dest)
		}},
		{"serial packet listen", func(o *guardedParallelOutbound, ctx context.Context, dest M.Socksaddr) (io.Closer, error) {
			conn, _, err := o.ListenSerialNetworkPacket(ctx, dest, []netip.Addr{dest.Addr}, nil, nil, nil, 0)
			return conn, err
		}},
	} {
		for _, outcome := range []struct {
			name      string
			err       error
			emergency bool
		}{
			{"success", nil, false},
			{"dial failure", errors.New("fixture failure"), false},
			{"FD exhaustion", &net.OpError{Op: "socket", Err: syscall.EMFILE}, true},
		} {
			t.Run(operation.name+"/"+outcome.name, func(t *testing.T) {
				g := overload.New(overload.Options{})
				defer g.Close()
				g.RecordSample(overload.Snapshot{OpenFDs: 83, MaxFDs: 100})
				ctx := admissionDialContext(t, g)
				attempt := func(netip.Addr) error {
					if d := g.Diagnostics(); d.PendingDials != 1 {
						t.Errorf("attempt did not retain its dial reservation: %+v", d)
					}
					return outcome.err
				}
				base := &overloadOutboundRecorder{dial: attempt, listen: attempt}
				out := newServerGuardedOutbound(base, func(string, M.Socksaddr) error { return nil }, g).(*guardedParallelOutbound)
				out.routeCheck = func(context.Context, M.Socksaddr) error { return nil }
				conn, err := operation.call(out, ctx, M.SocksaddrFrom(netip.MustParseAddr("8.8.4.4"), 53))
				if conn != nil {
					defer conn.Close()
				}
				if !errors.Is(err, outcome.err) {
					t.Fatalf("dial returned %v, want %v", err, outcome.err)
				}
				var wantUnmeasured int64
				if outcome.err == nil {
					wantUnmeasured = 1
				}
				if d := g.Diagnostics(); d.PendingDials != 0 || d.ActiveFlows != 1 || d.UnmeasuredFDs != wantUnmeasured || d.Emergency != outcome.emergency {
					t.Fatalf("invalid lease or pressure after dial: %+v", d)
				}
				retry, err := g.Acquire(t.Context(), overload.ClassFlow)
				defer retry.Release()
				if outcome.err == nil || outcome.emergency {
					if !errors.Is(err, overload.ErrOverloaded) {
						t.Fatalf("admission reused unavailable headroom: %v", err)
					}
				} else {
					requireSessionOK(t, err)
				}
			})
		}
	}
}

func TestOutboundAdmissionKeepsReservationAcrossCandidates(t *testing.T) {
	first := netip.MustParseAddr("2001:4860:4860::8888")
	second := netip.MustParseAddr("8.8.8.8")
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			g := overload.New(overload.Options{})
			defer g.Close()
			ctx := admissionDialContext(t, g)
			var attempts atomic.Int32
			attempt := func(addr netip.Addr) error {
				attempts.Add(1)
				d := g.Diagnostics()
				if d.PendingDials != 1 || (addr == second && !d.Emergency) {
					t.Errorf("invalid reservation or pressure at %s: %+v", addr, d)
				}
				if addr == first {
					return syscall.ENFILE
				}
				return nil
			}
			base := &overloadOutboundRecorder{dial: attempt, listen: attempt}
			out := newServerGuardedOutbound(base, func(string, M.Socksaddr) error { return nil }, g).(*guardedParallelOutbound)
			out.routeCheck = func(context.Context, M.Socksaddr) error { return nil }
			dest := M.Socksaddr{Fqdn: "fixture.invalid", Port: 53}
			candidates := []netip.Addr{first, second}
			if network == "tcp" {
				conn, err := out.DialParallelNetwork(ctx, network, dest, candidates, nil, nil, nil, time.Hour)
				requireSessionOK(t, err)
				requireSessionOK(t, conn.Close())
			} else {
				conn, addr, err := out.ListenSerialNetworkPacket(ctx, dest, candidates, nil, nil, nil, 0)
				requireSessionOK(t, err)
				requireSessionOK(t, conn.Close())
				if addr != second {
					t.Fatalf("packet listen selected %s, want %s", addr, second)
				}
			}
			if d := g.Diagnostics(); attempts.Load() != 2 || d.PendingDials != 0 || d.UnmeasuredFDs != 1 || !d.Emergency {
				t.Fatalf("candidate attempts=%d, %+v", attempts.Load(), d)
			}
		})
	}
}

func TestOutboundAdmissionChargesConcurrentAttempts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := overload.New(overload.Options{})
		defer g.Close()
		ctx := admissionDialContext(t, g)
		const delay = time.Millisecond
		failure := errors.New("fixture dial failure")
		unblock := make(chan struct{}, 2)
		defer close(unblock)
		var attempts atomic.Int32
		base := &overloadOutboundRecorder{dial: func(netip.Addr) error {
			attempts.Add(1)
			<-unblock
			return failure
		}}
		out := newServerGuardedOutbound(base, func(string, M.Socksaddr) error { return nil }, g).(*guardedParallelOutbound)
		result := make(chan error, 1)
		go func() {
			dest := M.Socksaddr{Fqdn: "fixture.invalid", Port: 443}
			candidates := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}
			_, err := out.DialParallelNetwork(ctx, "tcp", dest, candidates, nil, nil, nil, delay)
			result <- err
		}()
		synctest.Wait()
		if d := g.Diagnostics(); attempts.Load() != 1 || d.PendingDials != 1 {
			t.Fatalf("initial attempt reservation: attempts=%d, %+v", attempts.Load(), d)
		}
		time.Sleep(delay)
		synctest.Wait()
		if d := g.Diagnostics(); attempts.Load() != 2 || d.PendingDials != 2 {
			t.Fatalf("overlapping attempts did not each reserve a dial: attempts=%d, %+v", attempts.Load(), d)
		}
		unblock <- struct{}{}
		synctest.Wait()
		if d := g.Diagnostics(); d.PendingDials != 1 {
			t.Fatalf("one remaining attempt did not inherit the primary slot: %+v", d)
		}
		unblock <- struct{}{}
		if err := <-result; !errors.Is(err, failure) {
			t.Fatalf("parallel dial returned %v", err)
		}
		if d := g.Diagnostics(); d.PendingDials != 0 || d.UnmeasuredFDs != 0 {
			t.Fatalf("failed attempts retained FD charges: %+v", d)
		}
	})
}

func TestOutboundAdmissionSerialFallbackKeepsLastSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := overload.New(overload.Options{})
		defer g.Close()
		g.RecordSample(overload.Snapshot{OpenFDs: 83, MaxFDs: 100})
		ctx := admissionDialContext(t, g)
		first, second := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")
		unblock := make(chan struct{})
		release := sync.OnceFunc(func() { close(unblock) })
		defer release()
		var attempts atomic.Int32
		base := &overloadOutboundRecorder{dial: func(addr netip.Addr) error {
			attempts.Add(1)
			if addr == first {
				<-unblock
				return errors.New("first candidate failed")
			}
			if d := g.Diagnostics(); d.PendingDials != 1 {
				t.Errorf("serial fallback did not reuse the primary slot: %+v", d)
			}
			return nil
		}}
		out := newServerGuardedOutbound(base, func(string, M.Socksaddr) error { return nil }, g).(*guardedParallelOutbound)
		const delay = time.Millisecond
		result := make(chan error, 1)
		go func() {
			dest := M.Socksaddr{Fqdn: "fixture.invalid", Port: 443}
			conn, err := out.DialParallelNetwork(ctx, "tcp", dest, []netip.Addr{first, second}, nil, nil, nil, delay)
			if conn != nil {
				_ = conn.Close()
			}
			result <- err
		}()
		synctest.Wait()
		time.Sleep(delay)
		synctest.Wait()
		if d := g.Diagnostics(); attempts.Load() != 1 || d.PendingDials != 1 {
			t.Fatalf("fallback spent reserved headroom: attempts=%d, %+v", attempts.Load(), d)
		}
		release()
		requireSessionOK(t, <-result)
		if d := g.Diagnostics(); attempts.Load() != 2 || d.PendingDials != 0 || d.UnmeasuredFDs != 1 {
			t.Fatalf("serial fallback did not complete: attempts=%d, %+v", attempts.Load(), d)
		}
	})
}

func TestOutboundAdmissionKeepsChargesThroughParallelCleanup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
	}{{"winner", false}, {"cancellation", true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := overload.New(overload.Options{})
				defer g.Close()
				ctx, cancel := context.WithCancel(admissionDialContext(t, g))
				defer cancel()
				first, second := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")
				firstDone, secondDone, closeDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
				finishFirst := sync.OnceFunc(func() { close(firstDone) })
				finishSecond := sync.OnceFunc(func() { close(secondDone) })
				finishClose := sync.OnceFunc(func() { close(closeDone) })
				defer finishFirst()
				defer finishSecond()
				defer finishClose()
				closing := make(chan struct{})
				base := &overloadOutboundRecorder{
					dial: func(addr netip.Addr) error {
						if addr == first {
							<-firstDone
						} else {
							<-secondDone
						}
						return nil
					},
					newConn: func(addr netip.Addr) net.Conn {
						conn, peer := net.Pipe()
						_ = peer.Close()
						if addr == first {
							return &closeHookSessionConn{Conn: conn, beforeClose: func() {
								close(closing)
								<-closeDone
							}}
						}
						return conn
					},
				}
				out := newServerGuardedOutbound(base, func(string, M.Socksaddr) error { return nil }, g).(*guardedParallelOutbound)
				const delay = time.Millisecond
				type dialResult struct {
					conn net.Conn
					err  error
				}
				result := make(chan dialResult, 1)
				go func() {
					dest := M.Socksaddr{Fqdn: "fixture.invalid", Port: 443}
					conn, err := out.DialParallelNetwork(ctx, "tcp", dest, []netip.Addr{first, second}, nil, nil, nil, delay)
					result <- dialResult{conn, err}
				}()
				synctest.Wait()
				time.Sleep(delay)
				synctest.Wait()
				if d := g.Diagnostics(); d.PendingDials != 2 {
					t.Fatalf("expected two outstanding attempts: %+v", d)
				}
				var wantErr error
				var pending, unmeasured int64 = 1, 1
				if tc.cancel {
					cancel()
					wantErr, pending, unmeasured = context.Canceled, 2, 0
				} else {
					finishSecond()
				}
				res := <-result
				if res.conn != nil {
					defer res.conn.Close()
				}
				if !errors.Is(res.err, wantErr) || (res.conn == nil) != tc.cancel {
					t.Fatalf("parallel dial returned socket=%t, err=%v, want err=%v", res.conn != nil, res.err, wantErr)
				}
				if d := g.Diagnostics(); d.PendingDials != pending || d.UnmeasuredFDs != unmeasured {
					t.Fatalf("return released outstanding attempts too soon: %+v", d)
				}
				finishFirst()
				synctest.Wait()
				select {
				case <-closing:
				default:
					t.Fatal("cleanup did not start closing the late socket")
				}
				if d := g.Diagnostics(); d.PendingDials != pending {
					t.Fatalf("socket lost its charge during close: %+v", d)
				}
				finishClose()
				synctest.Wait()
				if d := g.Diagnostics(); d.PendingDials != pending-1 {
					t.Fatalf("socket close did not release its charge: %+v", d)
				}
				finishSecond()
				synctest.Wait()
				if d := g.Diagnostics(); d.PendingDials != 0 || d.UnmeasuredFDs != unmeasured {
					t.Fatalf("cleanup left unexpected reservations: %+v", d)
				}
			})
		})
	}
}

func TestOutboundAdmissionRevocationKeepsStartedDialCharged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := overload.New(overload.Options{})
		defer g.Close()
		g.RecordSample(overload.Snapshot{OpenFDs: 83, MaxFDs: 100})
		unblock := make(chan struct{})
		finishDial := sync.OnceFunc(func() { close(unblock) })
		defer finishDial()
		lateSocket, latePeer := net.Pipe()
		defer latePeer.Close()
		defer lateSocket.Close()
		base := &overloadOutboundRecorder{
			dial:    func(netip.Addr) error { <-unblock; return nil },
			newConn: func(netip.Addr) net.Conn { return lateSocket },
		}
		out := newServerGuardedOutbound(base, func(string, M.Socksaddr) error { return nil }, g)
		sessions := newDeviceSessions([]string{"device"}, g)
		result := make(chan error, 1)
		router := sessions.wrapRouter(&sessionTestRouter{tcp: func(ctx context.Context, _ net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
			addr := M.SocksaddrFrom(netip.MustParseAddr("1.1.1.1"), 443)
			conn, err := out.DialContext(ctx, "tcp", addr)
			if conn != nil {
				t.Error("revoked dial returned a socket")
				_ = conn.Close()
			}
			onClose(err)
		}})
		policy := NewEgressPolicy()
		policy.interfaces = func() ([]net.Addr, error) { return nil, nil }
		incoming, peer := net.Pipe()
		defer incoming.Close()
		defer peer.Close()
		requireSessionOK(t, latePeer.SetReadDeadline(time.Now().Add(time.Second)))
		go router.RouteConnectionEx(WithEgressPolicy(t.Context(), policy), incoming, adapter.InboundContext{User: "device"}, func(err error) { result <- err })
		synctest.Wait()
		sessions.allow(nil)
		if d := g.Diagnostics(); d.ActiveFlows != 0 || d.PendingDials != 1 {
			t.Fatalf("revocation released an unwinding dial: %+v", d)
		}
		replacement, err := g.Acquire(t.Context(), overload.ClassFlow)
		defer replacement.Release()
		if !errors.Is(err, overload.ErrOverloaded) {
			t.Fatalf("replacement got the unwinding dial's slot: %v", err)
		}
		finishDial()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("revoked dial returned %v", err)
		}
		if _, err := latePeer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("revoked dial did not close its late socket: %v", err)
		}
		if d := g.Diagnostics(); d.PendingDials != 0 || d.UnmeasuredFDs != 0 {
			t.Fatalf("revoked dial retained a charge after cleanup: %+v", d)
		}
	})
}

type revokeAtDialCompletion struct {
	context.Context
	lease *overload.Lease
	armed atomic.Bool
}

func (ctx *revokeAtDialCompletion) Err() error {
	err := ctx.Context.Err()
	if ctx.armed.Swap(false) {
		ctx.lease.Release()
	}
	return err
}

func TestOutboundAdmissionRevocationWinsDialCompletion(t *testing.T) {
	for _, mode := range []string{"direct", "parallel"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := overload.New(overload.Options{})
				defer g.Close()
				g.RecordSample(overload.Snapshot{OpenFDs: 83, MaxFDs: 100})
				parent := admissionDialContext(t, g)
				ctx := &revokeAtDialCompletion{Context: parent, lease: overload.LeaseFromContext(parent)}
				conn, peer := net.Pipe()
				defer conn.Close()
				defer peer.Close()
				requireSessionOK(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
				closing, unblock := make(chan struct{}), make(chan struct{})
				unblockClose := sync.OnceFunc(func() { close(unblock) })
				defer unblockClose()
				socket := &closeHookSessionConn{Conn: conn, beforeClose: func() {
					close(closing)
					<-unblock
				}}
				base := &overloadOutboundRecorder{
					dial: func(netip.Addr) error { return nil },
					newConn: func(netip.Addr) net.Conn {
						// Release after the outbound reads a live context at completion.
						ctx.armed.Store(true)
						return socket
					},
				}
				out := newServerGuardedOutbound(base, func(string, M.Socksaddr) error { return nil }, g).(*guardedParallelOutbound)
				type dialResult struct {
					conn net.Conn
					err  error
				}
				done := make(chan dialResult, 1)
				go func() {
					first, second := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")
					dest := M.SocksaddrFrom(first, 443)
					if mode == "parallel" {
						conn, err := out.DialParallelNetwork(ctx, "tcp", dest, []netip.Addr{first, second}, nil, nil, nil, time.Hour)
						done <- dialResult{conn, err}
						return
					}
					conn, err := out.DialContext(ctx, "tcp", dest)
					done <- dialResult{conn, err}
				}()
				synctest.Wait()
				select {
				case <-closing:
				default:
					t.Fatal("revoked socket did not start closing")
				}
				if d := g.Diagnostics(); d.ActiveFlows != 0 || d.PendingDials != 1 || d.UnmeasuredFDs != 0 {
					t.Fatalf("revoked socket lost its reservation during close: %+v", d)
				}
				unblockClose()
				res := <-done
				if res.conn != nil || !errors.Is(res.err, errDeviceRevoked) {
					t.Fatalf("revoked dial returned socket=%t, error=%v", res.conn != nil, res.err)
				}
				synctest.Wait()
				if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("revoked socket stayed open: %v", err)
				}
				if d := g.Diagnostics(); d.PendingDials != 0 || d.UnmeasuredFDs != 0 {
					t.Fatalf("closed socket retained its reservation: %+v", d)
				}
			})
		})
	}
}

func TestPublicDestinationNAT64WellKnownPrefix(t *testing.T) {
	for _, tc := range []struct {
		address string
		public  bool
	}{
		{"64:ff9b::808:808", true},
		{"64:ff9b::a00:1", false},
		{"64:ff9b::7f00:1", false},
		{"64:ff9b:1::808:808", false},
	} {
		if got := PublicDestination(netip.MustParseAddr(tc.address)); got != tc.public {
			t.Errorf("PublicDestination(%s) = %t, want %t", tc.address, got, tc.public)
		}
	}
}
