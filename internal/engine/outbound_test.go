// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
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
}

func (d *parallelDialRecorder) DialParallelNetwork(_ context.Context, _ string, _ M.Socksaddr, addresses []netip.Addr, _ *C.NetworkStrategy, _ []C.InterfaceType, _ []C.InterfaceType, _ time.Duration) (net.Conn, error) {
	d.parallelCalls++
	d.parallelAddrs = append([]netip.Addr(nil), addresses...)
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
	wrapped := newServerGuardedOutbound(base, guard)
	parallel, ok := wrapped.(interface {
		DialParallelNetwork(context.Context, string, M.Socksaddr, []netip.Addr, *C.NetworkStrategy, []C.InterfaceType, []C.InterfaceType, time.Duration) (net.Conn, error)
	})
	if !ok {
		t.Fatal("server guard hid the base outbound's parallel dialer")
	}
	public4 := netip.MustParseAddr("8.8.8.8")
	public6 := netip.MustParseAddr("2001:4860:4860::8888")
	conn, err := parallel.DialParallelNetwork(t.Context(), "tcp", M.Socksaddr{Fqdn: "example.com", Port: 443}, []netip.Addr{
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
	if base.parallelCalls != 1 || !slices.Equal(base.parallelAddrs, []netip.Addr{public4, public6}) {
		t.Fatalf("parallel dial got %v in %d calls", base.parallelAddrs, base.parallelCalls)
	}
	if base.chosenAddress != public4 {
		t.Fatalf("connected through %s, want first public candidate %s", base.chosenAddress, public4)
	}
}

func TestGuardedDirectParallelDialRejectsAllCandidates(t *testing.T) {
	base := &parallelDialRecorder{}
	wrapped := newServerGuardedOutbound(base, func(_ string, destination M.Socksaddr) error {
		return publicDestination(destination)
	})
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

func TestGuardedDirectPacketSkipsUnroutableAddress(t *testing.T) {
	v4 := netip.MustParseAddr("8.8.8.8")
	v6 := netip.MustParseAddr("2001:4860:4860::8888")
	unreachable := errors.New("network is unreachable")
	var routeChecks []netip.Addr
	base := &parallelDialRecorder{}
	wrapped := newServerGuardedOutbound(base, func(_ string, destination M.Socksaddr) error {
		return publicDestination(destination)
	}).(*guardedParallelOutbound)
	wrapped.routeCheck = func(_ context.Context, destination M.Socksaddr) error {
		routeChecks = append(routeChecks, destination.Addr)
		if destination.Addr == v4 {
			return unreachable
		}
		return nil
	}
	conn, destination, err := wrapped.ListenSerialNetworkPacket(t.Context(), M.Socksaddr{Fqdn: "example.com", Port: 53}, []netip.Addr{v4, v6}, nil, nil, nil, 0)
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
