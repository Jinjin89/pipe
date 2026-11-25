// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type lanTestDialer struct {
	mu          sync.Mutex
	truncateUDP bool
	network     []string
	addrs       []netip.AddrPort
}

func (d *lanTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.mu.Lock()
	d.network = append(d.network, network)
	d.addrs = append(d.addrs, destination.AddrPort())
	d.mu.Unlock()
	client, server := net.Pipe()
	go d.serve(server, network)
	return client, nil
}

func (d *lanTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, io.ErrClosedPipe
}

func (d *lanTestDialer) serve(conn net.Conn, network string) {
	defer conn.Close()
	var packet []byte
	if network == "tcp" {
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		packet = make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, packet); err != nil {
			return
		}
	} else {
		packet = make([]byte, 2048)
		n, err := conn.Read(packet)
		if err != nil {
			return
		}
		packet = packet[:n]
	}
	var query dns.Msg
	if query.Unpack(packet) != nil {
		return
	}
	response := new(dns.Msg).SetReply(&query)
	if network == "udp" && d.truncateUDP {
		response.Truncated = true
	} else {
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.8")}}
	}
	packet, err := response.Pack()
	if err != nil {
		return
	}
	if network == "tcp" {
		frame := make([]byte, 2+len(packet))
		binary.BigEndian.PutUint16(frame, uint16(len(packet)))
		copy(frame[2:], packet)
		packet = frame
	}
	_, _ = conn.Write(packet)
}

type cancelLANDialer struct {
	cancel context.CancelFunc
	calls  atomic.Int32
}

func (d *cancelLANDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	d.calls.Add(1)
	d.cancel()
	return nil, io.ErrClosedPipe
}
func (*cancelLANDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, io.ErrClosedPipe
}

func TestLANDNSForwardsAndRetriesTruncatedUDPOverTCP(t *testing.T) {
	server := netip.MustParseAddrPort("192.168.1.1:53")
	tunnel := netip.MustParseAddrPort("223.5.5.5:53")
	self := netip.MustParseAddrPort("172.19.0.1:53")
	selfDNS := netip.MustParseAddrPort("172.19.0.2:53")
	dialer := &lanTestDialer{truncateUDP: true}
	exclude := []netip.Prefix{netip.MustParsePrefix("172.19.0.0/30"), netip.MustParsePrefix("fdfe:dcba:9876::/126")}
	resolver := newLANDNSWithDialer("lan", func() []netip.AddrPort { return []netip.AddrPort{tunnel, self, selfDNS, server} }, exclude, dialer)
	query := new(dns.Msg).SetQuestion("printer.lan.", dns.TypeA)
	response, err := resolver.Exchange(t.Context(), query)
	if err != nil || len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "192.0.2.8" {
		t.Fatalf("LAN DNS response: %v, %v", response, err)
	}
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if !reflect.DeepEqual(dialer.network, []string{"udp", "tcp"}) {
		t.Fatalf("expected UDP then TCP, got %v", dialer.network)
	}
	if !reflect.DeepEqual(dialer.addrs, []netip.AddrPort{server, server}) {
		t.Fatalf("transport dialed filtered Pipe DNS addresses: %v", dialer.addrs)
	}
}

func TestLANDNSServesFailureWhenNoResolverExists(t *testing.T) {
	var calls int
	resolver := newLANDNSWithDialer("lan", func() []netip.AddrPort {
		calls++
		return []netip.AddrPort{netip.MustParseAddrPort("223.5.5.5:53"), netip.MustParseAddrPort("172.19.0.1:53")}
	}, []netip.Prefix{netip.MustParsePrefix("172.19.0.0/30")}, &lanTestDialer{})
	query := new(dns.Msg).SetQuestion("printer.lan.", dns.TypeA)
	started := time.Now()
	response, err := resolver.Exchange(t.Context(), query)
	if err != nil || response.Rcode != dns.RcodeServerFailure || time.Since(started) > 100*time.Millisecond {
		t.Fatalf("empty resolver answer: %v, %v", response, err)
	}
	if response, err = resolver.Exchange(t.Context(), query); err != nil || response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("cached empty resolver answer: %v, %v", response, err)
	}
	if calls != 1 {
		t.Fatalf("provider calls: %d", calls)
	}
}

func TestLANDNSKeepsLinkLocalZoneAndReadsTUNAddresses(t *testing.T) {
	zone := netip.MustParseAddrPort("[fe80::1%en0]:53")
	if got := filterLANDNSServers([]netip.AddrPort{zone}, nil); len(got) != 1 || got[0].Addr().Zone() != "en0" {
		t.Fatalf("link-local DNS zone lost: %v", got)
	}
	dialer := &lanTestDialer{}
	resolver := newLANDNSWithDialer("lan", func() []netip.AddrPort { return []netip.AddrPort{zone} }, nil, dialer)
	if _, err := resolver.Exchange(t.Context(), new(dns.Msg).SetQuestion("printer.lan.", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	dialer.mu.Lock()
	if len(dialer.addrs) != 1 || dialer.addrs[0].Addr().Zone() != "en0" {
		t.Fatalf("link-local zone was lost before dialing: %v", dialer.addrs)
	}
	dialer.mu.Unlock()
	config := Object{"inbounds": []Object{{
		"type": "tun", "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126", "10.0.0.2"},
	}}}
	got := tunAddresses(config)
	if !reflect.DeepEqual(got, []netip.Prefix{netip.MustParsePrefix("172.19.0.0/30"), netip.MustParsePrefix("fdfe:dcba:9876::/126"), netip.MustParsePrefix("10.0.0.2/32")}) {
		t.Fatalf("TUN addresses: %v", got)
	}
}

func TestLANDNSResetDoesNotWaitForProviderAndCoalescesRefresh(t *testing.T) {
	oldServer := netip.MustParseAddrPort("192.168.1.1:53")
	newServer := netip.MustParseAddrPort("10.0.0.1:53")
	release := make(chan struct{})
	started := make(chan struct{})
	var calls atomic.Int32
	resolver := newLANDNSWithDialer("lan", func() []netip.AddrPort {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			return []netip.AddrPort{oldServer}
		}
		return []netip.AddrPort{newServer}
	}, nil, &lanTestDialer{})
	first := make(chan []netip.AddrPort, 1)
	go func() {
		servers, _ := resolver.serverList(context.Background())
		first <- servers
	}()
	<-started
	second := make(chan []netip.AddrPort, 1)
	go func() {
		servers, _ := resolver.serverList(context.Background())
		second <- servers
	}()
	time.Sleep(10 * time.Millisecond)
	if calls.Load() != 1 {
		close(release)
		t.Fatalf("concurrent refresh was not coalesced: %d provider calls", calls.Load())
	}
	resetDone := make(chan struct{})
	go func() { resolver.Reset(); close(resetDone) }()
	select {
	case <-resetDone:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("Reset waited for the provider")
	}
	select {
	case servers := <-second:
		if !reflect.DeepEqual(servers, []netip.AddrPort{newServer}) {
			t.Fatalf("post-reset servers: %v", servers)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("post-reset provider refresh did not run")
	}
	close(release)
	if servers := <-first; !reflect.DeepEqual(servers, []netip.AddrPort{newServer}) {
		t.Fatalf("stale provider result escaped reset: %v", servers)
	}
	if calls.Load() != 2 {
		t.Fatalf("provider calls after coalesced reset: %d", calls.Load())
	}
}

func TestLANDNSEnvironmentChangesOnEveryReset(t *testing.T) {
	resolver := newLANDNSWithDialer("lan", nil, nil, &lanTestDialer{})
	before := resolver.Environment()
	resolver.Reset()
	if after := resolver.Environment(); reflect.DeepEqual(before, after) {
		t.Fatalf("environment %v did not change on reset", after)
	}
}

func TestLANDNSStopsTryingServersWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dialer := &cancelLANDialer{cancel: cancel}
	servers := []netip.AddrPort{netip.MustParseAddrPort("192.168.1.1:53"), netip.MustParseAddrPort("192.168.1.2:53")}
	resolver := newLANDNSWithDialer("lan", func() []netip.AddrPort { return servers }, nil, dialer)
	_, err := resolver.Exchange(ctx, new(dns.Msg).SetQuestion("printer.lan.", dns.TypeA))
	if !errors.Is(err, context.Canceled) || dialer.calls.Load() != 1 {
		t.Fatalf("canceled exchange err=%v dials=%d", err, dialer.calls.Load())
	}
}

func TestEngineRegistersLANDNSTransport(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(t.Context())
	instance, err := New(ctx, Options{
		Config: Object{"dns": Object{
			"servers": []Object{{"type": LANDNSType, "tag": "lan"}},
			"final":   "lan",
		}},
		LANDNSServers: func() []netip.AddrPort { return []netip.AddrPort{netip.MustParseAddrPort("192.168.1.1:53")} },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	transports := service.FromContext[adapter.DNSTransportManager](ctx)
	transport, ok := transports.Transport("lan")
	if !ok || transport.Type() != LANDNSType {
		t.Fatalf("custom LAN DNS transport was not registered: %v", transport)
	}
}
