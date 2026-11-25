// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestEmbeddedRuleSets(t *testing.T) {
	for _, name := range []string{"geoip-cn", "geosite-cn", "geosite-geolocation-!cn", "geosite-category-ads-all", "geosite-private"} {
		set, err := readRuleSet(name)
		if err != nil || len(set.InlineOptions.Rules) == 0 {
			t.Fatalf("embedded rule set %s is unusable: %v", name, err)
		}
	}
}

func TestPublicDestination(t *testing.T) {
	for _, raw := range []string{
		"0.1.2.3", "10.0.1.1", "127.0.0.1", "169.254.169.254", "100.100.100.200",
		"::1", "::ffff:127.0.0.1", "fe80::1", "fd00:ec2::254", "224.0.0.1",
		"64:ff9b::127.0.0.1", "64:ff9b::127.0.0.1%local", "64:ff9b:1::1", "::ffff:0:127.0.0.1", "2002:7f00:1::1",
		"2001::1234", "100::1", "198.18.0.1", "198.19.255.254",
		"192.0.2.80", "::ffff:192.0.2.80",
	} {
		if publicDestination(M.Socksaddr{Addr: netip.MustParseAddr(raw)}) == nil {
			t.Errorf("allowed restricted IP %s", raw)
		}
	}
	if publicDestination(M.Socksaddr{Fqdn: "unresolved.example"}) == nil {
		t.Error("allowed dial to an unresolved name")
	}
	for _, raw := range []string{"1.1.1.1", "11.0.0.80"} {
		if err := publicDestination(M.Socksaddr{Addr: netip.MustParseAddr(raw)}); err != nil {
			t.Errorf("blocked public IP %s: %v", raw, err)
		}
	}
}

func TestHostsTransportResolvesFixture(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(t.Context())
	const host = "other.split.test"
	ip := netip.MustParseAddr("11.0.0.80")
	instance, err := New(ctx, Options{Config: Object{
		"dns": Object{
			"servers": []Object{{"type": "hosts", "tag": TestHostsTag, "predefined": map[string]netip.Addr{host: ip}}},
			"final":   TestHostsTag,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	dns := service.FromContext[adapter.DNSRouter](ctx)
	transports := service.FromContext[adapter.DNSTransportManager](ctx)
	transport, ok := transports.Transport(TestHostsTag)
	if !ok {
		t.Fatal("missing test hosts DNS transport")
	}
	got, err := dns.Lookup(ctx, host, adapter.DNSQueryOptions{Transport: transport})
	if err != nil || !slices.Equal(got, []netip.Addr{ip}) {
		t.Fatalf("lookup %s = %v, %v; want %s", host, got, err, ip)
	}
}

func TestClientDirectOutboundsKeepNativeDialers(t *testing.T) {
	instance, err := New(t.Context(), Options{Config: Object{
		"outbounds": []Object{{"type": "direct", "tag": "direct"}, {"type": "direct", "tag": "lan"}},
		"route":     Object{"final": "direct"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	for _, tag := range []string{"direct", "lan"} {
		outbound, _ := instance.box.Outbound().Outbound(tag)
		if _, ok := outbound.(adapter.FlowOutbound); !ok {
			t.Errorf("%s lost native TUN flow support", tag)
		}
		if _, ok := outbound.(dialer.ParallelNetworkDialer); !ok {
			t.Errorf("%s lost native parallel dialing", tag)
		}
	}
}

func TestSlowTierRejectsOnlyUDP443(t *testing.T) {
	destination := M.Socksaddr{Port: 443}
	if rejectQUIC("udp", destination) == nil || rejectQUIC("tcp", destination) != nil {
		t.Fatal("only UDP/443 should be blocked")
	}
	if rejectQUIC("udp", M.Socksaddr{Port: 53}) != nil {
		t.Fatal("other UDP traffic should remain available")
	}
}

func TestProbeWithoutSocketDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	response := make(chan error, 1)
	go func() {
		defer server.Close()
		request, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			response <- err
			return
		}
		if request.Host != ProbeDomain || request.URL.Path != ProbePath || request.URL.Query().Get("burst") != "1" {
			response <- fmt.Errorf("unexpected probe request %s%s", request.Host, request.URL)
			return
		}
		_, err = fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", ProbeBurstSize)
		if err == nil {
			_, err = io.WriteString(server, strings.Repeat("x", ProbeBurstSize))
		}
		response <- err
	}()
	if stalled, err := probeHTTP(ctx, noSocketDeadline{client}, true); err != nil || stalled {
		t.Fatalf("burst probe without socket deadlines failed: %v", err)
	}
	if err := <-response; err != nil {
		t.Fatal(err)
	}
}

type noSocketDeadline struct{ net.Conn }

func (noSocketDeadline) SetDeadline(time.Time) error { return os.ErrInvalid }

func TestDeviceRevocationClosesOnlyRevokedSession(t *testing.T) {
	tracker := newDeviceSessions([]string{"first", "second"})
	first, firstPeer := net.Pipe()
	defer firstPeer.Close()
	second, secondPeer := net.Pipe()
	defer secondPeer.Close()
	first = tracker.RoutedConnection(t.Context(), first, adapter.InboundContext{User: "first"}, nil, nil)
	second = tracker.RoutedConnection(t.Context(), second, adapter.InboundContext{User: "second"}, nil, nil)
	defer first.Close()
	defer second.Close()
	if err := firstPeer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	tracker.allow([]string{"second"})
	if _, err := firstPeer.Write([]byte{0}); err != io.ErrClosedPipe {
		t.Fatalf("the revoked session stayed open: %v", err)
	}
	if err := second.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	go secondPeer.Write([]byte{1})
	var payload [1]byte
	if _, err := io.ReadFull(second, payload[:]); err != nil || payload[0] != 1 {
		t.Fatalf("the unrelated session stopped transferring: %v", err)
	}
}

type closeTrackConn struct {
	net.Conn
	closed chan struct{}
}

func (c *closeTrackConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
