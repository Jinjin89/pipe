// SPDX-License-Identifier: GPL-3.0-or-later
//go:build with_quic

package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxdialer "github.com/sagernet/sing-box/common/dialer"
	boxtls "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func TestFastObservationDistinguishesTimeoutFromCancellation(t *testing.T) {
	var observed []error
	fast := observedFast{observe: func(err error) { observed = append(observed, err) }}
	deadline, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	fast.report(deadline, fmt.Errorf("dial: %w", context.DeadlineExceeded))
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	fast.report(canceled, errors.New("caller went away"))
	fast.report(t.Context(), fmt.Errorf("dial: %w", context.Canceled))
	fast.report(context.WithValue(t.Context(), probeContextKey{}, true), context.DeadlineExceeded)
	if len(observed) != 1 || !errors.Is(observed[0], context.DeadlineExceeded) {
		t.Fatalf("expected exactly the application deadline failure, got %v", observed)
	}
}

type fastTestOutboundManager struct {
	adapter.OutboundManager
	detour adapter.Outbound
}

func (m fastTestOutboundManager) Outbound(string) (adapter.Outbound, bool) { return m.detour, true }

type fastTestDNSRouter struct {
	adapter.DNSRouter
	lookup func(context.Context, string, adapter.DNSQueryOptions) ([]netip.Addr, error)
}

func (r fastTestDNSRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return r.lookup(ctx, domain, options)
}

func TestFastObservationReportsAuthenticatedWinner(t *testing.T) {
	testFastObservationReportsAuthenticatedWinner(t, netip.Addr{}, false)
}

func TestRelayFastObservationReportsOnlyWinningLogin(t *testing.T) {
	testFastObservationReportsAuthenticatedWinner(t, netip.MustParseAddr("192.0.2.8"), false)
}

func TestRelayFastProbeUsesItsSessionPath(t *testing.T) {
	testFastObservationReportsAuthenticatedWinner(t, netip.MustParseAddr("2001:db8::8"), true)
}

func testFastObservationReportsAuthenticatedWinner(t *testing.T, relayIP netip.Addr, wantVia bool) {
	t.Helper()
	const name = "fast.example.test"
	const password = "test-password"
	const relayPort = 444
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	logger := log.NewNOPFactory().Logger()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(spki)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := boxtls.NewSTDServer(ctx, logger, option.InboundTLSOptions{
		Enabled:     true,
		Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))},
		Key:         []string{string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serverTLS.Close()
	server, err := hysteria2.NewService[string](hysteria2.ServiceOptions{
		Context: ctx, Logger: logger, TLSConfig: serverTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	server.UpdateUsers([]string{"test"}, []string{password})

	edge := M.ParseSocksaddrHostPort("edge.example.test", 443)
	v4 := netip.MustParseAddr("192.0.2.1")
	v6 := netip.MustParseAddr("2001:db8::1")
	serverIP := M.SocksaddrFrom(v6, edge.Port).UDPAddr()
	if wantVia {
		serverIP = M.SocksaddrFrom(relayIP, relayPort).UDPAddr()
	}
	clientIP := M.ParseSocksaddrHostPort("2001:db8::2", 30001).UDPAddr()
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	wire := bufio.NewUnbindPacketConn(fastTestConnectedUDP{Conn: serverSide, local: serverIP, remote: clientIP})
	if err := server.Start(wire); err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	silent, discard := net.Pipe()
	defer silent.Close()
	defer discard.Close()
	blackholed := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(io.Discard, discard)
		blackholed <- n
	}()
	var sockets, lookups atomic.Int32
	wireDialer := fastTestPacketDialer{dial: func(_ context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
		sockets.Add(1)
		if destination.Addr == relayIP {
			if destination.Port != relayPort {
				t.Errorf("relay UDP port = %d, want %d", destination.Port, relayPort)
			}
			if wantVia {
				return fastTestConnectedUDP{Conn: clientSide, local: clientIP, remote: serverIP}, nil
			}
			return nil, errors.New("relay unreachable")
		}
		if wantVia {
			return nil, fmt.Errorf("unexpected direct dial to %s", destination)
		}
		if destination.Port != edge.Port {
			t.Errorf("direct UDP port = %d, want %d", destination.Port, edge.Port)
		}
		if destination.Addr == v4 {
			local := M.ParseSocksaddrHostPort("192.0.2.2", 30002).UDPAddr()
			return fastTestConnectedUDP{Conn: silent, local: local, remote: destination.UDPAddr()}, nil
		}
		return fastTestConnectedUDP{Conn: clientSide, local: clientIP, remote: serverIP}, nil
	}}
	query := adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4, DisableCache: true}
	ctx = service.ContextWith[adapter.DNSRouter](ctx, fastTestDNSRouter{
		lookup: func(_ context.Context, domain string, opts adapter.DNSQueryOptions) ([]netip.Addr, error) {
			if domain != edge.Fqdn || opts != query {
				t.Errorf("lookup for %s with %+v, want %s with %+v", domain, opts, edge.Fqdn, query)
			}
			lookups.Add(1)
			return []netip.Addr{v4, v6}, nil
		},
	})
	type resolvedOutbound struct {
		outbound.Adapter
		boxdialer.ResolveDialer
	}
	native := &resolvedOutbound{ResolveDialer: boxdialer.NewResolveDialer(ctx, wireDialer, true, "", query, 0)}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, fastTestOutboundManager{detour: native})
	var relay *relayState
	wantSockets, wantLookups := int32(2), int32(1)
	if relayIP.IsValid() {
		relay = newRelayState(Relay{Host: relayIP.String(), Tags: []string{"fast"}, FastPort: relayPort})
		wantSockets++
	}
	if wantVia {
		wantSockets, wantLookups = 1, 0
	}
	var observed []error
	registry := outbound.NewRegistry()
	registerQUIC(inbound.NewRegistry(), registry, nil, Options{ObserveFastDial: func(err error) {
		observed = append(observed, err)
	}}, relay)
	fast, err := registry.CreateOutbound(ctx, nil, logger, "fast", C.TypeHysteria2, &option.Hysteria2OutboundOptions{
		DialerOptions: option.DialerOptions{Detour: "physical"},
		ServerOptions: option.ServerOptions{Server: edge.Fqdn, ServerPort: edge.Port},
		Password:      password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
			Enabled: true, ServerName: name, CertificatePublicKeySHA256: [][]byte{pin[:]},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := adapter.NewScope(ctx, logger)
	defer scope.Close()
	if err := scope.Start("fast", fast.(adapter.Lifecycle), adapter.StartStateInitialize); err != nil {
		t.Fatal(err)
	}
	destination := M.ParseSocksaddrHostPort("service.example.test", 443)
	stream, err := fast.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	packets, err := fast.ListenPacket(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer packets.Close()
	if wantVia {
		// The reused stream still goes via relay after the public status resets.
		relay.reset()
	} else {
		select {
		case n := <-blackholed:
			if n == 0 {
				t.Error("the first socket never sent QUIC packets")
			}
		case <-ctx.Done():
			t.Fatal("losing UDP socket stayed open")
		}
	}
	probe, err := fast.DialContext(context.WithValue(ctx, probeContextKey{}, true), N.NetworkTCP, M.ParseSocksaddrHostPort(ProbeDomain, 80))
	if err != nil {
		t.Fatal(err)
	}
	probe.Close()
	if got := probeViaRelay(probe); got != wantVia {
		t.Errorf("Fast probe stream via=%v, want %v", got, wantVia)
	}
	if sockets.Load() != wantSockets || lookups.Load() != wantLookups {
		t.Errorf("got %d UDP attempts and %d lookups, want %d attempts and %d lookups", sockets.Load(), lookups.Load(), wantSockets, wantLookups)
	}
	if len(observed) != 2 || observed[0] != nil || observed[1] != nil {
		t.Errorf("observed %v, want success for TCP and UDP", observed)
	}
	if relay != nil && !wantVia {
		if relay.retryAt.IsZero() || (&Instance{relay: relay}).RelayState("fast") != "direct" {
			t.Error("recovered relay failure did not select and record the direct path")
		}
		fast.(adapter.InterfaceUpdateListener).InterfaceUpdated(ctx)
		if !relay.retryAt.IsZero() || (&Instance{relay: relay}).RelayState("fast") != "pending" {
			t.Error("Fast interface update kept the relay cooldown")
		}
	}
}
