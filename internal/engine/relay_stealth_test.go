// SPDX-License-Identifier: GPL-3.0-or-later
//go:build with_utls

package engine

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxdialer "github.com/sagernet/sing-box/common/dialer"
	boxtls "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func TestRelayEngineWiring(t *testing.T) {
	for _, test := range []struct {
		name        string
		relay       Relay
		detour      bool
		namedOrigin bool
	}{
		{"off", Relay{Tags: []string{"stealth"}}, false, false},
		{"ports without tags", Relay{Host: "relay.example", StealthPort: 8444, FastPort: 444}, false, false},
		{"Rescue excluded", Relay{Host: "relay.example", Tags: []string{"rescue"}}, false, false},
		{"absent Fast excluded", Relay{Host: "relay.example", Tags: []string{"fast"}, FastPort: 444}, false, false},
		{"Stealth uses a physical detour", Relay{Host: "relay.example", Tags: []string{"stealth", "rescue"}, StealthPort: 8444}, true, false},
		{"Stealth keeps the origin resolver", Relay{Host: "relay.example", Tags: []string{"stealth"}, StealthPort: 8445}, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			const uuid = "9bc36cea-679f-40dd-8d9a-2f7c938f9701"
			origin := "192.0.2.10"
			if test.namedOrigin {
				origin = "origin.example"
			}
			instance, err := New(t.Context(), Options{Relay: test.relay, Config: Object{
				"dns": Object{"servers": []Object{
					{"type": "local", "tag": "local"},
					{"type": BootstrapDNSType, "tag": "bootstrap", "hosts": []string{"Relay.Example."}, "upstreams": []string{"doh"}},
				}},
				"route": Object{"default_domain_resolver": Object{"server": "local", "strategy": "ipv4_only"}},
				"outbounds": []Object{
					{
						"type": "vless", "tag": "stealth", "server": origin, "server_port": 8443, "uuid": uuid,
						"tls": Object{
							"enabled": true, "server_name": "identity.example",
							"utls": Object{"enabled": true, "fingerprint": "chrome"},
							"reality": Object{
								"enabled": true, "public_key": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
							},
						},
					},
					{"type": "vmess", "tag": "rescue", "server": "192.0.2.11", "server_port": 443, "uuid": uuid},
					{"type": "vless", "tag": "untagged", "server": "192.0.2.12", "server_port": 443, "uuid": uuid},
					{"type": "block", "tag": relayTCPType},
				},
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			for _, tag := range []string{"rescue", "untagged"} {
				tier, _ := instance.box.Outbound().Outbound(tag)
				if len(tier.Dependencies()) != 0 || instance.RelayState(tag) != "" {
					t.Errorf("unrelayed tier %s has dependencies %v", tag, tier.Dependencies())
				}
			}
			stealth, _ := instance.box.Outbound().Outbound("stealth")
			dependencies := stealth.Dependencies()
			if !test.detour {
				if len(dependencies) != 0 || instance.RelayState("stealth") != "" || instance.RelayState("fast") != "" {
					t.Fatalf("disabled relay installed a detour %v", dependencies)
				}
				return
			}
			if got := instance.RelayState("stealth"); got != "pending" {
				t.Fatalf("idle Stealth reports %q, want pending", got)
			}
			if !slices.Equal(dependencies, []string{relayTCPType + "-1"}) {
				t.Fatalf("Stealth dependencies = %v, want a unique relay detour", dependencies)
			}
			detour, _ := instance.box.Outbound().Outbound(dependencies[0])
			physical := detour.(*relayTCPOutbound)
			if physical.server != M.ParseSocksaddrHostPort(origin, 8443) {
				t.Errorf("detour server is %v", physical.server)
			}
			if want := M.ParseSocksaddrHostPort(test.relay.Host, test.relay.StealthPort); physical.endpoint != want {
				t.Errorf("relay endpoint = %v, want %v", physical.endpoint, want)
			}
			query := physical.viaRelay.(boxdialer.ResolveDialer).QueryOptions()
			transports := service.FromContext[adapter.DNSTransportManager](instance.ctx)
			bootstrap, _ := transports.Transport("bootstrap")
			if query.Transport != bootstrap || query.Strategy != C.DomainStrategyIPv4Only || !query.DisableCache {
				t.Errorf("unexpected relay lookup options %+v", query)
			}
			if test.namedOrigin {
				local, _ := transports.Transport("local")
				directQuery := physical.Dialer.(boxdialer.ResolveDialer).QueryOptions()
				if directQuery.Transport != local || directQuery.Strategy != C.DomainStrategyIPv4Only {
					t.Errorf("unexpected direct lookup options %+v", directQuery)
				}
			}
			if instance.box.Network().InterfaceMonitor() != nil && instance.relay.stopMonitor == nil {
				t.Error("relay did not register its reset callback with the desktop monitor")
			}
		})
	}
}

type relayTestOutbound struct {
	outbound.Adapter
	N.Dialer
}

type relayTestOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m relayTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	out, ok := m.outbounds[tag]
	return out, ok
}

func TestRelayStealthRejectsTCPOnlyRelay(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		t.Run(network, func(t *testing.T) {
			checkStealthRelay(t, network, false)
		})
	}
}

func TestRelayStealthProbeUsesItsDialPath(t *testing.T) {
	checkStealthRelay(t, N.NetworkTCP, true)
}

func checkStealthRelay(t *testing.T, network string, wantVia bool) {
	t.Helper()
	const name = "identity.example"
	const serverPort = 8443
	const relayPort = 8444
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	logger := log.NewNOPFactory().Logger()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	cert, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &certKey.PublicKey, certKey)
	if err != nil {
		t.Fatal(err)
	}
	coverTLS := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: certKey}},
		MinVersion:   tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
	}
	newPipe := func() (net.Conn, net.Conn) {
		local, peer := net.Pipe()
		deadline, _ := ctx.Deadline()
		_ = local.SetDeadline(deadline)
		_ = peer.SetDeadline(deadline)
		t.Cleanup(func() { local.Close(); peer.Close() })
		return local, peer
	}
	manager := relayTestOutboundManager{outbounds: make(map[string]adapter.Outbound)}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
	manager.outbounds["cover"] = &relayTestOutbound{Dialer: relayTestDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		local, peer := newPipe()
		go func() {
			defer peer.Close()
			_ = tls.Server(peer, coverTLS).HandshakeContext(ctx)
		}()
		return local, nil
	}}}
	serverTLS, err := boxtls.NewRealityServer(ctx, logger, option.InboundTLSOptions{
		Enabled: true, ServerName: name,
		Reality: &option.InboundRealityOptions{
			Enabled: true, PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()),
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{Server: "192.0.2.40", ServerPort: 443},
				DialerOptions: option.DialerOptions{Detour: "cover"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serverTLS.Close()
	origin := M.ParseSocksaddrHostPort("192.0.2.10", serverPort)
	state := newRelayState(Relay{Host: "192.0.2.20", Tags: []string{"stealth"}, StealthPort: relayPort})
	relay := M.ParseSocksaddrHostPort("192.0.2.20", relayPort)
	relayHello := make(chan error, 2)
	originHandshake := make(chan error, 2)
	var relayDials atomic.Int32
	connectOrigin := func() net.Conn {
		local, peer := newPipe()
		go func() {
			defer peer.Close()
			authenticated, err := boxtls.ServerHandshake(ctx, peer, serverTLS)
			originHandshake <- err
			if err == nil {
				_, _ = io.Copy(io.Discard, authenticated)
			}
		}()
		return local
	}
	manager.outbounds["physical"] = &relayTestOutbound{Dialer: relayTestDialer{dial: func(_ context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if network != N.NetworkTCP {
			return nil, fmt.Errorf("unexpected physical network %q", network)
		}
		switch destination {
		case relay:
			relayDials.Add(1)
			if wantVia {
				return connectOrigin(), nil
			}
			local, peer := newPipe()
			go func() {
				defer peer.Close()
				var firstByte [1]byte
				_, err := io.ReadFull(peer, firstByte[:])
				relayHello <- err
			}()
			return local, nil
		case origin:
			return connectOrigin(), nil
		default:
			return nil, fmt.Errorf("unexpected physical destination %v", destination)
		}
	}}}
	opts := option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: origin.Addr.String(), ServerPort: origin.Port},
		DialerOptions: option.DialerOptions{Detour: "physical"},
		UUID:          "9bc36cea-679f-40dd-8d9a-2f7c938f9701", Flow: "xtls-rprx-vision",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
			Enabled: true, ServerName: name,
			UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
			Reality: &option.OutboundRealityOptions{
				Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
			},
		}},
	}
	decoded := option.Options{Outbounds: []option.Outbound{{Type: C.TypeVLESS, Tag: "stealth", Options: &opts}}}
	state.configure(&decoded)
	registry := outbound.NewRegistry()
	registerOutbounds(registry, Options{}, state)
	outbound.Register(registry, relayTCPType, state.newTCPOutbound)
	if len(decoded.Outbounds) != 2 {
		t.Fatal("missing physical relay detour")
	}
	detour := decoded.Outbounds[1]
	physical, err := registry.CreateOutbound(ctx, nil, logger, detour.Tag, detour.Type, detour.Options)
	if err != nil {
		t.Fatal(err)
	}
	manager.outbounds[detour.Tag] = physical
	stealth, err := registry.CreateOutbound(ctx, nil, logger, "stealth", C.TypeVLESS, &opts)
	if err != nil {
		t.Fatal(err)
	}
	instance := &Instance{relay: state}
	if got := instance.RelayState("stealth"); got != "pending" {
		t.Fatalf("idle Stealth reports %q", got)
	}
	destination := M.ParseSocksaddrHostPort("proxied.example", 80)
	wantState := "direct"
	if wantVia {
		wantState = "via"
	}
	probeCtx := context.WithValue(ctx, probeContextKey{}, true)
	for range 2 {
		var conn io.Closer
		if network == N.NetworkTCP {
			stream, dialErr := stealth.DialContext(probeCtx, network, destination)
			if dialErr == nil {
				if got := probeViaRelay(stream); got != wantVia {
					t.Errorf("Stealth probe stream via=%v, want %v", got, wantVia)
				}
			}
			conn, err = stream, dialErr
		} else {
			conn, err = stealth.ListenPacket(ctx, destination)
		}
		if err != nil {
			t.Fatalf("Stealth dial failed: %v", err)
		}
		if got := instance.RelayState("stealth"); got != wantState {
			t.Errorf("Stealth reports %q, want %q", got, wantState)
		}
		select {
		case err := <-originHandshake:
			if err != nil {
				t.Errorf("origin REALITY handshake failed: %v", err)
			}
		case <-ctx.Done():
			t.Error("origin did not finish its handshake")
		}
		conn.Close()
	}
	if wantVia {
		if relayDials.Load() != 2 || !state.retryAt.IsZero() {
			t.Errorf("relay was dialed %d times and cooldown expires at %v", relayDials.Load(), state.retryAt)
		}
		return
	}
	select {
	case err := <-relayHello:
		if err != nil {
			t.Errorf("TCP-only relay did not receive the handshake: %v", err)
		}
	default:
		t.Error("Stealth never tried the TCP-only relay")
	}
	if relayDials.Load() != 1 || !state.retryAt.After(time.Now()) {
		t.Errorf("relay was dialed %d times and cooldown expires at %v", relayDials.Load(), state.retryAt)
	}
}
