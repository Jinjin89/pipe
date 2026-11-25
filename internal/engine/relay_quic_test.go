// SPDX-License-Identifier: GPL-3.0-or-later
//go:build with_quic

package engine

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-quic/hysteria"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestRelayFastFamilyStaggerAndPortHops(t *testing.T) {
	relay4 := netip.MustParseAddr("192.0.2.1")
	relay6 := netip.MustParseAddr("2001:db8::1")
	origin4 := netip.MustParseAddr("198.51.100.1")
	origin6 := netip.MustParseAddr("2001:db8::2")
	type attempt struct {
		ip netip.Addr
		at time.Duration
	}
	tests := []struct {
		name     string
		relayHop bool
		viaRelay bool
	}{
		{"relay hops with a single-port origin", true, true},
		{"single-port origin wins after a hopping relay stalls", true, false},
		{"single-port relay wins with a hopping origin", false, true},
		{"origin hops after a single-port relay stalls", false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := t.Context()
				server := M.ParseSocksaddrHostPort("origin.example", 443)
				relay := Relay{Host: "relay.example", Tags: []string{"fast"}, FastPort: 444}
				var directPorts, relayPorts []uint16
				directAllowed, relayAllowed := []uint16{server.Port}, []uint16{relay.FastPort}
				if test.relayHop {
					relay.FastPort, relay.FastPorts = 20000, "20000:20001"
					var err error
					relayPorts, err = hysteria.ParsePorts([]string{relay.FastPorts})
					if err != nil {
						t.Fatal(err)
					}
					relayAllowed = []uint16{20000, 20001}
				} else {
					directPorts = []uint16{30000, 30001}
					directAllowed = directPorts
				}
				state := newRelayState(relay)
				winnerIP := origin6
				if test.viaRelay {
					winnerIP = relay6
				}
				hopInterval := 5 * time.Second
				start := time.Now()
				calls := make(chan attempt, 8)
				dialer := &fastPacketDialer{
					Dialer: fastTestPacketDialer{dial: func(dialCtx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
						allowed := directAllowed
						if destination.Addr == relay4 || destination.Addr == relay6 {
							allowed = relayAllowed
						}
						if network != N.NetworkUDP || !slices.Contains(allowed, destination.Port) {
							t.Errorf("dial used %q %v, want UDP ports %v", network, destination, allowed)
						}
						if time.Since(start) >= hopInterval && dialCtx != ctx {
							t.Error("port hop did not use the client lifetime")
						}
						calls <- attempt{destination.Addr, time.Since(start)}
						local, remote := net.Pipe()
						t.Cleanup(func() { remote.Close() })
						return fastTestConnectedUDP{Conn: local, remote: destination.UDPAddr()}, nil
					}},
					server: server,
					relay:  state,
					lookup: func(_ context.Context, name string) ([]netip.Addr, error) {
						if name != server.Fqdn {
							t.Errorf("direct lookup used %s", name)
						}
						return []netip.Addr{origin4, origin6}, nil
					},
					relayLookup: func(_ context.Context, name string) ([]netip.Addr, error) {
						if name != state.host.Fqdn {
							t.Errorf("relay lookup used %s", name)
						}
						return []netip.Addr{relay4, relay6}, nil
					},
					lifetime: ctx, ports: directPorts, relayPorts: relayPorts, hopInterval: hopInterval,
				}
				conn, err := dialer.DialContext(ctx, N.NetworkUDP, server)
				if err != nil {
					t.Fatal(err)
				}
				winner, err := conn.(*fastDialConn).dial(ctx, func(ctx context.Context, socket net.Conn) (fastAuth, error) {
					peer := M.SocksaddrFromNet(socket.RemoteAddr()).Unwrap().Addr
					if peer != winnerIP {
						<-ctx.Done()
						socket.Close()
						return fastAuth{}, ctx.Err()
					}
					return fastAuth{socket: socket, response: &http.Response{Body: http.NoBody}}, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				defer winner.close()
				wantState := "direct"
				if test.viaRelay {
					wantState = "via"
				}
				if got := (&Instance{relay: state}).RelayState("fast"); got != wantState {
					t.Errorf("relay status = %q for winning IP %v", got, winnerIP)
				}
				time.Sleep(hopInterval)
				synctest.Wait()
				close(calls)
				var attempts []attempt
				for call := range calls {
					attempts = append(attempts, call)
				}
				want := []attempt{{relay4, 0}, {relay6, 300 * time.Millisecond}}
				if !test.viaRelay {
					want = append(want, attempt{origin4, time.Second}, attempt{origin6, 1300 * time.Millisecond})
				}
				if test.viaRelay && len(relayPorts) != 0 || !test.viaRelay && len(directPorts) != 0 {
					want = append(want, attempt{winnerIP, want[len(want)-1].at + hopInterval})
				}
				if !slices.Equal(attempts, want) {
					t.Errorf("attempts %v, want %v", attempts, want)
				}
			})
		})
	}
}

func TestRelayFastStalledDNSDoesNotDelayDirect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := M.ParseSocksaddrHostPort("192.0.2.1", 8443)
		state := newRelayState(Relay{Host: "relay.example", Tags: []string{"fast"}, FastPort: 444})
		start := time.Now()
		dialer := &fastPacketDialer{
			Dialer: fastTestPacketDialer{dial: func(_ context.Context, _ string, dest M.Socksaddr) (net.Conn, error) {
				if dest != server || time.Since(start) != time.Second {
					t.Errorf("dialed %v after %v, want %v after 1 s", dest, time.Since(start), server)
				}
				return new(fastTestSocket), nil
			}},
			server: server,
			relay:  state,
			relayLookup: func(ctx context.Context, _ string) ([]netip.Addr, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}
		conn, err := dialer.DialContext(t.Context(), N.NetworkUDP, server)
		if err != nil {
			t.Fatal(err)
		}
		winner, err := conn.(*fastDialConn).dial(t.Context(), func(_ context.Context, socket net.Conn) (fastAuth, error) {
			return fastAuth{socket: socket, response: &http.Response{Body: http.NoBody}}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		winner.close()
		if (&Instance{relay: state}).RelayState("fast") != "direct" {
			t.Error("stalled relay DNS was picked")
		}
	})
}

func TestRelayFastProbeDeadlineDuringSharedLogin(t *testing.T) {
	testRelayFastProbeDeadlineDuringSharedLogin(t, false)
}

func TestRelayProbeEngineFastDeadlineDuringSharedLogin(t *testing.T) {
	testRelayFastProbeDeadlineDuringSharedLogin(t, true)
}

func testRelayFastProbeDeadlineDuringSharedLogin(t *testing.T, noCooldown bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		state := newRelayState(Relay{Host: "192.0.2.2", Tags: []string{"fast", "stealth"}, FastPort: 444, StealthPort: 8444})
		state.noCooldown = noCooldown
		instance := &Instance{relay: state}
		ctx, stop := context.WithCancel(t.Context())
		defer stop()
		relayReady, loginDone := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(loginDone)
			_, _ = dialRelay(ctx, state, "fast", func(ctx context.Context, viaRelay bool) (bool, error) {
				if viaRelay {
					select {
					case <-relayReady:
						return true, nil
					case <-ctx.Done():
					}
				}
				<-ctx.Done()
				return false, ctx.Err()
			}, func(bool) {})
		}()

		probe := context.WithValue(t.Context(), probeContextKey{}, true)
		probe, cancel := context.WithTimeout(probe, 1200*time.Millisecond)
		defer cancel()
		<-probe.Done()
		if ctx.Err() != nil {
			t.Fatal("the shared login ended before the probe")
		}
		fast := observedFast{relay: state, observe: func(error) {
			t.Error("probe timeout was reported as an application dial")
		}}
		fast.report(probe, probe.Err())
		dial := func(_ context.Context, viaRelay bool) (bool, error) {
			return viaRelay, nil
		}
		viaRelay, err := dialRelay(t.Context(), state, "stealth", dial, func(bool) {})
		if err != nil || viaRelay != noCooldown {
			t.Errorf("next tier used relay=%v after the Fast probe deadline, err=%v, want relay=%v", viaRelay, err, noCooldown)
		}
		if got := instance.RelayState("fast"); got != "pending" {
			t.Errorf("unfinished Fast login was published as %q", got)
		}
		time.Sleep(100 * time.Millisecond)
		close(relayReady)
		<-loginDone
		if got := instance.RelayState("fast"); got != "via" {
			t.Errorf("completed Fast login was published as %q", got)
		}
		viaRelay, err = dialRelay(t.Context(), state, "stealth", dial, func(bool) {})
		if err != nil || !viaRelay {
			t.Errorf("next tier used relay=%v after the successful Fast login, err=%v", viaRelay, err)
		}
	})
}
