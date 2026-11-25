// SPDX-License-Identifier: GPL-3.0-or-later
//go:build with_quic

package engine

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type fastTestPacketDialer struct {
	N.Dialer
	dial func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (d fastTestPacketDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx, network, destination)
}

type fastTestSocket struct {
	net.Conn
	destination M.Socksaddr
	closed      bool
}

func (c *fastTestSocket) Close() error {
	c.closed = true
	return nil
}

type fastTestTLS struct {
	fastQUICConfig
	roundTrip func(*http.Request, *fastTestSocket) (*http.Response, error)
}

func (*fastTestTLS) HandshakeTimeout() time.Duration { return 0 }

func (c *fastTestTLS) CreateTransport(conn net.Conn, _ **quic.Conn, _ *quic.Config) http.RoundTripper {
	return fastRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return c.roundTrip(req, conn.(*fastTestSocket))
	})
}

func TestFastQUICFamilyRace(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.1")
	v6 := netip.MustParseAddr("2001:db8::1")
	firstError := errors.New("first family handshake failed")
	secondError := errors.New("other family handshake failed")
	tests := []struct {
		name              string
		first, second     netip.Addr
		waitForCancel     bool
		firstDelay        time.Duration
		firstErr, nextErr error
		firstStatus       int
		secondAt          time.Duration
		deadline          time.Duration
		want              netip.Addr
	}{
		{
			name: "second wins when first stalls", first: v4, second: v6, waitForCancel: true,
			secondAt: 300 * time.Millisecond, want: v6,
		},
		{
			name: "first wins without a second dial", first: v6, second: v4,
			firstDelay: 50 * time.Millisecond, want: v6,
		},
		{
			name: "both fail and the first error wins", first: v6, second: v4,
			firstDelay: 400 * time.Millisecond, firstErr: firstError, nextErr: secondError,
			secondAt: 300 * time.Millisecond,
		},
		{
			name: "definite failure starts the second immediately", first: v4, second: v6,
			firstDelay: 25 * time.Millisecond, firstErr: firstError,
			secondAt: 25 * time.Millisecond, want: v6,
		},
		{
			name: "rejected login starts the second immediately", first: v4, second: v6,
			firstDelay: 25 * time.Millisecond, firstStatus: http.StatusForbidden,
			secondAt: 25 * time.Millisecond, want: v6,
		},
		{
			name: "backup timeout preserves the first error", first: v4, second: v6,
			firstDelay: 25 * time.Millisecond, firstErr: firstError,
			secondAt: 25 * time.Millisecond, deadline: 400 * time.Millisecond,
		},
		{
			name: "late first success is closed", first: v4, second: v6,
			firstDelay: 400 * time.Millisecond, secondAt: 300 * time.Millisecond, want: v6,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				type dial struct {
					socket *fastTestSocket
					at     time.Duration
				}
				start := time.Now()
				dials := make(chan dial, 3)
				server := M.ParseSocksaddrHostPort("fast.example.test", 8443)
				dialer := fastPacketDialer{
					Dialer: fastTestPacketDialer{dial: func(_ context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
						if network != N.NetworkUDP || destination.Port != server.Port {
							t.Errorf("dial used %s %v, want UDP on port %d", network, destination, server.Port)
						}
						socket := &fastTestSocket{destination: destination}
						dials <- dial{socket, time.Since(start)}
						return socket, nil
					}},
					lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
						if host != server.Fqdn {
							t.Fatalf("lookup for %s, want %s", host, server.Fqdn)
						}
						return []netip.Addr{test.first, test.second}, nil
					},
				}
				config := &fastQUICConfig{Config: &fastTestTLS{
					roundTrip: func(req *http.Request, socket *fastTestSocket) (*http.Response, error) {
						if socket.destination.Addr == test.first {
							if test.waitForCancel {
								<-req.Context().Done()
								return nil, req.Context().Err()
							}
							time.Sleep(test.firstDelay)
							if test.firstErr != nil {
								return nil, test.firstErr
							}
							if test.firstStatus != 0 {
								return &http.Response{StatusCode: test.firstStatus, Body: http.NoBody}, nil
							}
						} else {
							if test.deadline != 0 {
								<-req.Context().Done()
								return nil, req.Context().Err()
							}
							if test.nextErr != nil {
								return nil, test.nextErr
							}
						}
						return &http.Response{StatusCode: fastAuthOK, Body: http.NoBody}, nil
					},
				}}
				raw, err := dialer.DialContext(t.Context(), N.NetworkUDP, server)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				if len(dials) != 0 {
					t.Fatal("dual-stack UDP opened outside the handshake race")
				}
				var conn *quic.Conn
				transport, err := qtls.CreateTransport(raw, &conn, config, &quic.Config{})
				if err != nil {
					t.Fatal(err)
				}
				ctx := t.Context()
				if test.deadline != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, test.deadline)
					defer cancel()
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://fast.example.test/auth", nil)
				if err != nil {
					t.Fatal(err)
				}
				_, err = transport.RoundTrip(req)
				if test.want.IsValid() {
					if err != nil {
						t.Fatal(err)
					}
				} else if !errors.Is(err, test.firstErr) {
					t.Fatalf("dial returned %v, want %v", err, test.firstErr)
				}
				time.Sleep(time.Second)
				synctest.Wait()
				close(dials)
				var addresses []netip.Addr
				for attempt := range dials {
					address := attempt.socket.destination.Addr
					addresses = append(addresses, address)
					if attempt.socket.closed != (address != test.want) {
						t.Errorf("socket to %s closed = %v, winner is %v", address, attempt.socket.closed, test.want)
					}
					if address == test.second && attempt.at != test.secondAt {
						t.Errorf("fallback started at %v, want %v", attempt.at, test.secondAt)
					}
				}
				expected := []netip.Addr{test.first}
				if test.secondAt != 0 {
					expected = append(expected, test.second)
				}
				if !slices.Equal(addresses, expected) {
					t.Errorf("family dials %v, want %v", addresses, expected)
				}
			})
		})
	}
}

func TestFastQUICSingleFamilyUsesSerialPacketDial(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	server := M.ParseSocksaddrHostPort("fast.example.test", 8443)
	var destinations []M.Socksaddr
	socket := new(fastTestSocket)
	dialer := fastPacketDialer{
		Dialer: fastTestPacketDialer{dial: func(_ context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
			destinations = append(destinations, destination)
			if destination.Addr == first {
				return nil, errors.New("no route to the first address")
			}
			return socket, nil
		}},
		lookup: func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{first, second}, nil },
	}
	conn, err := dialer.DialContext(t.Context(), N.NetworkUDP, server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if dial := conn.(*fastDialConn); dial.Conn != socket || dial.dial != nil {
		t.Fatal("single-family lookup did not select the UDP socket directly")
	}
	if len(destinations) != 2 || destinations[0] != M.SocksaddrFrom(first, server.Port) || destinations[1] != M.SocksaddrFrom(second, server.Port) {
		t.Fatalf("dial destinations = %v, want same-family addresses in resolver order", destinations)
	}
}

type fastTestConnectedUDP struct {
	net.Conn
	local, remote *net.UDPAddr
}

func (c fastTestConnectedUDP) LocalAddr() net.Addr  { return c.local }
func (c fastTestConnectedUDP) RemoteAddr() net.Addr { return c.remote }

func TestFastQUICPortHopsUseSelectedIPAndLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		type dial struct {
			ctx         context.Context
			destination M.Socksaddr
		}
		calls := make(chan dial, 2)
		offer, cancel := context.WithCancel(t.Context())
		defer cancel()
		ip := netip.MustParseAddr("2001:db8::1")
		dialer := fastPacketDialer{
			Dialer: fastTestPacketDialer{dial: func(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
				calls <- dial{ctx, destination}
				near, far := net.Pipe()
				t.Cleanup(func() { far.Close() })
				return fastTestConnectedUDP{Conn: near, remote: destination.UDPAddr()}, nil
			}},
			lifetime:    t.Context(),
			ports:       []uint16{8443},
			hopInterval: 5 * time.Second,
		}
		server := M.ParseSocksaddrHostPort("fast.example.test", 443)
		conn, err := dialer.dialFamily(offer, N.NetworkUDP, server, []netip.Addr{ip}, dialer.ports)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		cancel()
		time.Sleep(dialer.hopInterval)
		synctest.Wait()
		expected := M.SocksaddrFrom(ip, dialer.ports[0])
		first := <-calls
		if first.ctx != offer || first.destination != expected {
			t.Errorf("first dial used %v, %v, want the offer context and %v", first.ctx, first.destination, expected)
		}
		select {
		case hop := <-calls:
			if hop.ctx != dialer.lifetime || hop.destination != expected {
				t.Errorf("hop dial used %v, %v, want the client lifetime and %v", hop.ctx, hop.destination, expected)
			}
		default:
			t.Error("second port dial did not start")
		}
	})
}
