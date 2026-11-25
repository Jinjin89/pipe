// SPDX-License-Identifier: GPL-3.0-or-later
//go:build with_quic

package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

// The dialer passes the candidates to sing-quic's CreateTransport hook.
// sing-quic retains this connection for cleanup. QUIC uses the socket directly.
type fastDialConn struct {
	net.Conn
	dial func(context.Context, fastAuthenticate) (fastAuth, error)
}

func (c *fastDialConn) Close() error {
	if c.Conn == nil {
		return nil
	}
	return c.Conn.Close()
}

type fastQUICConfig struct {
	aTLS.Config
}

var _ qtls.Config = (*fastQUICConfig)(nil)

func (c *fastQUICConfig) Dial(ctx context.Context, conn net.Conn, config *quic.Config) (*quic.Conn, error) {
	return qtls.Dial(ctx, conn, c.Config, config)
}

func (c *fastQUICConfig) DialEarly(ctx context.Context, conn net.Conn, config *quic.Config) (*quic.Conn, error) {
	return qtls.DialEarly(ctx, conn, c.Config, config)
}

func (c *fastQUICConfig) CreatePacketTransport(conn net.PacketConn, remoteAddr net.Addr, quicConn **quic.Conn, config *quic.Config) http.RoundTripper {
	return fastRoundTripperOrError(qtls.CreatePacketTransport(conn, remoteAddr, quicConn, c.Config, config))
}

func (c *fastQUICConfig) CreateTransport(conn net.Conn, quicConn **quic.Conn, config *quic.Config) http.RoundTripper {
	dialConn := conn.(*fastDialConn)
	dial := dialConn.dial
	if dial == nil {
		return fastRoundTripperOrError(qtls.CreateTransport(dialConn.Conn, quicConn, c.Config, config))
	}
	return fastRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		winner, err := dial(req.Context(), func(ctx context.Context, socket net.Conn) (fastAuth, error) {
			return c.authenticate(req.Clone(ctx), config.Clone(), socket)
		})
		if err != nil {
			return nil, err
		}
		dialConn.Conn = winner.socket
		dialConn.dial = nil
		*quicConn = winner.conn
		return winner.response, nil
	})
}

type fastRoundTripFunc func(*http.Request) (*http.Response, error)

func (f fastRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func fastRoundTripperOrError(transport http.RoundTripper, err error) http.RoundTripper {
	if err != nil {
		return fastRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, err })
	}
	return transport
}

type fastAuth struct {
	socket   net.Conn
	conn     *quic.Conn
	response *http.Response
}

type fastAuthenticate func(context.Context, net.Conn) (fastAuth, error)

func (a fastAuth) close() {
	a.response.Body.Close()
	if a.conn != nil {
		a.conn.CloseWithError(0, "")
	}
	a.socket.Close()
}

// Hysteria2 returns HTTP status 233 on successful authentication.
const fastAuthOK = 233

func (c *fastQUICConfig) authenticate(req *http.Request, config *quic.Config, socket net.Conn) (fastAuth, error) {
	var conn *quic.Conn
	transport, err := qtls.CreateTransport(socket, &conn, c.Config, config)
	if err != nil {
		socket.Close()
		return fastAuth{}, err
	}
	response, err := transport.RoundTrip(req)
	if err != nil {
		// RoundTrip can return before its dial goroutine after cancellation.
		// Close the transport instead of reading its connection pointer here.
		common.Close(transport, socket)
		return fastAuth{}, err
	}
	auth := fastAuth{socket: socket, conn: conn, response: response}
	if response.StatusCode != fastAuthOK {
		auth.close()
		return fastAuth{}, fmt.Errorf("authentication failed, status code: %d", response.StatusCode)
	}
	return auth, nil
}

func raceFastAuth(ctx context.Context, attempt func(context.Context, int) (fastAuth, error)) (fastAuth, error) {
	winner, _, _, err := staggerDial(ctx, N.DefaultFallbackDelay, attempt, fastAuth.close, nil)
	return winner, err
}
