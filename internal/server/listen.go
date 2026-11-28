// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"

	"pipe/internal/overload"
)

func guardedListener(ctx context.Context, inner net.Listener, guard *overload.Guard) net.Listener {
	if guard == nil {
		return inner
	}
	ctx, cancel := context.WithCancel(ctx)
	return &overloadListener{Listener: inner, ctx: ctx, cancel: cancel, guard: guard}
}

type overloadListener struct {
	net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	guard  *overload.Guard
}

func (l *overloadListener) Accept() (net.Conn, error) {
	for {
		if err := l.guard.WaitAccept(l.ctx); err != nil {
			return nil, err
		}
		conn, err := l.Listener.Accept()
		if err != nil {
			l.guard.ObserveError(err)
			return nil, err
		}
		if l.guard.Emergency() {
			// Emergency began while Accept was waiting. Close the socket before pausing.
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

func (l *overloadListener) Close() error {
	l.cancel()
	return l.Listener.Close()
}

func emergencyLimitListener(inner net.Listener, guard *overload.Guard, limit int) net.Listener {
	if guard == nil {
		return inner
	}
	return &emergencyLimitedListener{Listener: inner, guard: guard, limit: int64(limit)}
}

type emergencyLimitedListener struct {
	net.Listener
	guard  *overload.Guard
	limit  int64
	active atomic.Int64
}

func (l *emergencyLimitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			l.guard.ObserveError(err)
			return nil, err
		}
		if l.active.Add(1) > l.limit && l.guard.Emergency() {
			_ = conn.Close()
			l.active.Add(-1)
			continue
		}
		return &emergencyLimitedConn{Conn: conn, active: &l.active}, nil
	}
}

type emergencyLimitedConn struct {
	net.Conn
	active  *atomic.Int64
	release sync.Once
}

func (c *emergencyLimitedConn) Close() error {
	err := c.Conn.Close()
	c.release.Do(func() { c.active.Add(-1) })
	return err
}

func bindWithIPv4Fallback[T any](host string, bind func(string) (T, error)) (T, string, error) {
	listener, err := bind(host)
	if host == "::" && ipv6Unavailable(err) {
		host = "0.0.0.0"
		listener, err = bind(host)
	}
	return listener, host, err
}

func listenTCP(host string, port uint16, listen func(string, string) (net.Listener, error)) (net.Listener, error) {
	listener, _, err := bindWithIPv4Fallback(host, func(address string) (net.Listener, error) {
		network := "tcp"
		if address == "0.0.0.0" {
			network = "tcp4"
		}
		return listen(network, addrPort(address, port))
	})
	return listener, err
}

func ipv6Unavailable(err error) bool {
	const (
		winsockFamilyUnsupported  = syscall.Errno(10047)
		winsockAddressUnavailable = syscall.Errno(10049)
	)
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) ||
		runtime.GOOS == "windows" && (errors.Is(err, winsockFamilyUnsupported) || errors.Is(err, winsockAddressUnavailable))
}

func portInUse(err error) bool {
	const winsockAddressInUse = syscall.Errno(10048)
	return errors.Is(err, syscall.EADDRINUSE) || runtime.GOOS == "windows" && errors.Is(err, winsockAddressInUse)
}
