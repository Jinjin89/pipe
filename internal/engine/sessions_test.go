// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"pipe/internal/overload"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type sessionTestRouter struct {
	adapter.Router
	calls atomic.Int32
	tcp   func(context.Context, net.Conn, adapter.InboundContext, N.CloseHandlerFunc)
	udp   func(context.Context, N.PacketConn, adapter.InboundContext, N.CloseHandlerFunc)
}

func (r *sessionTestRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.calls.Add(1)
	if r.tcp != nil {
		r.tcp(ctx, conn, metadata, onClose)
		return
	}
	_ = conn.Close()
	onClose(nil)
}

func (r *sessionTestRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.calls.Add(1)
	if r.udp != nil {
		r.udp(ctx, conn, metadata, onClose)
		return
	}
	_ = conn.Close()
	onClose(nil)
}

func requireSessionOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func pressSessions(g *overload.Guard) {
	for range 2 {
		g.RecordSample(overload.Snapshot{GoMemoryBytes: 85, GoMemoryLimit: 100})
	}
}

func TestAdmissionRefusalsSkipRouter(t *testing.T) {
	for _, name := range []string{"shed", "timeout", "caller cancellation", "revocation"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const wait = 50 * time.Millisecond
				g := overload.New(overload.Options{MaxWait: wait})
				defer g.Close()
				holder, err := g.Acquire(t.Context(), overload.ClassFlow)
				requireSessionOK(t, err)
				defer holder.Release()
				pressSessions(g)
				if name == "shed" {
					g.ObserveError(syscall.EMFILE)
				}
				sessions := newDeviceSessions([]string{"device"}, g)
				base := &sessionTestRouter{}
				router := sessions.wrapRouter(base)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				conn, peer := net.Pipe()
				defer conn.Close()
				defer peer.Close()
				requireSessionOK(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
				done := make(chan error, 1)
				go router.RouteConnectionEx(ctx, conn, adapter.InboundContext{User: "device"}, func(err error) { done <- err })
				synctest.Wait()
				if name != "shed" && g.Diagnostics().Waiters != 1 {
					t.Fatalf("expected a queued flow, got %+v", g.Diagnostics())
				}
				want := overload.ErrOverloaded
				switch name {
				case "timeout":
					time.Sleep(wait)
				case "caller cancellation":
					cancel()
					want = context.Canceled
				case "revocation":
					sessions.allow(nil)
					sessions.allow([]string{"device"})
					holder.Release()
					want = context.Canceled
				}
				synctest.Wait()
				select {
				case err := <-done:
					if !errors.Is(err, want) {
						t.Fatalf("refusal = %v, want %v", err, want)
					}
				default:
					t.Fatal("refusal did not call onClose")
				}
				if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("refused connection stayed open: %v", err)
				}
				if base.calls.Load() != 0 || g.Diagnostics().Waiters != 0 {
					t.Fatalf("refusal dispatched or left a waiter: %d, %+v", base.calls.Load(), g.Diagnostics())
				}
			})
		})
	}
}

type sessionPacket struct {
	N.PacketConn
	closes atomic.Int32
}

func (c *sessionPacket) Close() error                   { c.closes.Add(1); return nil }
func (*sessionPacket) SetWriteDeadline(time.Time) error { return nil }

func TestProbeReserveMatchesExactTCPDestination(t *testing.T) {
	for _, tc := range []struct {
		name, host string
		port       uint16
		udp, probe bool
	}{
		{"probe", ProbeDomain, 80, false, true},
		{"UDP", ProbeDomain, 80, true, false},
		{"wrong port", ProbeDomain, 443, false, false},
		{"wrong host", "other.invalid", 80, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := overload.New(overload.Options{ProbeReserve: 1})
			defer g.Close()
			g.ObserveError(syscall.EMFILE)
			var admitted net.Conn
			base := &sessionTestRouter{tcp: func(ctx context.Context, conn net.Conn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
				admitted = conn
				if overload.LeaseFromContext(ctx) == nil {
					t.Error("router did not receive the probe lease")
				}
			}}
			router := newDeviceSessions([]string{"device"}, g).wrapRouter(base)
			metadata := adapter.InboundContext{User: "device", Destination: M.Socksaddr{Fqdn: tc.host, Port: tc.port}}
			var reason error
			if tc.udp {
				packet := &sessionPacket{}
				router.RoutePacketConnectionEx(t.Context(), packet, metadata, func(err error) { reason = err })
				if packet.closes.Load() != 1 {
					t.Fatal("refused UDP connection did not close")
				}
			} else {
				conn, peer := net.Pipe()
				defer peer.Close()
				defer conn.Close()
				router.RouteConnectionEx(t.Context(), conn, metadata, func(err error) { reason = err })
			}
			if !tc.probe {
				if base.calls.Load() != 0 || !errors.Is(reason, overload.ErrOverloaded) {
					t.Fatalf("ordinary flow used the reserve: dispatches=%d, error=%v", base.calls.Load(), reason)
				}
				return
			}
			if d := g.Diagnostics(); base.calls.Load() != 1 || d.ActiveProbes != 1 || d.PendingDials != 0 {
				t.Fatalf("probe did not use the reserve: %+v", d)
			}
			requireSessionOK(t, admitted.Close())
			if d := g.Diagnostics(); d.ActiveProbes != 0 {
				t.Fatalf("probe close retained its lease: %+v", d)
			}
		})
	}
}

type halfCloseSessionConn struct {
	net.Conn
	halves, closes int
}

func (c *halfCloseSessionConn) CloseWrite() error { c.halves++; return nil }
func (c *halfCloseSessionConn) CloseRead() error  { c.halves++; return nil }
func (c *halfCloseSessionConn) Close() error      { c.closes++; return c.Conn.Close() }

func TestAdmissionTCPHalfCloseAndFinalization(t *testing.T) {
	g := overload.New(overload.Options{})
	defer g.Close()
	conn, peer := net.Pipe()
	defer peer.Close()
	defer conn.Close()
	inner := &halfCloseSessionConn{Conn: conn}
	var tracked net.Conn
	var flow context.Context
	var finish N.CloseHandlerFunc
	base := &sessionTestRouter{tcp: func(ctx context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
		tracked, flow, finish = conn, ctx, onClose
		if overload.LeaseFromContext(ctx) == nil {
			t.Error("router did not receive the flow lease")
		}
	}}
	router := newDeviceSessions([]string{"device"}, g).wrapRouter(base)
	callbacks := 0
	router.RouteConnectionEx(t.Context(), inner, adapter.InboundContext{User: "device"}, func(error) { callbacks++ })
	requireSessionOK(t, N.CloseWrite(tracked))
	requireSessionOK(t, N.CloseRead(tracked))
	if err := flow.Err(); err != nil {
		t.Fatalf("TCP half-close canceled routing: %v", err)
	}
	if d := g.Diagnostics(); inner.halves != 2 || inner.closes != 0 || d.ActiveFlows != 1 || d.PendingDials != 1 {
		t.Fatalf("half-close did not preserve the live flow: halves=%d, closes=%d, %+v", inner.halves, inner.closes, d)
	}
	finish(nil)
	finish(nil)
	if !errors.Is(flow.Err(), context.Canceled) {
		t.Fatal("final close left the routing context active")
	}
	if d := g.Diagnostics(); callbacks != 1 || d.ActiveFlows != 0 || d.PendingDials != 0 {
		t.Fatalf("final onClose did not release once: callbacks=%d, %+v", callbacks, d)
	}
	requireSessionOK(t, tracked.Close())
	requireSessionOK(t, tracked.Close())
	if inner.closes != 1 {
		t.Fatalf("wrapped connection closed %d times", inner.closes)
	}
}

type closeHookSessionConn struct {
	net.Conn
	beforeClose func()
}

func (c *closeHookSessionConn) Close() error {
	c.beforeClose()
	return c.Conn.Close()
}

func TestAdmissionRevocationCancelsDialBeforeClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		g := overload.New(overload.Options{})
		defer g.Close()
		sessions := newDeviceSessions([]string{"device"}, g)
		conn, peer := net.Pipe()
		defer conn.Close()
		defer peer.Close()
		var flow context.Context
		inner := &closeHookSessionConn{Conn: conn, beforeClose: func() {
			if !errors.Is(flow.Err(), context.Canceled) {
				t.Error("revocation closed the connection before canceling routing")
			}
		}}
		dialDone := make(chan error, 1)
		base := &sessionTestRouter{tcp: func(ctx context.Context, _ net.Conn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
			flow = ctx
			<-ctx.Done()
			dialDone <- ctx.Err()
		}}
		go sessions.wrapRouter(base).RouteConnectionEx(ctx, inner, adapter.InboundContext{User: "device"}, nil)
		synctest.Wait()
		if flow == nil || flow.Err() != nil || g.Diagnostics().PendingDials != 1 {
			t.Fatal("routing did not start with a live dial reservation")
		}
		sessions.allow(nil)
		synctest.Wait()
		select {
		case err := <-dialDone:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("revoked route returned %v", err)
			}
		default:
			t.Fatal("revoked route was still dialing")
		}
		if d := g.Diagnostics(); d.ActiveFlows != 0 || d.PendingDials != 0 {
			t.Fatalf("revoked route retained its lease: %+v", d)
		}
	})
}

func TestAdmissionDialFailureAndPacketCloseRelease(t *testing.T) {
	g := overload.New(overload.Options{})
	defer g.Close()
	dialErr := errors.New("fixture dial failure")
	var packet N.PacketConn
	base := &sessionTestRouter{
		tcp: func(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
			_ = N.CloseOnHandshakeFailure(conn, onClose, dialErr)
		},
		udp: func(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
			packet = conn
		},
	}
	router := newDeviceSessions([]string{"device"}, g).wrapRouter(base)
	metadata := adapter.InboundContext{User: "device"}
	conn, peer := net.Pipe()
	defer peer.Close()
	if err := router.RouteConnection(t.Context(), conn, metadata); !errors.Is(err, dialErr) {
		t.Fatalf("legacy route returned %v", err)
	}
	if d := g.Diagnostics(); d.ActiveFlows != 0 || d.PendingDials != 0 {
		t.Fatalf("failed dial retained its lease: %+v", d)
	}
	inner := &sessionPacket{}
	router.RoutePacketConnectionEx(t.Context(), inner, metadata, nil)
	requireSessionOK(t, packet.Close())
	requireSessionOK(t, packet.Close())
	if d := g.Diagnostics(); inner.closes.Load() != 1 || d.ActiveFlows != 0 || d.PendingDials != 0 {
		t.Fatalf("UDP close did not release once: closes=%d, %+v", inner.closes.Load(), d)
	}
}

func TestAdmissionAllowsRawRealityFrontWithoutCharging(t *testing.T) {
	g := overload.New(overload.Options{})
	defer g.Close()
	g.ObserveError(syscall.ENFILE)
	conn, peer := net.Pipe()
	defer peer.Close()
	defer conn.Close()
	base := &sessionTestRouter{tcp: func(ctx context.Context, routed net.Conn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
		if routed != conn || overload.LeaseFromContext(ctx) != nil {
			t.Error("raw REALITY hop was tracked")
		}
	}}
	router := newDeviceSessions(nil, g).wrapRouter(base)
	router.RouteConnectionEx(t.Context(), conn, adapter.InboundContext{Inbound: RealityFrontTag}, nil)
	if base.calls.Load() != 1 {
		t.Fatal("raw REALITY hop was shed under pressure")
	}
}

func TestAdmissionRacesRevocationShutdownAndFinalClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 16 {
			g := overload.New(overload.Options{})
			sessions := newDeviceSessions([]string{"live", "queued"}, g)
			var live net.Conn
			var finish N.CloseHandlerFunc
			base := &sessionTestRouter{tcp: func(_ context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
				if metadata.User == "live" {
					live, finish = conn, onClose
				} else {
					_ = conn.Close()
					onClose(nil)
				}
			}}
			router := sessions.wrapRouter(base)
			active, activePeer := net.Pipe()
			router.RouteConnectionEx(t.Context(), active, adapter.InboundContext{User: "live"}, nil)
			pressSessions(g)
			queued, queuedPeer := net.Pipe()
			var running sync.WaitGroup
			running.Go(func() { router.RouteConnectionEx(t.Context(), queued, adapter.InboundContext{User: "queued"}, nil) })
			synctest.Wait()
			if g.Diagnostics().Waiters != 1 {
				t.Fatal("flow did not queue before revocation and shutdown")
			}
			running.Go(func() { sessions.allow(nil); sessions.allow([]string{"live", "queued"}) })
			running.Go(func() { sessions.setAllowed(nil); g.Close() })
			running.Go(func() { _ = live.Close() })
			running.Go(func() { finish(nil) })
			running.Wait()
			_ = queuedPeer.Close()
			_ = activePeer.Close()
			if d := g.Diagnostics(); d.ActiveFlows != 0 || d.PendingDials != 0 || d.Waiters != 0 || len(sessions.active) != 0 || len(sessions.waiting) != 0 || sessions.allowed != nil {
				t.Fatalf("shutdown retained or resurrected work: %+v", d)
			}
		}
	})
}

func echoAdmittedStream(ctx context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	overload.LeaseFromContext(ctx).DialDone(false)
	go func() {
		_, err := io.Copy(conn, conn)
		_ = conn.Close()
		onClose(err)
	}()
}

type legacyMuxAdmissionHandler struct {
	router      adapter.Router
	inboundType string
	handled     chan<- struct{}
}

func (h legacyMuxAdmissionHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _, dest M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.router.RouteConnectionEx(ctx, conn, adapter.InboundContext{InboundType: h.inboundType, User: "device", Destination: dest}, onClose)
	if h.handled != nil {
		h.handled <- struct{}{}
	}
}

func (h legacyMuxAdmissionHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, _, dest M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.router.RoutePacketConnectionEx(ctx, conn, adapter.InboundContext{InboundType: h.inboundType, User: "device", Destination: dest}, onClose)
}

func serveLegacyMux(ctx context.Context, conn net.Conn, handler legacyMuxAdmissionHandler) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = vmess.HandleMuxConnection(ctx, conn, M.Socksaddr{}, handler)
	}()
	return done
}

func writeLegacyMuxFrame(t *testing.T, conn net.Conn, id uint16, status, payload byte) {
	t.Helper()
	frame := binary.BigEndian.AppendUint16([]byte{0, 0}, id)
	frame = append(frame, status, vmess.OptionData)
	if status == vmess.StatusNew {
		var address bytes.Buffer
		requireSessionOK(t, vmess.AddressSerializer.WriteAddrPort(&address, M.Socksaddr{Fqdn: "fixture.invalid", Port: 443}))
		frame = append(frame, vmess.NetworkTCP)
		frame = append(frame, address.Bytes()...)
	}
	binary.BigEndian.PutUint16(frame, uint16(len(frame)-2))
	frame = append(frame, 0, 1, payload)
	_, err := conn.Write(frame)
	requireSessionOK(t, err)
}

func readLegacyMuxFrame(t *testing.T, conn net.Conn, id uint16, status, want byte) {
	t.Helper()
	var header [6]byte
	_, err := io.ReadFull(conn, header[:])
	requireSessionOK(t, err)
	if binary.BigEndian.Uint16(header[:2]) != 4 || binary.BigEndian.Uint16(header[2:4]) != id || header[4] != status {
		t.Fatalf("unexpected frame for stream %d: %v", id, header)
	}
	if status == vmess.StatusKeep {
		var body [3]byte
		_, err := io.ReadFull(conn, body[:])
		requireSessionOK(t, err)
		if header[5] != vmess.OptionData || body != [3]byte{0, 1, want} {
			t.Fatalf("stream %d echo = %v, want %q", id, body, want)
		}
	}
}

func TestLegacyMuxRefusalPreservesSiblingProgress(t *testing.T) {
	for _, inboundType := range []string{C.TypeVMess, C.TypeVLESS} {
		t.Run(inboundType, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := overload.New(overload.Options{MaxWait: time.Minute})
				defer g.Close()
				base := &sessionTestRouter{tcp: echoAdmittedStream}
				router := newDeviceSessions([]string{"device"}, g).wrapRouter(base)
				client, server := net.Pipe()
				done := serveLegacyMux(t.Context(), server, legacyMuxAdmissionHandler{router: router, inboundType: inboundType})
				defer func() { _ = client.Close(); _ = server.Close(); <-done }()
				requireSessionOK(t, client.SetDeadline(time.Now().Add(time.Second)))
				writeLegacyMuxFrame(t, client, 1, vmess.StatusNew, 'a')
				readLegacyMuxFrame(t, client, 1, vmess.StatusKeep, 'a')
				pressSessions(g)
				// StatusNew carries data that would park the parent's synchronous pipe.
				writeLegacyMuxFrame(t, client, 2, vmess.StatusNew, 'x')
				readLegacyMuxFrame(t, client, 2, vmess.StatusEnd, 0)
				writeLegacyMuxFrame(t, client, 1, vmess.StatusKeep, 'b')
				readLegacyMuxFrame(t, client, 1, vmess.StatusKeep, 'b')
				if base.calls.Load() != 1 || g.Diagnostics().Waiters != 0 {
					t.Fatalf("mux dispatched or parked the refused sibling: %d, %+v", base.calls.Load(), g.Diagnostics())
				}
			})
		})
	}
}

type countedMuxTransport struct {
	net.Conn
	writeStarted   chan struct{}
	writes, closes atomic.Int32
}

func (c *countedMuxTransport) Write(payload []byte) (int, error) {
	if c.writes.Add(1) == 1 && c.writeStarted != nil {
		close(c.writeStarted)
	}
	return c.Conn.Write(payload)
}

func (c *countedMuxTransport) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// A framed transport can write on Close, just as the WebSocket transport does.
type muxFramedConn struct{ net.Conn }

func (c *muxFramedConn) Upstream() any { return c.Conn }
func (c *muxFramedConn) Close() error {
	_, _ = c.Write([]byte{0})
	return c.Conn.Close()
}

func TestLegacyMuxRefusalQueuesCloseBehindBlockedWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	g := overload.New(overload.Options{})
	defer g.Close()
	base := &sessionTestRouter{tcp: echoAdmittedStream}
	sessions := newDeviceSessions([]string{"device"}, g)
	router := sessions.wrapRouter(base)
	client, server := net.Pipe()
	transport := &countedMuxTransport{Conn: server, writeStarted: make(chan struct{})}
	handled := make(chan struct{}, 2)
	done := serveLegacyMux(ctx, &muxFramedConn{transport}, legacyMuxAdmissionHandler{router: router, inboundType: C.TypeVMess, handled: handled})
	defer func() { _ = client.Close(); _ = server.Close(); <-done }()
	requireSessionOK(t, client.SetDeadline(deadline))
	writeLegacyMuxFrame(t, client, 1, vmess.StatusNew, 'a')
	select {
	case <-transport.writeStarted:
	case <-ctx.Done():
		t.Fatal("mux did not start a blocked sibling write")
	}
	select {
	case <-handled:
	case <-ctx.Done():
		t.Fatal("established mux child did not reach routing")
	}
	pressSessions(g)
	writeLegacyMuxFrame(t, client, 2, vmess.StatusNew, 'x')
	select {
	case <-handled:
	case <-ctx.Done():
		t.Fatal("refusal waited for the stalled parent writer")
	}
	if transport.closes.Load() != 0 || base.calls.Load() != 1 {
		t.Fatal("refusing the mux child closed its parent or dispatched the child")
	}
	readLegacyMuxFrame(t, client, 1, vmess.StatusKeep, 'a')
	readLegacyMuxFrame(t, client, 2, vmess.StatusEnd, 0)
	writeLegacyMuxFrame(t, client, 1, vmess.StatusKeep, 'b')
	readLegacyMuxFrame(t, client, 1, vmess.StatusKeep, 'b')
	if d := g.Diagnostics(); transport.closes.Load() != 0 || d.ActiveFlows != 1 || d.Waiters != 0 {
		t.Fatalf("sibling did not stay active after backpressure cleared: %+v", d)
	}
}

func TestLegacyMuxRefusalClosesRevokedParentOutsideLock(t *testing.T) {
	for _, state := range []string{"revocation", "shutdown"} {
		t.Run(state, func(t *testing.T) {
			sessions := newDeviceSessions([]string{"device"}, nil)
			if state == "shutdown" {
				sessions.setAllowed(nil)
			} else {
				sessions.allow(nil)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			client, server := net.Pipe()
			closed := make(chan struct{})
			frameSent := make(chan struct{})
			transport := &closeHookSessionConn{Conn: server, beforeClose: func() {
				if sessions.mu.TryLock() {
					if len(sessions.muxClosers) != 0 {
						t.Error("refusal created a mux close queue for the revoked device")
					}
					sessions.mu.Unlock()
				} else {
					t.Error("refusal closed the mux parent with the session lock held")
				}
				// The mux handler can refuse the child before reading the frame payload.
				select {
				case <-frameSent:
				case <-ctx.Done():
				}
				close(closed)
			}}
			base := &sessionTestRouter{}
			handled := make(chan struct{}, 1)
			done := serveLegacyMux(ctx, transport, legacyMuxAdmissionHandler{router: sessions.wrapRouter(base), inboundType: C.TypeVMess, handled: handled})
			defer func() {
				cancel()
				_ = client.Close()
				_ = server.Close()
				<-done
			}()
			deadline, _ := ctx.Deadline()
			requireSessionOK(t, client.SetWriteDeadline(deadline))
			writeLegacyMuxFrame(t, client, 1, vmess.StatusNew, 'x')
			close(frameSent)
			select {
			case <-handled:
			case <-ctx.Done():
				t.Fatal("revoked mux refusal did not return")
			}
			select {
			case <-closed:
			default:
				t.Fatal("revoked mux refusal left the parent open")
			}
			sessions.mu.Lock()
			queues := len(sessions.muxClosers)
			sessions.mu.Unlock()
			if queues != 0 || base.calls.Load() != 0 {
				t.Fatalf("revoked mux refusal left work behind: queues=%d dispatches=%d", queues, base.calls.Load())
			}
		})
	}
}

func TestLegacyMuxCloseQueuesAreBoundedAndDrainedOnRevocation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sessions := newDeviceSessions([]string{"device"}, nil)
		defer sessions.allow(nil)
		parent := &closeTrackConn{closed: make(chan struct{})}
		var completed atomic.Int32
		blockingClose := func(parent *closeTrackConn) func() {
			return func() { <-parent.closed; completed.Add(1) }
		}
		if !sessions.enqueueMuxClose(parent, "device", blockingClose(parent)) {
			t.Fatal("first mux close was rejected")
		}
		synctest.Wait()
		for range muxCloseQueueSize {
			if !sessions.enqueueMuxClose(parent, "device", blockingClose(parent)) {
				t.Fatal("mux close queue filled too early")
			}
		}
		if sessions.enqueueMuxClose(parent, "device", blockingClose(parent)) {
			t.Fatal("mux close queue exceeded its per-parent limit")
		}
		for range maxMuxCloseQueues - 1 {
			other := &closeTrackConn{closed: make(chan struct{})}
			if !sessions.enqueueMuxClose(other, "device", blockingClose(other)) {
				t.Fatal("global mux close queue limit reached too early")
			}
		}
		if sessions.enqueueMuxClose(&closeTrackConn{closed: make(chan struct{})}, "device", func() {}) {
			t.Fatal("mux close queues exceeded the global limit")
		}
		sessions.allow(nil)
		synctest.Wait()
		if queues := len(sessions.muxClosers); queues != 0 || completed.Load() != muxCloseQueueSize+maxMuxCloseQueues {
			t.Fatalf("revocation left mux close work behind: queues=%d completed=%d", queues, completed.Load())
		}
	})
}

func TestLegacyMuxRevocationAndShutdownInterruptBlockedWriter(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		name := "revocation"
		if shutdown {
			name = "shutdown"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			g := overload.New(overload.Options{})
			defer g.Close()
			instance, err := New(ctx, Options{Server: true, DeviceIDs: []string{"device", "other"}, Overload: g})
			requireSessionOK(t, err)
			sessions := instance.sessions
			client, server := net.Pipe()
			transport := &countedMuxTransport{Conn: server, writeStarted: make(chan struct{})}
			base := &sessionTestRouter{tcp: func(ctx context.Context, conn net.Conn, md adapter.InboundContext, onClose N.CloseHandlerFunc) {
				if md.User == "device" {
					echoAdmittedStream(ctx, conn, md, onClose)
				}
			}}
			router := sessions.wrapRouter(base)
			handled := make(chan struct{}, 2)
			done := serveLegacyMux(ctx, &muxFramedConn{transport}, legacyMuxAdmissionHandler{router: router, inboundType: C.TypeVMess, handled: handled})
			defer func() { _ = client.Close(); _ = server.Close(); <-done; _ = instance.Close() }()
			other, peer := net.Pipe()
			defer other.Close()
			defer peer.Close()
			requireSessionOK(t, client.SetWriteDeadline(deadline))
			requireSessionOK(t, peer.SetReadDeadline(deadline))
			router.RouteConnectionEx(ctx, other, adapter.InboundContext{User: "other"}, nil)
			writeLegacyMuxFrame(t, client, 1, vmess.StatusNew, 'a')
			writeLegacyMuxFrame(t, client, 2, vmess.StatusNew, 'b')
			for range 2 {
				select {
				case <-handled:
				case <-ctx.Done():
					t.Fatal("mux child did not reach routing")
				}
			}
			select {
			case <-transport.writeStarted:
			case <-ctx.Done():
				t.Fatal("mux fixture did not start a blocked write")
			}
			if g.Diagnostics().ActiveFlows != 3 {
				t.Fatal("mux fixture did not track three active sessions")
			}
			drained := make(chan error, 1)
			go func() {
				if shutdown {
					drained <- instance.Close()
					return
				}
				sessions.allow(nil)
				drained <- nil
			}()
			select {
			case err := <-drained:
				requireSessionOK(t, err)
			case <-ctx.Done():
				t.Fatal("draining stalled behind the blocked mux writer")
			}
			if transport.closes.Load() != 1 {
				t.Fatal("draining did not interrupt the shared mux parent once")
			}
			if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("draining left the other session open: %v", err)
			}
			if d := g.Diagnostics(); d.ActiveFlows != 0 || d.PendingDials != 0 {
				t.Fatalf("draining retained active sessions: %+v", d)
			}
		})
	}
}

func TestBulkSessionRevocationBoundsCloseWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := overload.New(overload.Options{})
		defer g.Close()
		sessions := newDeviceSessions([]string{"device"}, g)
		base := &sessionTestRouter{tcp: func(context.Context, net.Conn, adapter.InboundContext, N.CloseHandlerFunc) {}}
		router := sessions.wrapRouter(base)
		unblock := make(chan struct{})
		release := sync.OnceFunc(func() { close(unblock) })
		defer release()
		const count = 96
		var started atomic.Int32
		for range count {
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()
			inner := &closeHookSessionConn{Conn: conn, beforeClose: func() {
				started.Add(1)
				<-unblock
			}}
			router.RouteConnectionEx(t.Context(), inner, adapter.InboundContext{User: "device"}, nil)
		}
		done := make(chan struct{})
		go func() { sessions.allow(nil); close(done) }()
		synctest.Wait()
		if n := started.Load(); n != maxSessionCloseWorkers {
			t.Fatalf("bulk revocation started %d closes, want %d concurrent closes", n, maxSessionCloseWorkers)
		}
		release()
		<-done
		if d := g.Diagnostics(); started.Load() != count || d.ActiveFlows != 0 || d.PendingDials != 0 {
			t.Fatalf("bulk revocation left sessions behind: closed=%d, %+v", started.Load(), d)
		}
	})
}

type admissionQUICStream struct {
	*quic.Stream
	parent *quic.Conn
}

func (s *admissionQUICStream) LocalAddr() net.Addr  { return s.parent.LocalAddr() }
func (s *admissionQUICStream) RemoteAddr() net.Addr { return s.parent.RemoteAddr() }
func (s *admissionQUICStream) Close() error {
	s.CancelRead(0)
	return s.Stream.Close()
}

func admissionQUICTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	requireSessionOK(t, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, private)
	requireSessionOK(t, err)
	cert, err := x509.ParseCertificate(der)
	requireSessionOK(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	protocols := []string{"pipe-admission-test"}
	return &tls.Config{NextProtos: protocols, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}},
		&tls.Config{NextProtos: protocols, RootCAs: roots, ServerName: "localhost"}
}

func openAdmissionQUIC(t *testing.T, ctx context.Context) (server, client *quic.Conn) {
	t.Helper()
	serverTLS, clientTLS := admissionQUICTLS(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	requireSessionOK(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	client, err = quic.DialAddr(ctx, listener.Addr().String(), clientTLS, nil)
	requireSessionOK(t, err)
	t.Cleanup(func() { _ = client.CloseWithError(0, "") })
	server, err = listener.Accept(ctx)
	requireSessionOK(t, err)
	t.Cleanup(func() { _ = server.CloseWithError(0, "") })
	return server, client
}

func TestQUICQueuedStreamPreservesSiblingProgress(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	server, client := openAdmissionQUIC(t, ctx)
	g := overload.New(overload.Options{MaxWait: time.Minute})
	sessions := newDeviceSessions([]string{"device"}, g)
	base := &sessionTestRouter{tcp: echoAdmittedStream}
	router := sessions.wrapRouter(base)
	done := make(chan struct{})
	refused := make(chan error, 1)
	go func() {
		defer close(done)
		var handlers sync.WaitGroup
		defer handlers.Wait()
		for idx := range 2 {
			stream, err := server.AcceptStream(ctx)
			if err != nil {
				return
			}
			handlers.Go(func() {
				conn := &admissionQUICStream{Stream: stream, parent: server}
				var onClose N.CloseHandlerFunc
				if idx == 1 {
					onClose = func(err error) { refused <- err }
				}
				router.RouteConnectionEx(ctx, conn, adapter.InboundContext{InboundType: C.TypeHysteria2, User: "device"}, onClose)
			})
		}
	}()
	defer func() { cancel(); g.Close(); sessions.setAllowed(nil); <-done }()
	first, err := client.OpenStreamSync(ctx)
	requireSessionOK(t, err)
	requireSessionOK(t, first.SetDeadline(deadline))
	echo := func(value byte) {
		t.Helper()
		_, err := first.Write([]byte{value})
		requireSessionOK(t, err)
		var result [1]byte
		_, err = io.ReadFull(first, result[:])
		requireSessionOK(t, err)
		if result[0] != value {
			t.Fatalf("echo = %q, want %q", result[0], value)
		}
	}
	echo('a')
	pressSessions(g)
	second, err := client.OpenStreamSync(ctx)
	requireSessionOK(t, err)
	requireSessionOK(t, second.SetDeadline(deadline))
	_, err = second.Write([]byte{'x'})
	requireSessionOK(t, err)
	watch := time.NewTicker(time.Millisecond)
	defer watch.Stop()
	for g.Diagnostics().Waiters != 1 {
		select {
		case <-ctx.Done():
			t.Fatalf("QUIC stream did not queue: %+v", g.Diagnostics())
		case <-watch.C:
		}
	}
	echo('b')
	if g.Diagnostics().Waiters != 1 || base.calls.Load() != 1 {
		t.Fatalf("queued QUIC stream reached the router: %d, %+v", base.calls.Load(), g.Diagnostics())
	}
	second.CancelRead(0)
	select {
	case err := <-refused:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("aborted queued stream returned %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("peer abort did not cancel the queued QUIC stream: %+v", g.Diagnostics())
	}
	if d := g.Diagnostics(); d.Waiters != 0 || base.calls.Load() != 1 {
		t.Fatalf("aborted stream reached the router or remained queued: %+v", d)
	}
	echo('c')
}

func TestQUICAdmissionPeerAbortCancelsDialAfterGracefulFIN(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	server, client := openAdmissionQUIC(t, ctx)
	peerStream, err := client.OpenStreamSync(ctx)
	requireSessionOK(t, err)
	requireSessionOK(t, peerStream.SetWriteDeadline(deadline))
	_, err = peerStream.Write([]byte{'x'})
	requireSessionOK(t, err)
	stream, err := server.AcceptStream(ctx)
	requireSessionOK(t, err)
	requireSessionOK(t, stream.SetReadDeadline(deadline))
	g := overload.New(overload.Options{})
	defer g.Close()
	sessions := newDeviceSessions([]string{"device"}, g)
	started := make(chan context.Context, 1)
	done := make(chan error, 1)
	base := &sessionTestRouter{tcp: func(ctx context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
		defer conn.Close()
		if _, err := io.Copy(io.Discard, conn); err != nil {
			onClose(err)
			return
		}
		started <- ctx
		<-ctx.Done() // Simulate a dial that waits until it is canceled.
		onClose(ctx.Err())
	}}
	conn := &admissionQUICStream{Stream: stream, parent: server}
	go sessions.wrapRouter(base).RouteConnectionEx(ctx, conn, adapter.InboundContext{InboundType: C.TypeHysteria2, User: "device"}, func(err error) { done <- err })
	requireSessionOK(t, peerStream.Close())
	select {
	case flow := <-started:
		if flow.Err() != nil || stream.Context().Err() != nil || g.Diagnostics().PendingDials != 1 {
			t.Fatal("graceful upload FIN canceled the live flow")
		}
	case err := <-done:
		t.Fatalf("graceful upload FIN ended routing: %v", err)
	case <-ctx.Done():
		t.Fatal("router never observed the graceful upload FIN")
	}
	peerStream.CancelRead(0)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("aborted in-flight dial returned %v", err)
		}
	case <-ctx.Done():
		t.Fatal("peer abort did not cancel the in-flight dial")
	}
	if d := g.Diagnostics(); d.ActiveFlows != 0 || d.PendingDials != 0 {
		t.Fatalf("aborted dial retained its reservation: %+v", d)
	}
}
