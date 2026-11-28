// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"pipe/internal/overload"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
)

var errDeviceRevoked = errors.New("device authorization revoked")

const (
	refusalWriteTimeout    = time.Second
	muxCloseQueueSize      = 16
	maxMuxCloseQueues      = 64
	maxSessionCloseWorkers = 32
)

type deviceSessions struct {
	mu         sync.Mutex
	allowed    map[string]bool // nil after shutdown
	active     map[*session]struct{}
	waiting    map[*session]struct{}
	muxClosers map[io.Closer]*muxCloseQueue
	guard      *overload.Guard
}

type muxCloseQueue struct {
	deviceID string
	pending  chan func()
}

type session struct {
	id         string
	closer     io.Closer
	parent     io.Closer
	owner      *deviceSessions
	ctx        context.Context
	cancel     context.CancelFunc
	stopAbort  func() bool
	lease      *overload.Lease
	finishOnce sync.Once
	closeOnce  sync.Once
	err        error
}

func newDeviceSessions(ids []string, guard *overload.Guard) *deviceSessions {
	return &deviceSessions{allowed: deviceSet(ids), active: make(map[*session]struct{}), waiting: make(map[*session]struct{}), guard: guard}
}

func deviceSet(ids []string) map[string]bool {
	allowed := make(map[string]bool, len(ids))
	for _, id := range ids {
		allowed[id] = true
	}
	return allowed
}

func (s *deviceSessions) allow(ids []string) { s.setAllowed(deviceSet(ids)) }

func (s *deviceSessions) setAllowed(allowed map[string]bool) {
	closeSessions(s.revokeDisallowed(allowed))
}

// Cancel routing and interrupt mux transports before any child close can block.
func (s *deviceSessions) revokeDisallowed(allowed map[string]bool) []*session {
	s.mu.Lock()
	if s.allowed == nil {
		s.mu.Unlock()
		return nil
	}
	s.allowed = allowed
	var waiters []*session
	for conn := range s.waiting {
		if !allowed[conn.id] {
			delete(s.waiting, conn)
			waiters = append(waiters, conn)
		}
	}
	var revoked []*session
	for conn := range s.active {
		if !allowed[conn.id] {
			revoked = append(revoked, conn)
		}
	}
	parents := make(map[io.Closer]struct{})
	for parent, queue := range s.muxClosers {
		if !allowed[queue.deviceID] {
			parents[parent] = struct{}{}
		}
	}
	s.mu.Unlock()
	for _, sessions := range [2][]*session{waiters, revoked} {
		for _, conn := range sessions {
			conn.cancel()
			if conn.parent != nil {
				parents[conn.parent] = struct{}{}
			}
		}
	}
	for parent := range parents {
		_ = parent.Close()
	}
	return revoked
}

func closeSessions(revoked []*session) {
	var closing sync.WaitGroup
	var next atomic.Int64
	for range min(len(revoked), maxSessionCloseWorkers) {
		closing.Go(func() {
			for idx := next.Add(1) - 1; idx < int64(len(revoked)); idx = next.Add(1) - 1 {
				_ = revoked[idx].close()
			}
		})
	}
	closing.Wait()
}

func (s *deviceSessions) admit(ctx context.Context, id string, conn io.Closer, class overload.Class) (*session, error) {
	s.mu.Lock()
	if !s.allowed[id] {
		s.mu.Unlock()
		return nil, errDeviceRevoked
	}
	flowCtx, cancel := context.WithCancel(ctx)
	tracked := &session{id: id, closer: conn, parent: muxParentCloser(conn), owner: s, ctx: flowCtx, cancel: cancel}
	var abortCtx context.Context
	if stream, ok := common.Cast[interface{ Context() context.Context }](conn); ok {
		abortCtx = stream.Context()
		if abortCtx != nil {
			// QUIC's send-side context stays live when the peer sends a FIN.
			tracked.stopAbort = context.AfterFunc(abortCtx, cancel)
			if abortCtx.Err() != nil {
				cancel()
			}
		}
	}
	var err error
	if s.guard != nil {
		s.waiting[tracked] = struct{}{}
		s.mu.Unlock()
		tracked.lease, err = s.guard.Acquire(flowCtx, class)
		s.mu.Lock()
		_, waiting := s.waiting[tracked]
		delete(s.waiting, tracked)
		// Removal invalidates this waiter even if the same ID has been re-added.
		if err == nil && (!waiting || !s.allowed[id]) {
			err = errDeviceRevoked
		}
	}
	if err == nil && abortCtx != nil && abortCtx.Err() != nil {
		cancel()
	}
	if err == nil {
		err = flowCtx.Err()
	}
	if err != nil {
		s.mu.Unlock()
		tracked.finish()
		return nil, err
	}
	s.active[tracked] = struct{}{}
	s.mu.Unlock()
	return tracked, nil
}

func (s *session) finish() {
	s.finishOnce.Do(func() {
		if s.stopAbort != nil {
			s.stopAbort()
		}
		s.cancel()
		s.owner.mu.Lock()
		delete(s.owner.active, s)
		s.owner.mu.Unlock()
		s.lease.Release()
	})
}

func (s *session) close() error {
	s.closeOnce.Do(func() {
		s.err = s.closer.Close()
		s.finish()
	})
	return s.err
}

func (s *session) routing(onClose N.CloseHandlerFunc) (context.Context, N.CloseHandlerFunc) {
	ctx := s.ctx
	if s.lease != nil {
		ctx = overload.WithLease(ctx, s.lease)
	}
	return ctx, N.OnceClose(N.AppendClose(onClose, func(error) { s.finish() }))
}

type serverRouter struct {
	adapter.Router
	sessions *deviceSessions
}

func (s *deviceSessions) wrapRouter(base adapter.Router) adapter.Router {
	return &serverRouter{Router: base, sessions: s}
}

func admissionClass(metadata adapter.InboundContext, conn any, onClose N.CloseHandlerFunc, tcp bool) overload.Class {
	if tcp && metadata.Destination.Fqdn == ProbeDomain && metadata.Destination.Port == 80 {
		return overload.ClassProbe
	}
	// Legacy mux children use synchronous pipes on the parent receive loop.
	if _, upstream := conn.(common.WithUpstream); (metadata.InboundType == C.TypeVMess || metadata.InboundType == C.TypeVLESS) && onClose == nil && !upstream {
		return overload.ClassFlowNoWait
	}
	return overload.ClassFlow
}

func muxParentCloser(conn any) io.Closer {
	child, ok := conn.(interface{ UpstreamWriter() any })
	if !ok {
		return nil
	}
	if _, upstream := conn.(common.WithUpstream); upstream {
		return nil
	}
	writer := child.UpstreamWriter()
	// Interrupt the socket directly. Wrappers such as WebSocket write on Close.
	if transport, ok := common.Top(writer).(net.Conn); ok {
		return transport
	}
	parent, _ := common.Cast[net.Conn](writer)
	return parent
}

func (s *deviceSessions) enqueueMuxClose(parent io.Closer, deviceID string, closeChild func()) bool {
	s.mu.Lock()
	if !s.allowed[deviceID] {
		s.mu.Unlock()
		_ = parent.Close()
		return false
	}
	defer s.mu.Unlock()
	queue := s.muxClosers[parent]
	if queue == nil {
		if len(s.muxClosers) >= maxMuxCloseQueues {
			return false
		}
		if s.muxClosers == nil {
			s.muxClosers = make(map[io.Closer]*muxCloseQueue)
		}
		queue = &muxCloseQueue{deviceID: deviceID, pending: make(chan func(), muxCloseQueueSize)}
		s.muxClosers[parent] = queue
		go s.flushMuxCloses(parent, queue)
	}
	select {
	case queue.pending <- closeChild:
		return true
	default:
		return false
	}
}

func (s *deviceSessions) flushMuxCloses(parent io.Closer, queue *muxCloseQueue) {
	for {
		s.mu.Lock()
		select {
		case closeChild := <-queue.pending:
			s.mu.Unlock()
			closeChild()
		default:
			delete(s.muxClosers, parent)
			s.mu.Unlock()
			return
		}
	}
}

func (s *deviceSessions) rejectConn(conn interface {
	io.Closer
	SetWriteDeadline(time.Time) error
}, deviceID string, onClose N.CloseHandlerFunc, err error) {
	if parent := muxParentCloser(conn); parent != nil {
		// Mux Close detaches the child and can then block on the shared writer.
		if !s.enqueueMuxClose(parent, deviceID, func() { _ = N.CloseOnHandshakeFailure(conn, onClose, err) }) && onClose != nil {
			onClose(err)
		}
		return
	}
	if conn.SetWriteDeadline(time.Now().Add(refusalWriteTimeout)) == nil {
		_ = N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	timer := time.NewTimer(refusalWriteTimeout)
	defer timer.Stop()
	done := make(chan struct{})
	go func() {
		_ = N.CloseOnHandshakeFailure(conn, onClose, err)
		close(done)
	}()
	select {
	case <-done:
	case <-timer.C:
		_ = conn.Close()
		<-done
	}
}

func (r *serverRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if metadata.Inbound == RealityFrontTag {
		r.Router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	tracked, err := r.sessions.admit(ctx, metadata.User, conn, admissionClass(metadata, conn, onClose, true))
	if err != nil {
		r.sessions.rejectConn(conn, metadata.User, onClose, err)
		return
	}
	ctx, onClose = tracked.routing(onClose)
	r.Router.RouteConnectionEx(ctx, &trackedTCP{Conn: conn, session: tracked}, metadata, onClose)
}

func (r *serverRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if metadata.Inbound == RealityFrontTag {
		r.Router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	tracked, err := r.sessions.admit(ctx, metadata.User, conn, admissionClass(metadata, conn, onClose, false))
	if err != nil {
		r.sessions.rejectConn(conn, metadata.User, onClose, err)
		return
	}
	ctx, onClose = tracked.routing(onClose)
	r.Router.RoutePacketConnectionEx(ctx, &trackedUDP{PacketConn: conn, session: tracked}, metadata, onClose)
}

func (r *serverRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	if metadata.Inbound == RealityFrontTag {
		return r.Router.RouteConnection(ctx, conn, metadata)
	}
	return waitForRoute(ctx, func(onClose N.CloseHandlerFunc) { r.RouteConnectionEx(ctx, conn, metadata, onClose) })
}

func (r *serverRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	if metadata.Inbound == RealityFrontTag {
		return r.Router.RoutePacketConnection(ctx, conn, metadata)
	}
	return waitForRoute(ctx, func(onClose N.CloseHandlerFunc) { r.RoutePacketConnectionEx(ctx, conn, metadata, onClose) })
}

func waitForRoute(ctx context.Context, route func(N.CloseHandlerFunc)) error {
	done := make(chan error, 1)
	route(func(err error) { done <- err })
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

type trackedTCP struct {
	net.Conn
	session *session
}

func (c *trackedTCP) Close() error            { return c.session.close() }
func (c *trackedTCP) Upstream() any           { return c.Conn }
func (c *trackedTCP) ReaderReplaceable() bool { return true }
func (c *trackedTCP) WriterReplaceable() bool { return true }

type trackedUDP struct {
	N.PacketConn
	session *session
}

func (c *trackedUDP) Close() error  { return c.session.close() }
func (c *trackedUDP) Upstream() any { return c.PacketConn }
