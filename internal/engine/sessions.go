// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

type deviceSessions struct {
	mu      sync.Mutex
	allowed map[string]bool
	active  map[*session]struct{}
}

type session struct {
	id     string
	closer io.Closer
	owner  *deviceSessions
	once   sync.Once
	err    error
}

func newDeviceSessions(ids []string) *deviceSessions {
	s := &deviceSessions{active: make(map[*session]struct{})}
	s.allow(ids)
	return s
}

func (s *deviceSessions) allow(ids []string) {
	allowed := make(map[string]bool, len(ids))
	for _, id := range ids {
		allowed[id] = true
	}
	s.mu.Lock()
	s.allowed = allowed
	var revoked []*session
	for conn := range s.active {
		if !allowed[conn.id] {
			revoked = append(revoked, conn)
		}
	}
	s.mu.Unlock()
	for _, conn := range revoked {
		conn.close()
	}
}

func (s *deviceSessions) track(id string, conn io.Closer) *session {
	tracked := &session{id: id, closer: conn, owner: s}
	s.mu.Lock()
	allowed := s.allowed[id]
	if allowed {
		s.active[tracked] = struct{}{}
	}
	s.mu.Unlock()
	if !allowed {
		tracked.close()
	}
	return tracked
}

func (s *session) close() error {
	s.once.Do(func() {
		s.owner.mu.Lock()
		delete(s.owner.active, s)
		s.owner.mu.Unlock()
		s.err = s.closer.Close()
	})
	return s.err
}

func (s *deviceSessions) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	if metadata.Inbound == RealityFrontTag {
		// The only destinations for this inbound are the local REALITY listeners.
		return conn
	}
	return &trackedTCP{Conn: conn, session: s.track(metadata.User, conn)}
}

func (s *deviceSessions) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	return &trackedUDP{PacketConn: conn, session: s.track(metadata.User, conn)}
}

func (s *deviceSessions) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

type trackedTCP struct {
	net.Conn
	session *session
}

func (c *trackedTCP) Close() error  { return c.session.close() }
func (c *trackedTCP) Upstream() any { return c.Conn }

type trackedUDP struct {
	N.PacketConn
	session *session
}

func (c *trackedUDP) Close() error  { return c.session.close() }
func (c *trackedUDP) Upstream() any { return c.PacketConn }
