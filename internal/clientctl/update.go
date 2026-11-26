// SPDX-License-Identifier: GPL-3.0-or-later

package clientctl

import (
	"context"
	"net"

	"pipe/internal/update"
)

// UpdateSession pins an update to the live engine and its selected tier.
type UpdateSession struct {
	session *session
	tier    string
	engine  interface {
		DialUpdate(context.Context, string, string, string) (net.Conn, error)
	}
}

func (c *Controller) BindUpdateSession() (*UpdateSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.current
	tier := c.activeTier()
	if s == nil || tier == "" || !s.opts.UsesProxy() {
		return nil, update.ErrTunnelUnavailable
	}
	engine, ok := s.engine.(interface {
		DialUpdate(context.Context, string, string, string) (net.Conn, error)
	})
	if !ok {
		return nil, update.ErrTunnelUnavailable
	}
	return &UpdateSession{session: s, tier: tier, engine: engine}, nil
}

func (c *Controller) UpdateRoute() update.Route {
	bound, err := c.BindUpdateSession()
	if err != nil {
		return update.UnavailableRoute(err)
	}
	return update.TunnelRoute(bound.Context(), bound.DialContext)
}

func (s *UpdateSession) Same(other *UpdateSession) bool {
	return s.session == other.session && s.tier == other.tier
}

func (s *UpdateSession) Context() context.Context { return s.session.ctx }

func (s *UpdateSession) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !s.session.begin() {
		return nil, update.ErrTunnelStopped
	}
	defer s.session.work.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(s.session.ctx, cancel)()
	if s.session.ctx.Err() != nil {
		return nil, update.ErrTunnelStopped
	}
	return s.engine.DialUpdate(ctx, s.tier, network, address)
}
