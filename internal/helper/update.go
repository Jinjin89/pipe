// SPDX-License-Identifier: GPL-3.0-or-later

package helper

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/update"
)

type updateStreamParams struct {
	Address string `json:"address"`
	Route   string `json:"route,omitempty"`
}

type updateRouteState struct {
	mu      sync.Mutex
	id      string
	session *clientctl.UpdateSession
}

func (s *server) boundUpdateSession(id string) (*clientctl.UpdateSession, string, error) {
	routes := &s.updateRoutes
	routes.mu.Lock()
	defer routes.mu.Unlock()
	if id != "" {
		if id != routes.id || routes.session == nil || routes.session.Context().Err() != nil {
			return nil, "", update.ErrTunnelStopped
		}
		return routes.session, id, nil
	}
	source, ok := s.opts.Session.(interface {
		BindUpdateSession() (*clientctl.UpdateSession, error)
	})
	if !ok {
		return nil, "", update.ErrTunnelUnavailable
	}
	bound, err := source.BindUpdateSession()
	if err != nil {
		return nil, "", err
	}
	if routes.session == nil || !bound.Same(routes.session) {
		id := rand.Text()
		routes.id, routes.session = id, bound
		context.AfterFunc(bound.Context(), func() {
			routes.mu.Lock()
			defer routes.mu.Unlock()
			if routes.id == id {
				routes.id, routes.session = "", nil
			}
		})
	}
	return routes.session, routes.id, nil
}

// serveUpdateStream takes over an already authenticated local connection.
func (s *server) serveUpdateStream(ctx context.Context, conn *net.UnixConn, params json.RawMessage) {
	var req updateStreamParams
	if json.Unmarshal(params, &req) != nil || !update.AllowedAddress(req.Address) {
		reply(conn, nil, "That update address isn't allowed.")
		return
	}
	bound, id, err := s.boundUpdateSession(req.Route)
	if err != nil {
		reply(conn, nil, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 11*time.Minute)
	defer cancel()
	defer context.AfterFunc(bound.Context(), cancel)()
	defer context.AfterFunc(ctx, func() { conn.Close() })()
	dialCtx, done := context.WithTimeout(ctx, 15*time.Second)
	upstream, err := bound.DialContext(dialCtx, "tcp", req.Address)
	done()
	if err != nil {
		if bound.Context().Err() != nil {
			reply(conn, nil, update.ErrTunnelStopped.Error())
		} else {
			reply(conn, nil, "Could not open the update stream through Pipe.")
		}
		return
	}
	defer upstream.Close()
	defer context.AfterFunc(ctx, func() { upstream.Close() })()
	reply(conn, id, "")
	_ = conn.SetDeadline(time.Time{})
	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		_, _ = io.Copy(upstream, conn)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(conn, upstream)
	_ = conn.Close()
	<-copyDone
}

// UpdateRoute uses the privileged helper stream even if the session
// disappears before the first request or between HTTPS connections.
func (r *Remote) UpdateRoute() update.Route {
	var mu sync.Mutex
	var id string
	return update.TunnelRoute(nil, func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || !update.AllowedAddress(address) {
			return nil, update.ErrTunnelUnavailable
		}
		mu.Lock()
		defer mu.Unlock()
		conn, nextID, err := r.openUpdateStream(ctx, updateStreamParams{Address: address, Route: id})
		if err == nil {
			id = nextID
		}
		return conn, err
	})
}

func (r *Remote) openUpdateStream(ctx context.Context, req updateStreamParams) (net.Conn, string, error) {
	if r.socket == "" {
		return nil, "", update.ErrTunnelUnavailable
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", r.socket)
	if err != nil {
		return nil, "", update.ErrTunnelStopped
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	defer context.AfterFunc(ctx, func() { conn.Close() })()
	uid, err := peerUID(conn.(*net.UnixConn))
	if err != nil || uid != 0 {
		return nil, "", errors.New("Could not authenticate Pipe Helper.")
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	resp, err := exchange(conn, "updateStream", req)
	if err != nil {
		return nil, "", update.ErrTunnelStopped
	}
	if resp.Error != "" {
		if resp.Error == update.ErrTunnelStopped.Error() {
			return nil, "", update.ErrTunnelStopped
		}
		return nil, "", errors.New(resp.Error)
	}
	var id string
	if json.Unmarshal(resp.Result, &id) != nil || id == "" || (req.Route != "" && req.Route != id) {
		return nil, "", update.ErrTunnelStopped
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, "", err
	}
	success = true
	return conn, id, nil
}
