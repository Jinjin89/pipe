// SPDX-License-Identifier: GPL-3.0-or-later

package mobile

import (
	"context"
	"encoding/json"
	"net"

	"pipe/internal/config"
	"pipe/internal/update"
	"pipe/internal/version"
)

// Updates is owned by the Android VPN service. Only it can resolve a verified
// artifact to a path inside the app's private directory.
type Updates struct{ manager *update.Manager }

func NewUpdates(dir, abi string) *Updates {
	return client.newUpdates(dir, abi)
}

func (b *bridge) newUpdates(dir, abi string) *Updates {
	manager := update.NewManager(version.Version, update.Target{OS: "android", ABI: abi}, dir)
	b.mu.Lock()
	b.updates = append(b.updates, manager)
	b.mu.Unlock()
	return &Updates{manager: manager}
}

func updateJSON(status update.Status) string {
	raw, _ := json.Marshal(status)
	return string(raw)
}

func (u *Updates) Status() string { return updateJSON(u.manager.Status()) }

func (u *Updates) Check(requireTunnel, automatic bool) string {
	return updateJSON(u.manager.CheckWithRoute(func() update.Route { return client.updateRoute(requireTunnel) }, automatic))
}

func (u *Updates) Download(requireTunnel bool) string {
	return updateJSON(u.manager.DownloadWithRoute(func() update.Route { return client.updateRoute(requireTunnel) }))
}

// CancelDirect cancels requests using the direct update route.
func (u *Updates) CancelDirect() { u.manager.CancelDirect() }

func (u *Updates) Artifact(handle string) (string, error) { return u.manager.Resolve(handle) }

func (b *bridge) updateRoute(requireTunnel bool) update.Route {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.active
	if s == nil && b.guard == nil && !b.starting && !requireTunnel {
		return update.DirectRoute()
	}
	if s == nil || s.client.Mode == config.Direct || !s.online.Load() {
		return update.UnavailableRoute(update.ErrTunnelUnavailable)
	}
	instance, ok := s.engine.(interface {
		DialUpdate(context.Context, string, string, string) (net.Conn, error)
	})
	if !ok {
		return update.UnavailableRoute(update.ErrTunnelUnavailable)
	}
	b.stateMu.Lock()
	tier := b.state.Tier
	b.stateMu.Unlock()
	network := s.networkCtx
	return update.TunnelRoute(network, func(ctx context.Context, proto, address string) (net.Conn, error) {
		if network.Err() != nil || !s.begin() {
			return nil, update.ErrTunnelStopped
		}
		defer s.work.Done()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		defer context.AfterFunc(network, cancel)()
		return instance.DialUpdate(ctx, tier, proto, address)
	})
}
