// SPDX-License-Identifier: GPL-3.0-or-later

package clientctl

import (
	"context"
	"errors"
	"net"
	"testing"

	"pipe/internal/config"
	"pipe/internal/engine"
	"pipe/internal/update"
)

type updateTestEngine struct {
	*fakeEngine
	usedTier string
}

func (e *updateTestEngine) DialUpdate(_ context.Context, tier, network, address string) (net.Conn, error) {
	e.usedTier = tier
	if network != "tcp" || address != "api.github.com:443" {
		return nil, errors.New("unexpected test destination")
	}
	local, peer := net.Pipe()
	peer.Close()
	return local, nil
}

func TestUpdateSessionPinsEngineAndTier(t *testing.T) {
	c := NewWithSettings(Settings{SkipConnectProbe: true})
	instance := &updateTestEngine{fakeEngine: &fakeEngine{}}
	c.newEngine = func(context.Context, engine.Options) (engineAPI, error) { return instance, nil }
	options := opts()
	options.Tier = "stealth"
	if err := c.Start(options); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop() })
	session, err := c.BindUpdateSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetTier("fast"); err != nil {
		t.Fatal(err)
	}
	conn, err := session.DialContext(context.Background(), "tcp", "api.github.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if instance.usedTier != "stealth" {
		t.Fatalf("update moved to a different tier: %s", instance.usedTier)
	}
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := session.DialContext(context.Background(), "tcp", "api.github.com:443"); !errors.Is(err, update.ErrTunnelStopped) {
		t.Fatalf("expired session dial returned %v", err)
	}
	options.Mode = config.Direct
	if err := c.Start(options); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BindUpdateSession(); !errors.Is(err, update.ErrTunnelUnavailable) {
		t.Fatalf("Direct unexpectedly supplied an update session: %v", err)
	}
}
