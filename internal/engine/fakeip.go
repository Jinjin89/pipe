// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

// FakeIP keeps the fake IPs that apps have cached valid across engine
// replacement: every engine built with the same FakeIP shares one allocator,
// so a settings change or rebuild never forgets an address it handed out.
type FakeIP struct {
	mu        sync.Mutex
	transport *sharedFakeIPTransport
	inet4     netip.Prefix
	inet6     netip.Prefix
}

type sharedFakeIPTransport struct{ adapter.FakeIPTransport }

func (*sharedFakeIPTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }

func (c *FakeIP) newTransport(_ context.Context, _ log.ContextLogger, tag string, options option.FakeIPDNSServerOptions) (adapter.DNSTransport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	inet4, inet6 := options.Inet4Range.Build(netip.Prefix{}), options.Inet6Range.Build(netip.Prefix{})
	if c.transport != nil {
		if c.transport.Tag() != tag || c.inet4 != inet4 || c.inet6 != inet6 {
			return nil, errors.New("FakeIP ranges changed during engine replacement")
		}
		return c.transport, nil
	}
	// The store belongs to the owner of FakeIP, independent of any box's
	// context registry and in-memory DNS transport lifecycle.
	base, err := fakeip.NewTransport(context.Background(), logger.NOP(), tag, options)
	if err != nil {
		return nil, err
	}
	transport := base.(adapter.FakeIPTransport)
	if err := transport.Store().Start(); err != nil {
		return nil, err
	}
	c.transport = &sharedFakeIPTransport{transport}
	c.inet4, c.inet6 = inet4, inet6
	return c.transport, nil
}

func (c *FakeIP) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.transport == nil {
		return nil
	}
	err := c.transport.Store().Close()
	c.transport = nil
	return err
}
