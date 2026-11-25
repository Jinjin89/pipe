// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

type usageTracker struct {
	total, proxy usageCounter
}

type usageCounter struct {
	up, down []N.CountFunc
}

func newUsageTracker(count, countProxy func(up, down int64)) *usageTracker {
	tracker := &usageTracker{}
	if count != nil {
		tracker.total.add(count)
	}
	if countProxy != nil {
		tracker.proxy = tracker.total
		tracker.proxy.add(countProxy)
	}
	return tracker
}

func (c *usageCounter) add(count func(up, down int64)) {
	c.up = append(c.up, func(n int64) { count(n, 0) })
	c.down = append(c.down, func(n int64) { count(0, n) })
}

func (t *usageTracker) counterFor(metadata adapter.InboundContext) *usageCounter {
	if len(t.proxy.up) != 0 && proxyTier(metadata) != "" {
		return &t.proxy
	}
	if len(t.total.up) != 0 {
		return &t.total
	}
	return nil
}

func (t *usageTracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	if counter := t.counterFor(metadata); counter != nil {
		return bufio.NewCounterConn(conn, counter.up, counter.down)
	}
	return conn
}

func (t *usageTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	if counter := t.counterFor(metadata); counter != nil {
		return bufio.NewCounterPacketConn(conn, counter.up, counter.down)
	}
	return conn
}

func (t *usageTracker) RoutedFlow(_ context.Context, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) tun.FlowTracker {
	if counter := t.counterFor(metadata); counter != nil {
		return counter
	}
	return nil
}

func (c *usageCounter) CountForward(n int) {
	for _, count := range c.up {
		count(int64(n))
	}
}

func (c *usageCounter) CountReverse(n int) {
	for _, count := range c.down {
		count(int64(n))
	}
}

func (c *usageCounter) AttachFlow(tun.FlowHandle)     {}
func (c *usageCounter) FlowEstablished()              {}
func (c *usageCounter) CloseFlow(tun.FlowCloseReason) {}
