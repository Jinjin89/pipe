// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

func TestUsageTrackerCountsProxyPacketsAndFlows(t *testing.T) {
	for _, test := range []struct {
		tier  string
		proxy bool
	}{
		{"fast", true}, {"stealth", true}, {"rescue", true},
		{"direct", false}, {"lan", false}, {"block", false},
	} {
		t.Run(test.tier, func(t *testing.T) {
			type taggedOutbound struct {
				outbound.Adapter
				N.Dialer
			}
			selected := &taggedOutbound{Adapter: outbound.NewAdapter("", test.tier, nil, nil)}
			metadata := adapter.InboundContext{OutboundChain: []adapter.Outbound{selected}}
			var totalUp, totalDown, proxyUp, proxyDown int64
			tracker := newUsageTracker(
				func(up, down int64) { totalUp += up; totalDown += down },
				func(up, down int64) { proxyUp += up; proxyDown += down },
			)

			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()
			packet := tracker.RoutedPacketConnection(t.Context(), bufio.NewUnbindPacketConn(conn), metadata, nil, selected)
			_, read := N.UnwrapCountPacketReader(packet, nil)
			_, write := N.UnwrapCountPacketWriter(packet, nil)
			for _, count := range read {
				count(3)
			}
			for _, count := range write {
				count(5)
			}

			flow := tracker.RoutedFlow(t.Context(), metadata, nil, selected)
			flow.CountForward(7)
			flow.CountReverse(11)
			if totalUp != 10 || totalDown != 16 {
				t.Fatalf("total up=%d down=%d, want 10 and 16", totalUp, totalDown)
			}
			wantUp, wantDown := int64(0), int64(0)
			if test.proxy {
				wantUp, wantDown = totalUp, totalDown
			}
			if proxyUp != wantUp || proxyDown != wantDown {
				t.Errorf("proxy up=%d down=%d, want %d and %d", proxyUp, proxyDown, wantUp, wantDown)
			}
		})
	}
}
