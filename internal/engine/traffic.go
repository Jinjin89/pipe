// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

const (
	stallAfter         = 5 * time.Second
	downloadWindow     = 10 * time.Second
	minDownloadToWatch = 256 * 1024
)

type trafficTracker struct {
	observe      func()
	suspectStall func()
}

func proxyTier(metadata adapter.InboundContext) string {
	if len(metadata.OutboundChain) == 0 {
		return ""
	}
	tag := metadata.OutboundChain[len(metadata.OutboundChain)-1].Tag()
	switch tag {
	case "fast", "stealth", "rescue":
		return tag
	default:
		return ""
	}
}

func (t *trafficTracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	tier := proxyTier(metadata)
	if tier == "" {
		return conn
	}
	t.observe()
	count := []N.CountFunc{func(int64) { t.observe() }}
	if tier != "fast" || t.suspectStall == nil {
		return bufio.NewCounterConn(conn, count, count)
	}
	watch := &downloadWatch{report: t.suspectStall}
	counted := bufio.NewCounterConn(conn, count, append(count, watch.progress))
	return &watchedDownload{CounterConn: counted, watch: watch}
}

func (t *trafficTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	if proxyTier(metadata) == "" {
		return conn
	}
	t.observe()
	count := []N.CountFunc{func(int64) { t.observe() }}
	return bufio.NewCounterPacketConn(conn, count, count)
}

func (t *trafficTracker) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

type watchedDownload struct {
	*bufio.CounterConn
	watch *downloadWatch
}

func (c *watchedDownload) Close() error {
	c.watch.stop()
	return c.CounterConn.Close()
}

type downloadWatch struct {
	mu       sync.Mutex
	samples  []downloadSample
	received int64
	timer    *time.Timer
	report   func()
}

type downloadSample struct {
	at    time.Time
	bytes int64
}

func (w *downloadWatch) progress(count int64) {
	if count <= 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.report == nil {
		return
	}
	now := time.Now()
	count = min(count, minDownloadToWatch)
	w.samples = append(w.samples, downloadSample{at: now, bytes: count})
	w.received += count
	w.trim(now)
	if w.received >= minDownloadToWatch && w.timer == nil {
		w.timer = time.AfterFunc(stallAfter, w.check)
	}
}

// Only the newest 256 KiB can determine whether the download qualifies.
// Drop older samples as well as anything outside the activity window.
func (w *downloadWatch) trim(windowEnd time.Time) {
	cutoff := windowEnd.Add(-downloadWindow)
	for len(w.samples) != 0 {
		oldest := w.samples[0]
		if !oldest.at.Before(cutoff) && w.received-oldest.bytes < minDownloadToWatch {
			return
		}
		w.received -= oldest.bytes
		w.samples = w.samples[1:]
	}
}

func (w *downloadWatch) check() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.report == nil || len(w.samples) == 0 {
		w.timer = nil
		return
	}
	last := w.samples[len(w.samples)-1].at
	if remaining := stallAfter - time.Since(last); remaining > 0 {
		w.timer.Reset(remaining)
		return
	}
	w.trim(last)
	if w.received < minDownloadToWatch {
		w.timer = nil
		return
	}
	w.report()
	w.report = nil
	w.samples = nil
	w.timer = nil
}

func (w *downloadWatch) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.report = nil
	w.samples = nil
	if w.timer != nil {
		w.timer.Stop()
	}
}
