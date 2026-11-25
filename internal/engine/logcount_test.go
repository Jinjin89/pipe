// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type captureWriter struct {
	mu    sync.Mutex
	lines []string
}

func (c *captureWriter) WriteMessage(_ log.Level, message string) {
	c.mu.Lock()
	c.lines = append(c.lines, message)
	c.mu.Unlock()
}

func (c *captureWriter) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, "\n")
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestMixedInboundCountsBytesAndFeedsLogWriter(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, strings.Repeat("x", 4096))
	}))
	defer origin.Close()
	port := freePort(t)
	var up, down, proxyUp, proxyDown atomic.Int64
	logs := &captureWriter{}
	instance, err := New(t.Context(), Options{
		Config: Object{
			"log":      Object{"level": "info", "output": "stderr"},
			"inbounds": []Object{{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": port}},
			"outbounds": []Object{
				{"type": "selector", "tag": "proxy", "outbounds": []string{"direct", "fast"}},
				{"type": "direct", "tag": "direct"},
				{"type": "direct", "tag": "fast"},
			},
			"route": Object{"final": "proxy"},
		},
		CountBytes:      func(u, d int64) { up.Add(u); down.Add(d) },
		CountProxyBytes: func(u, d int64) { proxyUp.Add(u); proxyDown.Add(d) },
		LogWriter:       logs,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	for _, tier := range []string{"direct", "fast"} {
		if err := instance.SelectTier(tier); err != nil {
			t.Fatal(err)
		}
		previousDown := down.Load()
		response, err := client.Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || len(body) != 4096 {
			t.Fatalf("%s body %d, err=%v", tier, len(body), err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for down.Load() < previousDown+4096 && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if down.Load() < previousDown+4096 || up.Load() == 0 {
			t.Fatalf("%s counted up=%d down=%d", tier, up.Load(), down.Load()-previousDown)
		}
		if tier == "direct" && (proxyUp.Load() != 0 || proxyDown.Load() != 0) {
			t.Fatalf("direct traffic counted as proxied: up=%d down=%d", proxyUp.Load(), proxyDown.Load())
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for proxyDown.Load() < 4096 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if proxyDown.Load() < 4096 || proxyUp.Load() == 0 {
		t.Fatalf("proxy traffic counted as up=%d down=%d", proxyUp.Load(), proxyDown.Load())
	}
	if !strings.Contains(logs.text(), "inbound connection") {
		t.Fatalf("log writer saw %q", logs.text())
	}
}

func TestLevelWriterFilters(t *testing.T) {
	capture := &captureWriter{}
	w := newLevelWriter(capture, "warn")
	w.WriteMessage(log.LevelInfo, "info")
	w.WriteMessage(log.LevelDebug, "debug")
	w.WriteMessage(log.LevelWarn, "warn")
	w.WriteMessage(log.LevelError, "error")
	if got := capture.text(); got != "warn\nerror" {
		t.Fatalf("got %q", got)
	}
}

func TestProbeLatencyUnknownTier(t *testing.T) {
	instance, err := New(t.Context(), Options{Config: Object{
		"outbounds": []Object{{"type": "direct", "tag": "direct"}},
		"route":     Object{"final": "direct"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if _, _, via, err := instance.ProbeLatency(t.Context(), "fast", false); err == nil || via {
		t.Fatalf("missing tier returned via=%v, err=%v", via, err)
	}
	if _, err := instance.Probe(t.Context(), "fast", false); err == nil {
		t.Fatal("Probe wrapper must fail too")
	}
}

func TestProbeLatencyReportsViaOnSuccess(t *testing.T) {
	instance, err := New(t.Context(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	const kind = "test-probe"
	registry := service.FromContext[adapter.OutboundRegistry](instance.ctx).(*outbound.Registry)
	outbound.Register(registry, kind, func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, fail bool) (adapter.Outbound, error) {
		return &testRelayedProbe{
			probeOutbound: probeOutbound{outbound.NewAdapter(kind, tag, []string{"tcp"}, nil)},
			fail:          fail,
		}, nil
	})
	for _, test := range []struct {
		tag  string
		fail bool
	}{{"response", false}, {"no-response", true}} {
		if err := instance.box.Outbound().Create(instance.ctx, instance.box.Router(), log.NewNOPFactory().Logger(), test.tag, kind, &test.fail); err != nil {
			t.Fatal(err)
		}
		stalled, latency, via, err := instance.ProbeLatency(t.Context(), test.tag, false)
		wantVia := !test.fail
		if stalled || latency <= 0 || via != wantVia || (err != nil) != test.fail {
			t.Errorf("%s returned stalled=%v, latency=%v, via=%v, err=%v", test.tag, stalled, latency, via, err)
		}
	}
}

type testRelayedProbe struct {
	probeOutbound
	fail bool
}

func (o *testRelayedProbe) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if o.fail {
		conn, peer := net.Pipe()
		peer.Close()
		return relayedProbeConn{conn}, nil
	}
	conn, err := o.probeOutbound.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return interrupt.NewGroup().NewConn(relayedProbeConn{conn}, false), nil
}
