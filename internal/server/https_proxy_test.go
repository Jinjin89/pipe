// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"pipe/internal/engine"
	"pipe/internal/overload"
)

func TestHTTPSProxyUnauthenticatedRequestsUseTheSite(t *testing.T) {
	device := Device{Name: "device"}
	device.HTTPSProxyPassword = "test-password"
	site := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("forwarded proxy credential to the decoy")
		}
		w.Header().Set("X-Site", "custom")
		w.WriteHeader(418)
		fmt.Fprintf(w, "%s %s", r.Method, r.RequestURI)
	})
	for _, request := range []struct{ method, target string }{
		{http.MethodConnect, "11.0.0.80:443"},
		{http.MethodGet, "http://11.0.0.80/path"},
		{http.MethodGet, "/normal"},
	} {
		for _, auth := range []string{"", basicProxyAuth("device", "wrong"), "Basic malformed"} {
			req := httptest.NewRequest(request.method, request.target, nil)
			expected := httptest.NewRecorder()
			site.ServeHTTP(expected, req)
			req.Header.Set("Proxy-Authorization", auth)
			got := httptest.NewRecorder()
			p := newHTTPSProxy(site, []Device{device})
			p.dial = func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("unauthenticated request reached a destination")
				return nil, nil
			}
			p.ServeHTTP(got, req)
			if got.Code != expected.Code || got.Body.String() != expected.Body.String() ||
				got.Header().Get("X-Site") != "custom" || got.Header().Get("Proxy-Authenticate") != "" {
				t.Fatalf("response differs from the site for %s", request.method)
			}
		}
	}
}

func TestHTTPSProxyMissingAuthSkipsFailureAccounting(t *testing.T) {
	p := newHTTPSProxy(http.NotFoundHandler(), nil)
	p.now = func() time.Time {
		t.Fatal("request without Proxy-Authorization entered authentication")
		return time.Time{}
	}
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodConnect, "11.0.0.80:443", nil),
		httptest.NewRequest(http.MethodGet, "http://11.0.0.80/path", nil),
	} {
		req.RemoteAddr = "11.0.0.81:12345"
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound || len(p.failures) != 0 {
			t.Fatal("anonymous request did not go directly to the site")
		}
	}
}

func TestHTTPSProxyAbsoluteRequestsCheckResolvedAddressAndStripAuth(t *testing.T) {
	device := Device{Name: "name:with:colons"}
	device.HTTPSProxyPassword = "test-password"
	p := newHTTPSProxy(http.NotFoundHandler(), []Device{device})
	var dialed atomic.Bool
	p.lookup = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host == "mixed.example" {
			return []netip.Addr{netip.MustParseAddr("11.0.0.80"), netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("11.0.0.80")}, nil
	}
	finished := make(chan error, 1)
	p.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		dialed.Store(true)
		if network != "tcp" || address != "11.0.0.80:80" {
			return nil, fmt.Errorf("dialed unchecked address %s", address)
		}
		proxy, target := net.Pipe()
		go func() {
			defer target.Close()
			req, err := http.ReadRequest(bufio.NewReader(target))
			if err == nil && (req.Host != "public.example" || req.URL.Path != "/target" || req.Header.Get("Proxy-Authorization") != "") {
				err = errors.New("request destination or headers changed")
			}
			if err == nil {
				_, err = io.WriteString(target, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
			}
			finished <- err
		}()
		return proxy, nil
	}
	for _, request := range []struct{ method, target string }{
		{http.MethodConnect, "127.0.0.1:443"},
		{http.MethodConnect, "10.0.0.1:443"},
		{http.MethodGet, "http://[64:ff9b::7f00:1]/"},
		{http.MethodGet, "http://mixed.example/"},
	} {
		req := httptest.NewRequest(request.method, request.target, nil)
		req.Header.Set("Proxy-Authorization", basicProxyAuth(device.Name, device.HTTPSProxyPassword))
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		if w.Code != http.StatusBadGateway || dialed.Load() {
			t.Fatalf("forwarded restricted request to %s", request.target)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "http://public.example/target", nil)
	req.Header.Set("Proxy-Authorization", basicProxyAuth(device.Name, device.HTTPSProxyPassword))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "OK" || !dialed.Load() {
		t.Fatalf("authenticated proxy request failed, status %d", w.Code)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

type proxyTestListener struct {
	conn   net.Conn
	done   chan struct{}
	closed sync.Once
}

func (l *proxyTestListener) Accept() (net.Conn, error) {
	if l.conn != nil {
		conn := l.conn
		l.conn = nil
		return conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *proxyTestListener) Addr() net.Addr { return &net.TCPAddr{} }
func (l *proxyTestListener) Close() error {
	l.closed.Do(func() { close(l.done) })
	return nil
}

func TestHTTPSProxyCONNECTRelaysBufferedDataAndClosesOnRevoke(t *testing.T) {
	settings := Settings{Domain: "origin.example"}
	dir := t.TempDir()
	certificate, err := testCertificate(dir, settings)
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := loadOrCreateTestRoot(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	device := Device{Name: "phone"}
	device.DeviceID, device.HTTPSProxyPassword = "phone-id", "phone-password"
	proxy := newHTTPSProxy(http.NotFoundHandler(), []Device{device})
	destinationDone := make(chan error, 1)
	proxy.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		if address != "11.0.0.80:443" {
			return nil, errors.New("unexpected destination")
		}
		left, right := net.Pipe()
		go func() {
			defer right.Close()
			_ = right.SetDeadline(time.Now().Add(5 * time.Second))
			var body [4]byte
			if _, err := io.ReadFull(right, body[:]); err != nil || string(body[:]) != "ping" {
				destinationDone <- fmt.Errorf("missing buffered tunnel bytes: %v", err)
				return
			}
			if _, err := io.WriteString(right, "pong"); err != nil {
				destinationDone <- err
				return
			}
			if _, err := right.Read(body[:]); err != io.EOF {
				destinationDone <- fmt.Errorf("revoked upstream was not closed: %v", err)
				return
			}
			destinationDone <- nil
		}()
		return left, nil
	}
	client, server := net.Pipe()
	defer client.Close()
	listener := &proxyTestListener{conn: server, done: make(chan struct{})}
	website := webServer(proxy, &tls.Config{Certificates: []tls.Certificate{*certificate}})
	go func() { _ = website.ServeTLS(listener, "", "") }()
	defer website.Close()
	defer listener.Close()
	conn := tls.Client(client, &tls.Config{RootCAs: pool, ServerName: settings.Domain})
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request := "CONNECT 11.0.0.80:443 HTTP/1.1\r\nHost: 11.0.0.80:443\r\nProxy-Authorization: " +
		basicProxyAuth(device.Name, device.HTTPSProxyPassword) + "\r\n\r\nping"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	wire := bufio.NewReader(conn)
	response, err := http.ReadResponse(wire, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT failed: %v", err)
	}
	var body [4]byte
	if _, err := io.ReadFull(wire, body[:]); err != nil || string(body[:]) != "pong" {
		t.Fatalf("CONNECT failed to relay data: %v", err)
	}
	proxy.update(nil)
	if err := <-destinationDone; err != nil {
		t.Fatal(err)
	}
}

func proxyTestConnect(ctx context.Context, p *httpsProxy, device Device, address string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(ctx, http.MethodConnect, address, nil)
	r.ProtoMajor = 2 // exercise the CONNECT relay with an in-memory recorder
	r.Header.Set("Proxy-Authorization", basicProxyAuth(device.Name, device.HTTPSProxyPassword))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func TestHTTPSProxyAdmits50RequestsOnOneCredential(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		device := Device{Name: "shared"}
		device.HTTPSProxyPassword = "shared-password"
		p := newHTTPSProxy(http.NotFoundHandler(), []Device{device})
		p.policy = proxyEgressPolicyFunc(engine.PublicDestination)
		p.guard = overload.New(overload.Options{})
		defer p.guard.Close()
		p.guard.RecordSample(overload.Snapshot{OpenFDs: 10, MaxFDs: 512})
		gate := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(gate) })
		defer unblock()
		p.dial = func(context.Context, string, string) (net.Conn, error) {
			<-gate
			conn, peer := net.Pipe()
			peer.Close()
			return conn, nil
		}
		const requests = 50
		results := make(chan int, requests)
		for range requests {
			go func() { results <- proxyTestConnect(t.Context(), p, device, "11.0.0.80:443").Code }()
		}
		synctest.Wait()
		if d := p.guard.Diagnostics(); d.ActiveFlows != requests || d.PendingDials != requests || d.Waiters != 0 {
			t.Fatalf("healthy shared link was limited: %+v", d)
		}
		unblock()
		for range requests {
			if code := <-results; code != http.StatusOK {
				t.Errorf("CONNECT returned %d", code)
			}
		}
		if d := p.guard.Diagnostics(); d.ActiveFlows != 0 || d.PendingDials != 0 {
			t.Errorf("finished CONNECTs retained leases: %+v", d)
		}
	})
}

func TestHTTPSProxyRevocationCancelsActiveAndQueuedRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first, second := Device{Name: "first"}, Device{Name: "second"}
		first.HTTPSProxyPassword, second.HTTPSProxyPassword = "first-pass", "second-pass"
		p := newHTTPSProxy(http.NotFoundHandler(), []Device{first, second})
		p.policy = proxyEgressPolicyFunc(engine.PublicDestination)
		p.guard = overload.New(overload.Options{})
		defer p.guard.Close()
		defer p.update(nil)
		const queuedAddress = "11.0.0.82:443"
		peers := make(chan net.Conn, 2)
		var queuedDials atomic.Int32
		p.dial = func(_ context.Context, _, address string) (net.Conn, error) {
			if address == queuedAddress {
				queuedDials.Add(1)
				return nil, errors.New("queued request reached the dialer")
			}
			conn, peer := net.Pipe()
			peers <- peer
			return conn, nil
		}
		start := func(device Device, address string) <-chan int {
			result := make(chan int, 1)
			go func() { result <- proxyTestConnect(t.Context(), p, device, address).Code }()
			return result
		}
		active := start(first, "11.0.0.80:443")
		other := start(second, "11.0.0.81:443")
		synctest.Wait()
		if d := p.guard.Diagnostics(); d.ActiveFlows != 2 || d.PendingDials != 0 {
			t.Fatalf("CONNECT relays did not establish: %+v", d)
		}
		defer (<-peers).Close()
		defer (<-peers).Close()
		low := overload.Snapshot{GoMemoryBytes: 85, GoMemoryLimit: 100}
		p.guard.RecordSample(low)
		p.guard.RecordSample(low)
		queued := start(first, queuedAddress)
		synctest.Wait()
		if d := p.guard.Diagnostics(); d.Waiters != 1 || queuedDials.Load() != 0 {
			t.Fatalf("request did not queue before dialing: %+v", d)
		}
		p.update([]Device{second})
		synctest.Wait()
		if len(active) == 0 || len(queued) == 0 || <-active != http.StatusOK ||
			<-queued != http.StatusServiceUnavailable || queuedDials.Load() != 0 {
			t.Fatal("revocation did not stop the active tunnel and shed the queued request before dialing")
		}
		select {
		case code := <-other:
			t.Fatalf("revocation interrupted the other device: %d", code)
		default:
		}
		if d := p.guard.Diagnostics(); d.ActiveFlows != 1 || d.Waiters != 0 {
			t.Fatalf("revocation retained resources: %+v", d)
		}
	})
}

func TestHTTPSProxyPasswordRotationCancelsQueuedRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := Device{Name: "phone"}
		old.HTTPSProxyPassword = "old-password"
		p := newHTTPSProxy(http.NotFoundHandler(), []Device{old})
		p.guard = overload.New(overload.Options{})
		defer p.guard.Close()
		held, err := p.guard.Acquire(t.Context(), overload.ClassFlow)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Release()
		held.DialDone(false)
		low := overload.Snapshot{GoMemoryBytes: 85, GoMemoryLimit: 100}
		p.guard.RecordSample(low)
		p.guard.RecordSample(low)
		p.policy = proxyEgressPolicyFunc(engine.PublicDestination)
		var dials atomic.Int32
		p.dial = func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("queued request reached the dialer")
		}
		queued := make(chan int, 1)
		go func() { queued <- proxyTestConnect(t.Context(), p, old, "11.0.0.80:443").Code }()
		synctest.Wait()
		if d := p.guard.Diagnostics(); d.Waiters != 1 {
			t.Fatalf("request did not queue: %+v", d)
		}
		next := old
		next.HTTPSProxyPassword = "replacement-password"
		p.update([]Device{next})
		synctest.Wait()
		if len(queued) == 0 || <-queued != http.StatusServiceUnavailable || dials.Load() != 0 || p.guard.Diagnostics().Waiters != 0 {
			t.Fatal("password rotation did not cancel the queued request before dialing")
		}
	})
}

func TestHTTPSProxyOverloadPreservesCoverAndBackoff(t *testing.T) {
	device := Device{Name: "phone"}
	device.HTTPSProxyPassword = "password"
	p := newHTTPSProxy(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}), []Device{device})
	p.guard = overload.New(overload.Options{MaxWait: 3500 * time.Millisecond})
	defer p.guard.Close()
	p.guard.ObserveError(syscall.EMFILE)
	p.policy = proxyEgressPolicyFunc(engine.PublicDestination)
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Error("overloaded handler attempted an upstream dial")
		return nil, errors.New("unexpected dial")
	}
	now := time.Unix(1000, 0)
	p.now = func() time.Time { return now }
	bad := device
	bad.HTTPSProxyPassword = "wrong-password"
	checkCover := func(credentials Device) {
		t.Helper()
		if w := proxyTestConnect(t.Context(), p, credentials, "11.0.0.80:443"); w.Code != http.StatusTeapot || w.Header().Get("Retry-After") != "" {
			t.Fatalf("failed or cooling-down login lost cover: %d, %v", w.Code, w.Header())
		}
	}
	for _, credentials := range []Device{bad, bad, bad, device} {
		checkCover(credentials)
	}
	now = now.Add(time.Second)
	checkCover(bad) // the fourth failure starts a two-second cooldown
	now = now.Add(time.Second)
	checkCover(device)
	now = now.Add(time.Second)
	if w := proxyTestConnect(t.Context(), p, device, "11.0.0.80:443"); w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "3" {
		t.Fatalf("overload response = %d, %v", w.Code, w.Header())
	}
	if d := p.guard.Diagnostics(); d.ActiveFlows != 0 || d.PendingDials != 0 || d.Waiters != 0 || len(p.devices[device.Name].active) != 0 {
		t.Fatalf("overload retained request resources: %+v", d)
	}
}

func TestHTTPSProxyDialRetiresReservationAndObservesFDExhaustion(t *testing.T) {
	for _, outcome := range []struct {
		name               string
		lookupErr, dialErr error
		sample             bool
	}{
		{name: "success until release"},
		{name: "success until FD sample", sample: true},
		{name: "lookup EMFILE", lookupErr: syscall.EMFILE},
		{name: "dial EMFILE", dialErr: syscall.EMFILE},
	} {
		t.Run(outcome.name, func(t *testing.T) {
			p := newHTTPSProxy(http.NotFoundHandler(), nil)
			p.policy = proxyEgressPolicyFunc(engine.PublicDestination)
			p.guard = overload.New(overload.Options{})
			defer p.guard.Close()
			lease, err := p.guard.Acquire(t.Context(), overload.ClassFlow)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			p.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				if outcome.lookupErr != nil {
					return nil, outcome.lookupErr
				}
				return []netip.Addr{netip.MustParseAddr("11.0.0.80")}, nil
			}
			p.dial = func(context.Context, string, string) (net.Conn, error) {
				if outcome.dialErr != nil {
					return nil, outcome.dialErr
				}
				conn, peer := net.Pipe()
				peer.Close()
				return conn, nil
			}
			conn, err := p.dialPublic(overload.WithLease(t.Context(), lease), "tcp", "origin.example:443")
			if conn != nil {
				defer conn.Close()
			}
			pressure := outcome.lookupErr != nil || outcome.dialErr != nil
			wantUnmeasured := int64(1)
			if pressure {
				wantUnmeasured = 0
			}
			if d := p.guard.Diagnostics(); (conn == nil) != pressure || (err != nil) != pressure ||
				d.Pressured != pressure || d.Emergency != pressure || d.PendingDials != 0 ||
				d.ActiveFlows != 1 || d.UnmeasuredFDs != wantUnmeasured {
				t.Fatalf("dial returned %v and left %+v", err, d)
			}
			if outcome.sample {
				p.guard.RecordSample(overload.Snapshot{OpenFDs: 12, MaxFDs: 512})
				if d := p.guard.Diagnostics(); d.UnmeasuredFDs != 0 || d.ActiveFlows != 1 {
					t.Fatalf("fresh FD sample left %+v", d)
				}
			}
			if conn != nil {
				must(t, conn.Close())
			}
			lease.Release()
			if d := p.guard.Diagnostics(); d.UnmeasuredFDs != 0 || d.ActiveFlows != 0 {
				t.Fatalf("lease release left %+v", d)
			}
		})
	}
}

func TestWebListenerClosesIdleHTTP1ConnectionsUnderPressure(t *testing.T) {
	guard := overload.New(overload.Options{})
	defer guard.Close()
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := webServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}), nil)
	idle := make(chan struct{}, 4)
	server.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateIdle {
			idle <- struct{}{}
		}
	}
	web := serveOn(t.Context(), server, raw, make(chan error, 1), guard)
	defer web.Close()
	dial := func() (net.Conn, *bufio.Reader) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", raw.Addr().String(), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		return conn, bufio.NewReader(conn)
	}
	request := func(conn net.Conn, reader *bufio.Reader) {
		t.Helper()
		if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: loopback\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		res, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || string(body) != "ok" || res.Close {
			t.Fatalf("expected a reusable connection, got %q, close=%t, %v", body, res.Close, err)
		}
	}
	conn, reader := dial()
	request(conn, reader)
	select {
	case <-idle:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not make the connection idle")
	}
	guard.RecordSample(overload.Snapshot{GoMemoryBytes: 90, GoMemoryLimit: 100})
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("idle connection survived pressure: %v", err)
	}
	for range 3 {
		guard.RecordSample(overload.Snapshot{GoMemoryBytes: 10, GoMemoryLimit: 100})
	}
	conn, reader = dial()
	request(conn, reader)
	request(conn, reader)
}

func TestHTTPSProxyFailureBackoff(t *testing.T) {
	device := Device{Name: "phone"}
	device.HTTPSProxyPassword = "secret"
	p := newHTTPSProxy(http.NotFoundHandler(), []Device{device})
	now := time.Unix(1000, 0)
	p.now = func() time.Time { return now }
	peer := netip.MustParseAddr("11.0.0.80")
	for range 3 {
		if _, _, accepted := p.acquire(t.Context(), peer, device.Name, "wrong"); accepted {
			t.Fatal("accepted the wrong password")
		}
	}
	if _, _, accepted := p.acquire(t.Context(), peer, device.Name, device.HTTPSProxyPassword); accepted {
		t.Fatal("repeated failures did not apply backoff")
	}
	for _, address := range []netip.Addr{netip.MustParseAddr("11.0.0.81"), peer} {
		if address == peer {
			now = now.Add(time.Second)
		}
		_, finish, accepted := p.acquire(t.Context(), address, device.Name, device.HTTPSProxyPassword)
		if !accepted || finish == nil {
			t.Fatal("incorrect backoff duration or scope")
		}
		finish()
	}
}

func TestHTTPSProxyLoopbackFailuresNeverLockOutADevice(t *testing.T) {
	device := Device{Name: "phone"}
	device.HTTPSProxyPassword = "secret"
	p := newHTTPSProxy(http.NotFoundHandler(), []Device{device})
	for _, address := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		peer := netip.MustParseAddr(address)
		for range 20 {
			if _, _, accepted := p.acquire(t.Context(), peer, device.Name, "wrong"); accepted {
				t.Fatal("accepted the wrong password")
			}
		}
		_, finish, accepted := p.acquire(t.Context(), peer, device.Name, device.HTTPSProxyPassword)
		if !accepted || finish == nil || len(p.failures) != 0 {
			t.Fatalf("loopback failures triggered backoff for %s", address)
		}
		finish()
	}
}

func basicProxyAuth(name, key string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(name+":"+key))
}

func TestHTTPSProxyDialSkipsBlackholedFamily(t *testing.T) {
	p := newHTTPSProxy(http.NotFoundHandler(), nil)
	p.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		// IPv6 first, as resolvers often return it; the server's IPv6 is dead.
		return []netip.Addr{netip.MustParseAddr("2001:4860::1"), netip.MustParseAddr("11.0.0.80")}, nil
	}
	var order []string
	p.dial = func(ctx context.Context, _, address string) (net.Conn, error) {
		order = append(order, address)
		if strings.HasPrefix(address, "[") {
			<-ctx.Done() // black hole: hangs until this attempt's budget ends
			return nil, ctx.Err()
		}
		proxy, target := net.Pipe()
		target.Close()
		return proxy, nil
	}
	start := time.Now()
	conn, err := p.dialPublic(context.Background(), "tcp", "public.example:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if len(order) != 1 || order[0] != "11.0.0.80:443" {
		t.Fatalf("dial order %v, want IPv4 first", order)
	}
	if time.Since(start) > time.Second {
		t.Fatal("IPv4 should connect without waiting for IPv6")
	}
}

func TestHTTPSProxyNAT64DestinationsUseEmbeddedIPv4Policy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		allowed bool
	}{
		{"public IPv4", "64:ff9b::808:808", true},
		{"private IPv4", "64:ff9b::a00:1", false},
		{"loopback IPv4", "64:ff9b::7f00:1", false},
		{"local-use prefix", "64:ff9b:1::808:808", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newHTTPSProxy(http.NotFoundHandler(), nil)
			ip := netip.MustParseAddr(tc.address)
			p.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{ip}, nil
			}
			var dialed []string
			p.dial = func(_ context.Context, _, address string) (net.Conn, error) {
				dialed = append(dialed, address)
				client, peer := net.Pipe()
				peer.Close()
				return client, nil
			}
			conn, err := p.dialPublic(context.Background(), "tcp", "translated.example:443")
			if tc.allowed {
				if err != nil {
					t.Fatalf("public NAT64 destination rejected: %v", err)
				}
				if conn == nil || len(dialed) != 1 {
					t.Fatalf("public NAT64 destination did not dial: conn=%v dialed=%v", conn, dialed)
				}
				if dialed[0] != net.JoinHostPort(ip.String(), "443") {
					t.Fatalf("dialed %s, want translated address %s", dialed[0], ip)
				}
				conn.Close()
			} else if err == nil || len(dialed) != 0 {
				t.Fatalf("restricted NAT64 destination reached dialer: err=%v dialed=%v", err, dialed)
			}
		})
	}
}

func TestHTTPSProxyChecksFreshResolvedAddresses(t *testing.T) {
	p := newHTTPSProxy(http.NotFoundHandler(), nil)
	p.policy = engine.NewEgressPolicy(netip.MustParseAddr("11.2.3.4"))
	addresses := []netip.Addr{netip.MustParseAddr("11.2.3.5")}
	p.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return addresses, nil }
	var calls []string
	p.dial = func(_ context.Context, _ string, address string) (net.Conn, error) {
		calls = append(calls, address)
		return nil, errors.New("fixture intercepts all dials")
	}
	_, _ = p.dialPublic(t.Context(), "tcp", "origin.example:443")
	addresses = []netip.Addr{netip.MustParseAddr("::ffff:11.2.3.4")}
	_, _ = p.dialPublic(t.Context(), "tcp", "origin.example:443")
	if !slices.Equal(calls, []string{"11.2.3.5:443"}) {
		t.Fatalf("fixture dials = %v", calls)
	}
}

type proxyEgressPolicyFunc func(netip.Addr) bool

func (f proxyEgressPolicyFunc) AllowsFresh(ip netip.Addr) bool { return f(ip) }

func TestHTTPSProxyRejectsNewlyLocalFallbackAddress(t *testing.T) {
	p := newHTTPSProxy(http.NotFoundHandler(), nil)
	first, fallback := netip.MustParseAddr("11.0.0.80"), netip.MustParseAddr("2001:4860::1")
	p.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{first, fallback}, nil
	}
	var local netip.Addr
	p.policy = proxyEgressPolicyFunc(func(ip netip.Addr) bool { return ip != local })
	var calls []string
	p.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		calls = append(calls, address)
		local = fallback
		return nil, errors.New("first address became unreachable")
	}
	if conn, err := p.dialPublic(t.Context(), "tcp", "origin.example:443"); conn != nil || err == nil {
		t.Fatalf("unexpected proxy dial result: %v, %v", conn, err)
	}
	if want := []string{net.JoinHostPort(first.String(), "443")}; !slices.Equal(calls, want) {
		t.Fatalf("dialed %v, want only %v", calls, want)
	}
}

func TestDialOrderInterleavesIPv4First(t *testing.T) {
	in := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3"),
	}
	got := fmt.Sprint(dialOrder(in))
	want := "[192.0.2.1 2001:db8::1 192.0.2.2 2001:db8::2 192.0.2.3]"
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestProxyCoverDefaultsToFastSite(t *testing.T) {
	page, err := generateCoverSite(testCoverKey(1), mainCoverLabel)
	if err != nil {
		t.Fatal(err)
	}
	cover, err := proxyCover("", page)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	cover.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://example.com/", nil))
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), page) {
		t.Fatalf("expected the generated site, got %d", w.Code)
	}
}
