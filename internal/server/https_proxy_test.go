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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestHTTPSProxyCapsConnectionsAndCancelsRevokedDevice(t *testing.T) {
	first := Device{Name: "first"}
	first.DeviceID, first.HTTPSProxyPassword = "first-id", "first-pass"
	second := Device{Name: "second"}
	second.DeviceID, second.HTTPSProxyPassword = "second-id", "second-pass"
	p := newHTTPSProxy(http.NotFoundHandler(), []Device{first, second})
	peer := netip.MustParseAddr("11.0.0.80")
	var active []context.Context
	for range proxyDeviceLimit {
		ctx, finish, accepted := p.acquire(t.Context(), peer, first.Name, first.HTTPSProxyPassword)
		if !accepted || finish == nil {
			t.Fatal("device hit cap too early")
		}
		t.Cleanup(finish)
		active = append(active, ctx)
	}
	if _, finish, accepted := p.acquire(t.Context(), peer, first.Name, first.HTTPSProxyPassword); !accepted || finish != nil {
		t.Fatal("connection cap was not enforced")
	}
	other, finish, accepted := p.acquire(t.Context(), peer, second.Name, second.HTTPSProxyPassword)
	if !accepted || finish == nil {
		t.Fatal("one device exhausted the other device's cap")
	}
	defer finish()
	p.update([]Device{second})
	for _, ctx := range active {
		if ctx.Err() != context.Canceled {
			t.Fatal("revoked device retained an active tunnel")
		}
	}
	if other.Err() != nil {
		t.Fatal("revocation interrupted a different device")
	}
	if _, _, accepted := p.acquire(t.Context(), peer, first.Name, first.HTTPSProxyPassword); accepted {
		t.Fatal("revoked proxy credential remained valid")
	}
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
	page, err := generateCoverSite(testCoverKey(1))
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
