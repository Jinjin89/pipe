// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func openH2ProxyTestClient(t *testing.T, handler http.Handler, receiveWindow int) *http.ClientConn {
	t.Helper()
	settings := Settings{Domain: "origin.example"}
	dir := t.TempDir()
	cert, err := testCertificate(dir, settings)
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := loadOrCreateTestRoot(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	listener := &proxyTestListener{conn: server, done: make(chan struct{})}
	t.Cleanup(func() { _ = listener.Close() })
	website := webServer(handler, &tls.Config{Certificates: []tls.Certificate{*cert}})
	go func() { _ = website.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = website.Close() })
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		HTTP2:             &http.HTTP2Config{MaxReceiveBufferPerStream: receiveWindow},
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: settings.Domain, NextProtos: []string{"h2"}})
			if err := conn.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return conn, nil
		},
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := transport.NewClientConn(ctx, "https", settings.Domain+":443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestHTTPSProxyH2ConnectEndsWhenUpstreamCloses(t *testing.T) {
	device := Device{Name: "phone"}
	device.HTTPSProxyPassword = "secret"
	p := newHTTPSProxy(http.NotFoundHandler(), []Device{device})
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		proxy, target := net.Pipe()
		go func() {
			defer target.Close()
			_ = target.SetWriteDeadline(time.Now().Add(4 * time.Second))
			_, _ = io.WriteString(target, "reply")
		}()
		return proxy, nil
	}
	conn := openH2ProxyTestClient(t, p, 0)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	body, send := io.Pipe()
	defer send.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://11.0.0.80:443", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", basicProxyAuth(device.Name, device.HTTPSProxyPassword))
	res, err := conn.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if res.ProtoMajor != 2 || res.StatusCode != http.StatusOK || err != nil || string(data) != "reply" {
		t.Fatalf("HTTP/2 CONNECT did not end while the upload stayed open: %v", err)
	}
}

func TestHTTPSProxyH2RevokeUnblocksStalledResponse(t *testing.T) {
	device := Device{Name: "phone"}
	device.HTTPSProxyPassword = "secret"
	p := newHTTPSProxy(http.NotFoundHandler(), []Device{device})
	written := make(chan error, 1)
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		proxy, target := net.Pipe()
		go func() {
			defer target.Close()
			_ = target.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := target.Write(make([]byte, 128<<10))
			written <- err
		}()
		return proxy, nil
	}
	returned := make(chan struct{})
	conn := openH2ProxyTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(returned)
		p.ServeHTTP(w, r)
	}), 1024)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	body, send := io.Pipe()
	defer send.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://11.0.0.80:443", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", basicProxyAuth(device.Name, device.HTTPSProxyPassword))
	res, err := conn.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.ProtoMajor != 2 || res.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT did not open an HTTP/2 stream: %s %s", res.Proto, res.Status)
	}
	// Receive the first window, then keep the body open without reading more.
	if _, err := io.ReadFull(res.Body, make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	p.update(nil)
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("revocation left the HTTP/2 handler blocked on flow control")
	}
	if err := <-written; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("revocation did not close the blocked upstream: %v", err)
	}
}

func TestHTTPSProxyH2ForwardsPlainHTTPOnlyWithValidAuth(t *testing.T) {
	const path = "/plain?query=1"
	device := Device{Name: "phone"}
	device.HTTPSProxyPassword = "secret"
	site := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.IsAbs() || r.RequestURI != path || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("the proxy changed the request passed to the site")
		}
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "site")
	})
	p := newHTTPSProxy(site, []Device{device})
	var dials atomic.Int32
	p.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp" || address != "11.0.0.80:8080" {
			return nil, fmt.Errorf("unexpected proxy destination %s", address)
		}
		proxy, target := net.Pipe()
		go func() {
			defer target.Close()
			_ = target.SetDeadline(time.Now().Add(4 * time.Second))
			req, err := http.ReadRequest(bufio.NewReader(target))
			if err != nil {
				t.Error(err)
				return
			}
			if req.RequestURI != path || req.Header.Get("Proxy-Authorization") != "" {
				t.Error("forwarded path or headers are wrong")
			}
			_, _ = io.WriteString(target, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\norigin")
		}()
		return proxy, nil
	}
	conn := openH2ProxyTestClient(t, p, 0)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for _, test := range []struct {
		auth, body string
		status     int
	}{
		{"", "site", http.StatusTeapot},
		{basicProxyAuth(device.Name, "wrong"), "site", http.StatusTeapot},
		{basicProxyAuth(device.Name, device.HTTPSProxyPassword), "origin", http.StatusOK},
	} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://11.0.0.80:8080"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if test.auth != "" {
			req.Header.Set("Proxy-Authorization", test.auth)
		}
		res, err := conn.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if err != nil || res.ProtoMajor != 2 || res.StatusCode != test.status || string(body) != test.body {
			t.Fatalf("wanted HTTP/2 status %d, got %s %s with body %q: %v", test.status, res.Proto, res.Status, body, err)
		}
	}
	if dials.Load() != 1 {
		t.Fatalf("expected only the authenticated request to reach the origin, got %d dials", dials.Load())
	}
}
