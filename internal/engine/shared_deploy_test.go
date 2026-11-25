// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestFastSPKIPinHandshake(t *testing.T) {
	const name = "fast.example"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	wrong := pin
	wrong[0] ^= 1
	for _, test := range []struct {
		name string
		pin  [32]byte
		ok   bool
	}{
		{"self-signed match", pin, true},
		{"wrong SPKI", wrong, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			peer, wire := net.Pipe()
			defer peer.Close()
			defer wire.Close()
			server := tls.Server(peer, &tls.Config{
				Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
			})
			serverDone := make(chan error, 1)
			go func() { serverDone <- server.HandshakeContext(ctx) }()
			cfg, err := boxtls.NewClient(ctx, log.NewNOPFactory().Logger(), "11.0.0.80", option.OutboundTLSOptions{
				Enabled: true, ServerName: name, CertificatePublicKeySHA256: [][]byte{test.pin[:]},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = boxtls.ClientHandshake(ctx, wire, cfg)
			if test.ok {
				if err != nil || <-serverDone != nil || server.ConnectionState().ServerName != name {
					t.Fatalf("correct SPKI or Fast SNI failed: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "unrecognized remote public key") {
				t.Fatalf("wrong pin did not fail the SPKI check: %v", err)
			}
		})
	}
}

func TestSharedRescueNormalizesMappedListener(t *testing.T) {
	in, err := newSharedRescue(t.Context(), nil, log.NewNOPFactory().Logger(), "rescue", sharedRescueOptions{
		Listen: "[::ffff:127.0.0.1]:10001", Host: "static.example", Path: "/ws/private",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := in.(*sharedRescue).listen; got != "127.0.0.1:10001" {
		t.Fatalf("unexpected Rescue listen address %s", got)
	}
}

func TestSharedRescueGate(t *testing.T) {
	const uuid = "ab2cb5b2-8200-4132-b010-9fd96948afb0"
	const host, path = "static.example", "/ws/private"
	auth := new(RescueAuthenticator)
	if err := auth.SetUsers([]string{uuid}); err != nil {
		t.Fatal(err)
	}
	handler := rescueGate(host, path, auth.Authenticate,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusSwitchingProtocols) }))
	for _, test := range []struct {
		host, path, upgrade, data string
		want                      int
	}{
		{host, path, "websocket", vmessEarlyData(t, uuid), 101},
		{host + ":443", path, "websocket", vmessEarlyData(t, uuid), 101},
		{host, path, "websocket", "wrong", 404},
		{host, path + "?unexpected=1", "websocket", vmessEarlyData(t, uuid), 404},
		{host, path + "/", "websocket", vmessEarlyData(t, uuid), 404},
		{host, path, "", vmessEarlyData(t, uuid), 404},
		{"elsewhere.example", path, "websocket", vmessEarlyData(t, uuid), 404},
	} {
		r := httptest.NewRequest("GET", "http://"+test.host+test.path, nil)
		r.Header.Set("Upgrade", test.upgrade)
		r.Header.Set(WebSocketEarlyDataHeader, test.data)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != test.want || w.Body.Len() != 0 {
			t.Fatalf("shared Rescue gate sent %d instead of bare %d", w.Code, test.want)
		}
	}
}

func TestSharedProbeNeedsNoListener(t *testing.T) {
	probe := new(probeOutbound)
	for _, path := range []string{ProbePath, ProbePath + "?burst=1", "/other"} {
		conn, err := probe.DialContext(t.Context(), "tcp", M.ParseSocksaddrHostPort(ProbeDomain, 80))
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("GET", "http://"+ProbeDomain+path, nil)
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		res, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		_ = conn.Close()
		status, expected := ProbeResponse(req)
		if err != nil || res.StatusCode != status || string(body) != expected {
			t.Fatalf("unexpected probe response for %s: %v", path, err)
		}
	}
}
