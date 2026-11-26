// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pipe/internal/link"
)

const testRescueDomain = "rescue.edge.example"

func TestRescueExpiryWarning(t *testing.T) {
	now := time.Date(2026, time.November, 25, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		offset time.Duration
		want   string
	}{
		{"outside the warning window", 30*24*time.Hour + time.Second, ""},
		{"30 days left", 30 * 24 * time.Hour, "expires"},
		{"expires now", 0, "expired"},
		{"already expired", -time.Hour, "expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expires := now.Add(tc.offset)
			warning := rescueExpiryWarning(expires, now)
			if tc.want == "" {
				if warning != "" {
					t.Fatalf("unexpected warning: %s", warning)
				}
				return
			}
			for _, part := range []string{tc.want, expires.Format(time.RFC3339), "pipe server setup", "rescue.cert", "rescue.key"} {
				if !strings.Contains(warning, part) {
					t.Fatalf("warning is missing %q: %s", part, warning)
				}
			}
		})
	}
}

func TestRescueSourceAllowed(t *testing.T) {
	for _, tc := range []struct {
		address          string
		production, test bool
	}{
		{"173.245.48.0", true, true},
		{"104.27.255.255", true, true},
		{"104.28.0.0", false, false},
		{"::ffff:104.16.5.7", true, true},
		{"2606:4700::1", true, true},
		{"2606:4701::1", false, false},
		{"127.0.0.1", false, true},
		{"::ffff:127.0.0.1", false, true},
		{"::1", false, true},
		{"192.168.1.1", false, false},
		{"::ffff:10.83.0.2", false, false},
		{"fd00::1", false, false},
	} {
		ip := netip.MustParseAddr(tc.address)
		if got := rescueSourceAllowed(ip, false); got != tc.production {
			t.Errorf("production source %s allowed = %t, want %t", tc.address, got, tc.production)
		}
		if got := rescueSourceAllowed(ip, true); got != tc.test {
			t.Errorf("test source %s allowed = %t, want %t", tc.address, got, tc.test)
		}
	}
}

func TestSharedTCPPorts(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		stealth, rescue, vmess uint16
		proxy                  httpsProxyListenerConfig
		want                   string
	}{
		{"Fast UDP and Rescue TCP may share a number", 8443, 443, 10001, httpsProxyListenerConfig{}, ""},
		{"inactive Stealth and Rescue", 8443, 8443, 10001, httpsProxyListenerConfig{}, ""},
		{"Stealth and Rescue", 8443, 8443, 10001, httpsProxyListenerConfig{Port: 9443, CertMethod: "files"}, "Stealth"},
		{"Rescue and VMess", 8443, 2053, 2053, httpsProxyListenerConfig{}, "Rescue"},
		{"Rescue and proxy", 8443, 2053, 10001, httpsProxyListenerConfig{Port: 2053, CertMethod: "files"}, "Rescue"},
		{"VMess and proxy", 8443, 2053, 10001, httpsProxyListenerConfig{Port: 10001, CertMethod: "files"}, "VMess"},
		{"Stealth and proxy", 8443, 2053, 10001, httpsProxyListenerConfig{Port: 8443, CertMethod: "dns"}, "Stealth"},
		{"Rescue and HTTP-01", 8443, 80, 10001, httpsProxyListenerConfig{Port: 9443, CertMethod: "http"}, "Rescue"},
		{"TCP 80 with files", 8443, 80, 10001, httpsProxyListenerConfig{Port: 9443, CertMethod: "files"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := Settings{Mode: Shared, RealityDest: realitySelf, Ports: Ports{Fast: 443, Stealth: tc.stealth, VMess: tc.vmess}, Rescue: &RescueConfig{Port: tc.rescue}}
			var cfg *httpsProxyListenerConfig
			if tc.proxy.Port != 0 {
				cfg = &tc.proxy
			}
			err := settings.validateSharedTCPPorts(cfg)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), "conflicts with "+tc.want)) {
				t.Fatalf("port validation: %v", err)
			}
		})
	}
	if err := (Settings{}).validateSharedTCPPorts(&httpsProxyListenerConfig{Port: 80, CertMethod: "http"}); err == nil {
		t.Fatal("the HTTPS proxy can never use TCP 80 as its own listener")
	}
	for _, port := range []uint16{443, 2053, 2083, 2087, 2096, 8443} {
		if warning := RescuePortWarning(port); warning != "" {
			t.Errorf("supported port %d: %s", port, warning)
		}
	}
	if warning := RescuePortWarning(9443); !strings.Contains(warning, "9443") || !strings.Contains(warning, "Cloudflare") {
		t.Fatalf("unsupported port warning: %q", warning)
	}
}

func TestLegacySharedRescueAndProxyMigration(t *testing.T) {
	dir := t.TempDir()
	must(t, InitWithOptions(dir, "origin.example", "", InitOptions{Mode: Shared}))
	s, err := ReadSettings(dir)
	must(t, err)
	s.CDNDomain = testRescueDomain
	s.RescueListen = "172.17.0.1:18080"
	s.HTTPSProxyListener = &httpsProxyListenerConfig{Domain: testProxyDomain, Port: 9443, CertMethod: "nginx", ACMEListen: "172.17.0.1:18081"}
	s.borrowProxySite()
	must(t, writeJSON(dir, settingsFile, s))
	before, err := ReadSettings(dir)
	must(t, err)
	if before.RescueListen != s.RescueListen || before.HTTPSProxyListener.ACMEListen != s.HTTPSProxyListener.ACMEListen {
		t.Fatal("retired state was not read")
	}
	_, err = startSharedRescue(t.Context(), before, RunOptions{}, "", nil, io.Discard, func(string) {})
	if err == nil || err.Error() != retiredRescue {
		t.Fatalf("retired Rescue startup: %v", err)
	}
	_, err = startSharedHTTPSProxy(t.Context(), dir, "", *before.HTTPSProxyListener, nil, io.Discard, func(string) {}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cert.dns") || !strings.Contains(err.Error(), "cert.file") {
		t.Fatalf("retired proxy startup: %v", err)
	}
	if err := before.realityTargetProblem(); err == nil || err.Error() != retiredProxy {
		t.Fatalf("legacy proxy must keep Stealth off: %v", err)
	}
	raw, _, proxy, err := AddWithProxy(dir, "phone", false)
	must(t, err)
	legacy, err := link.Parse(raw)
	must(t, err)
	if proxy != "" || legacy.CDN != "" || legacy.WSPath != "" || legacy.CDNPort != 0 {
		t.Fatalf("unexpected retired endpoints in link: %+v", legacy)
	}
	devices, err := os.ReadFile(filepath.Join(dir, devicesFile))
	must(t, err)

	cert, key := writeProxyTestPair(t, testRescueDomain, t.TempDir())
	port, err := SetRescue(dir, nil, RescueConfig{Cert: cert, Key: key})
	must(t, err)
	if port != DefaultRescuePort {
		t.Fatalf("Rescue default port %d", port)
	}
	active, err := ReadSettings(dir)
	must(t, err)
	if active.RescueListen != "" || active.Rescue == nil || active.Ports.VMess == 0 || active.CDNDomain != testRescueDomain {
		t.Fatalf("unexpected migrated Rescue configuration: %+v", active.Rescue)
	}
	if _, err := SetRescue(dir, new("wrong.example"), RescueConfig{}); err == nil {
		t.Fatal("changing to a name that is absent from the certificate succeeded")
	}
	port, err = SetRescue(dir, nil, RescueConfig{Port: 443})
	must(t, err)
	if port != 443 {
		t.Fatalf("Rescue port change got %d", port)
	}
	raw, _, _, err = AddWithProxy(dir, "after-migration", false)
	must(t, err)
	profile, err := link.Parse(raw)
	must(t, err)
	if profile.CDN != testRescueDomain || profile.CDNPort != 0 || profile.CDNEndpointPort() != 443 {
		t.Fatalf("default HTTPS port was not normalized: %+v", profile)
	}
	must(t, Revoke(dir, "after-migration"))
	must(t, enableTestProxy(t, dir, testProxyDomain, DefaultProxyPort, nil))
	port, err = SetRescue(dir, new(""), RescueConfig{})
	must(t, err)
	after, err := ReadSettings(dir)
	must(t, err)
	if after.RescueListen != "" || after.Rescue != nil || after.CDNDomain != "" || after.Ports.VMess != 0 || port != 0 {
		t.Fatal("clearing Rescue kept dedicated state")
	}
	if after.HTTPSProxyListener == nil || after.HTTPSProxyListener.retired() || after.realityTargetProblem() != nil {
		t.Fatal("migrating the HTTPS proxy did not restore its listener and Stealth settings")
	}
	if after.RealityPrivateKey != before.RealityPrivateKey || after.RealityPublicKey != before.RealityPublicKey ||
		after.WSPath != before.WSPath || !bytes.Equal(after.FastPrivateKey, before.FastPrivateKey) {
		t.Fatal("Rescue migration changed the server's identity")
	}
	kept, err := os.ReadFile(filepath.Join(dir, devicesFile))
	must(t, err)
	if !bytes.Equal(kept, devices) {
		t.Fatal("Rescue migration changed devices")
	}
	for _, path := range []string{active.Rescue.Cert, active.Rescue.Key} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("clearing Rescue kept a managed certificate or key: %v", err)
		}
	}
	for _, path := range []string{cert, key} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("source certificate or key was modified: %v", err)
		}
	}
}

func TestRescueNameMustDifferFromFast(t *testing.T) {
	const origin, fast = "203.0.113.7", "fast.example"
	for _, opts := range []InitOptions{
		{Mode: Shared, FastSNI: fast},
		{Mode: Shared, ProxyDomain: fast},
		{Mode: Standalone, FastSNI: fast},
	} {
		if err := InitWithOptions(t.TempDir(), origin, strings.ToUpper(fast), opts); !errors.Is(err, errRescueFastName) {
			t.Fatalf("initializing with the Fast TLS name as the CDN name: %v", err)
		}
	}
	dir := t.TempDir()
	must(t, InitWithOptions(dir, origin, "", InitOptions{Mode: Shared, FastSNI: fast}))
	if _, err := SetRescue(dir, new(fast), RescueConfig{}); !errors.Is(err, errRescueFastName) {
		t.Fatalf("setting Rescue to the Fast TLS name: %v", err)
	}

	// Older states allowed the same name, and continue to load for Fast and migration.
	s, err := ReadSettings(dir)
	must(t, err)
	s.CDNDomain = fast
	s.Rescue = &RescueConfig{Port: DefaultRescuePort, Cert: filepath.Join(dir, "cert.pem"), Key: filepath.Join(dir, "key.pem")}
	s.Ports.VMess = 10001
	must(t, writeJSON(dir, settingsFile, s))
	legacy, err := ReadSettings(dir)
	must(t, err)
	if legacy.CDNDomain != fast || legacy.Rescue == nil || legacy.rescuePort() != 0 {
		t.Fatal("older state must retain its configured Rescue settings for migration")
	}
	_, err = startSharedRescue(t.Context(), legacy, RunOptions{}, "127.0.0.1", nil, io.Discard, func(string) {})
	if !errors.Is(err, errRescueFastName) || !strings.Contains(err.Error(), "pipe server rescue") {
		t.Fatalf("expected actionable startup guidance for the old settings, got %v", err)
	}
	raw, _, err := Add(dir, "phone", false)
	must(t, err)
	profile, err := link.Parse(raw)
	must(t, err)
	if profile.CDN != "" || profile.WSPath != "" || profile.CDNPort != 0 {
		t.Fatal("the link advertised the disabled Rescue endpoint")
	}
	_, err = SetRescue(dir, new(""), RescueConfig{})
	must(t, err)
}

type rescueSessionCache struct{ tls.ClientSessionCache }

func (c rescueSessionCache) Get(string) (*tls.ClientSessionState, bool) {
	return c.ClientSessionCache.Get(testRescueDomain)
}

func (c rescueSessionCache) Put(_ string, state *tls.ClientSessionState) {
	c.ClientSessionCache.Put(testRescueDomain, state)
}

func TestRescueTLSGatesNewAndResumedHandshakes(t *testing.T) {
	certificate, err := testCertificate(t.TempDir(), Settings{Domain: testRescueDomain})
	must(t, err)
	config := rescueTLSConfig(testRescueDomain, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return certificate, nil }, nil)
	cache := rescueSessionCache{tls.NewLRUClientSessionCache(1)}
	for _, tc := range []struct {
		name, sni    string
		resume, want bool
	}{
		{"no SNI", "", false, false},
		{"wrong SNI", "wrong.example", false, false},
		{"IP", "127.0.0.1", false, false},
		{"Rescue SNI", testRescueDomain, false, true},
		{"resume", testRescueDomain, true, true},
		{"resume without SNI", "", true, false},
		{"resume with wrong SNI", "wrong.example", true, false},
		{"resume with IP", "127.0.0.1", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var session *tls.ClientSessionState
			if tc.resume {
				var ok bool
				session, ok = cache.Get("")
				if !ok {
					t.Fatal("the client did not cache a Rescue session")
				}
			}
			serverWire, clientWire := net.Pipe()
			defer serverWire.Close()
			defer clientWire.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			server := tls.Server(serverWire, config)
			go func() { done <- server.HandshakeContext(ctx) }()
			client := tls.Client(clientWire, &tls.Config{
				MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
				ServerName: tc.sni, InsecureSkipVerify: true, ClientSessionCache: cache,
			})
			err := client.HandshakeContext(ctx)
			if serverErr := <-done; (err == nil) != tc.want || (serverErr == nil) != tc.want {
				t.Fatalf("TLS SNI %q: client %v, server %v", tc.sni, err, serverErr)
			}
			state := client.ConnectionState()
			if tc.want && state.DidResume != tc.resume {
				t.Fatalf("TLS resumption = %t, want %t", state.DidResume, tc.resume)
			}
			if !tc.want && len(state.PeerCertificates) != 0 {
				t.Fatal("rejected handshake received the Rescue certificate")
			}
			if session != nil {
				cache.Put("", session)
			}
		})
	}
}

func TestSharedRescueRequiresCloudflareClientCertificate(t *testing.T) {
	caDir, stateDir := t.TempDir(), t.TempDir()
	certPath, keyPath := writeProxyTestPair(t, testRescueDomain, caDir)
	held, err := net.Listen("tcp4", "127.0.0.1:0")
	must(t, err)
	port := uint16(held.Addr().(*net.TCPAddr).Port)
	defer held.Close()
	must(t, InitWithOptions(stateDir, "origin.example", testRescueDomain, InitOptions{
		Mode: Shared, Rescue: RescueConfig{Port: port, Cert: certPath, Key: keyPath},
	}))
	settings, err := ReadSettings(stateDir)
	must(t, err)
	originCA := filepath.Join(caDir, TestRootFile)
	options := RunOptions{CFOriginCA: originCA}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "Rescue cover") })
	warnings := make(chan string, 2)
	warn := func(message string) { warnings <- message }
	if _, err := startSharedRescue(t.Context(), settings, options, "127.0.0.1", handler, io.Discard, warn); err == nil ||
		!strings.Contains(err.Error(), fmt.Sprintf("bind TCP port %d", port)) {
		t.Fatalf("occupied Rescue port: %v", err)
	}
	must(t, held.Close())
	stopProduction, err := startSharedRescue(t.Context(), settings, options, "127.0.0.1", handler, io.Discard, warn)
	must(t, err)
	defer stopProduction()
	select {
	case warning := <-warnings:
		if !strings.Contains(warning, "Rescue certificate expires") || !strings.Contains(warning, "rescue.cert and rescue.key") {
			t.Fatalf("unexpected startup warning: %s", warning)
		}
	default:
		t.Fatal("Rescue did not warn about its short-lived certificate at startup")
	}
	conn, err := net.DialTimeout("tcp4", loopback(port), 3*time.Second)
	must(t, err)
	defer conn.Close()
	must(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	var received [1]byte
	if n, err := conn.Read(received[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("production listener sent %d bytes to loopback or kept it open: %v", n, err)
	}
	stopProduction()
	options.TestPorts = true
	stop, err := startSharedRescue(t.Context(), settings, options, "127.0.0.1", handler, io.Discard, warn)
	must(t, err)
	defer stop()
	now := time.Now()
	root, rootKey, err := loadOrCreateTestRoot(caDir, now)
	must(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	serial, err := randomSerial()
	must(t, err)
	leaf := &x509.Certificate{
		SerialNumber: serial, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	must(t, err)
	clientCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	for _, withCert := range []bool{false, true} {
		config := &tls.Config{RootCAs: roots, ServerName: testRescueDomain}
		if withCert {
			config.Certificates = []tls.Certificate{clientCert}
		}
		transport := &http.Transport{TLSClientConfig: config, DisableKeepAlives: true}
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		response, err := client.Get("https://" + loopback(port))
		if !withCert {
			if err == nil {
				response.Body.Close()
				t.Fatal("Rescue listener accepted a client with no certificate")
			}
			continue
		}
		must(t, err)
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		must(t, err)
		if response.StatusCode != http.StatusOK || string(body) != "Rescue cover" {
			t.Fatalf("verified client got %s %q", response.Status, body)
		}
	}
}
