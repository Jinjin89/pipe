// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

func writeProxyTestPair(t *testing.T, domain, dir string) (string, string) {
	t.Helper()
	certificate, err := testCertificate(dir, Settings{Domain: domain})
	if err != nil {
		t.Fatal(err)
	}
	return writeProxyTestPEM(t, dir, certificate)
}

func writeProxyTestPEM(t *testing.T, dir string, certificate *tls.Certificate) (string, string) {
	t.Helper()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	const certFile, keyFile = "fullchain.pem", "key.pem"
	if err := writeAtomic(dir, certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(dir, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
}

func TestProxyCertFileReloadPreservesLastGoodPair(t *testing.T) {
	oldCert, oldKey := writeProxyTestPair(t, testProxyDomain, t.TempDir())
	newCert, newKey := writeProxyTestPair(t, testProxyDomain, t.TempDir())
	dir := t.TempDir()
	cfg := httpsProxyListenerConfig{Domain: testProxyDomain, Cert: filepath.Join(dir, "cert"), Key: filepath.Join(dir, "key")}
	swapLink := func(target, destination string) {
		t.Helper()
		next := destination + ".next"
		if err := os.Symlink(target, next); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlinks unavailable: %v", err)
			}
			t.Fatal(err)
		}
		if err := os.Rename(next, destination); err != nil {
			t.Fatal(err)
		}
	}
	swapLink(oldCert, cfg.Cert)
	swapLink(oldKey, cfg.Key)
	var warnings []string
	certificates := proxyPEMCertificates{cfg: cfg, warn: func(message string) { warnings = append(warnings, message) }}
	now := time.Now()
	first, err := certificates.certificateAt(now)
	if err != nil {
		t.Fatal(err)
	}
	swapLink(newCert, cfg.Cert)
	if pair, err := certificates.certificateAt(now.Add(30 * time.Second)); err != nil || pair != first || len(warnings) != 0 {
		t.Fatalf("checked the files before the one-minute interval: %v", err)
	}
	if pair, err := certificates.certificateAt(now.Add(time.Minute)); err != nil || pair != first || len(warnings) != 1 {
		t.Fatalf("mismatched renewal failed to retain the old pair: %v", err)
	}
	swapLink(newKey, cfg.Key)
	if pair, err := certificates.certificateAt(now.Add(2 * time.Minute)); err != nil || pair == first ||
		bytes.Equal(pair.Certificate[0], first.Certificate[0]) || len(warnings) != 1 {
		t.Fatalf("matching replacement files were not picked up: %v", err)
	}
	cfg.Domain = "different.example"
	if _, err := loadProxyPEM(cfg, now); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatal("accepted a certificate for a different hostname")
	}
}

func TestProxyPEMStartupChecksAndRetriesWithoutACertificate(t *testing.T) {
	dir := t.TempDir()
	cfg := httpsProxyListenerConfig{Domain: testProxyDomain, Cert: filepath.Join(dir, "fullchain.pem"), Key: filepath.Join(dir, "key.pem")}
	var warnings []string
	start := time.Now()
	certificates := newProxyPEMCertificates(cfg, func(message string) { warnings = append(warnings, message) })
	retry := certificates.nextCheck
	if len(warnings) != 1 || certificates.current != nil ||
		retry.Before(start.Add(5*time.Second)) || retry.After(time.Now().Add(5*time.Second)) {
		t.Fatal("startup did not warn and schedule a five-second retry")
	}
	writeProxyTestPair(t, testProxyDomain, dir)
	if pair, err := certificates.certificateAt(retry.Add(-time.Nanosecond)); err == nil || pair != nil || len(warnings) != 1 {
		t.Fatal("reloaded the missing certificate before the retry interval")
	}
	if pair, err := certificates.certificateAt(retry); err != nil || pair == nil ||
		!certificates.nextCheck.Equal(retry.Add(time.Minute)) {
		t.Fatalf("certificate did not recover after five seconds: %v", err)
	}
}

func TestProxyCertReloadRejectsInvalidValidityPeriods(t *testing.T) {
	for _, test := range []struct {
		name                string
		notBefore, notAfter time.Duration
		warning             string
	}{
		{"expired", -time.Hour, -time.Minute, "expired"},
		{"not yet valid", 2 * time.Minute, time.Hour, "not yet valid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			cert, key := writeProxyTestPair(t, testProxyDomain, dir)
			cfg := httpsProxyListenerConfig{Domain: testProxyDomain, Cert: cert, Key: key}
			var warnings []string
			certificates := proxyPEMCertificates{cfg: cfg, warn: func(message string) { warnings = append(warnings, message) }}
			now := time.Now()
			good, err := certificates.certificateAt(now)
			if err != nil {
				t.Fatal(err)
			}
			template := *good.Leaf
			template.NotBefore = now.Add(test.notBefore)
			template.NotAfter = now.Add(test.notAfter)
			der, err := x509.CreateCertificate(rand.Reader, &template, &template, template.PublicKey, good.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			writeProxyTestPEM(t, dir, &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: good.PrivateKey})
			if pair, err := certificates.certificateAt(now.Add(time.Minute)); err != nil || pair != good ||
				len(warnings) != 1 || !strings.Contains(warnings[0], test.warning) {
				t.Fatalf("invalid replacement did not preserve the last valid certificate: %v", err)
			}
			if pair, err := certificates.certificateAt(good.Leaf.NotAfter); err == nil || pair != nil {
				t.Fatal("served the cached certificate after its expiry")
			}
		})
	}
}

func TestProxyRefusesInsecureSecretAndKeyFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are required")
	}
	dir := t.TempDir()
	cert, key := writeProxyTestPair(t, testProxyDomain, dir)
	if err := os.Chmod(key, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProxyPEM(httpsProxyListenerConfig{Domain: testProxyDomain, Cert: cert, Key: key}, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "owner") {
		t.Fatal("accepted a TLS key readable by the group")
	}
	for _, provider := range []string{proxyDNSCloudflare, proxyDNSAliDNS} {
		secret := filepath.Join(dir, provider)
		if err := os.WriteFile(secret, []byte("test-value"), 0644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readProxyDNSSecret(provider, secret); err == nil || !strings.Contains(err.Error(), "owner") {
			t.Errorf("accepted a world-readable %s secret", provider)
		}
	}
}

func TestProxyDNSCredentialParsing(t *testing.T) {
	for _, test := range []struct {
		provider, contents string
		valid              bool
	}{
		{proxyDNSCloudflare, "one-token\n", true},
		{proxyDNSCloudflare, "one-token\r\n", true},
		{proxyDNSCloudflare, "", false},
		{proxyDNSCloudflare, "one-token\n\n", false},
		{proxyDNSCloudflare, "one\x00-token", false},
		{proxyDNSCloudflare, "one\nsecond-token", false},
		{proxyDNSAliDNS, "access_key_id=test-id\naccess_key_secret=test-secret\n", true},
		{proxyDNSAliDNS, "access_key_secret=test-secret\r\naccess_key_id=test-id\r\n", true},
		{proxyDNSAliDNS, "access_key_id=test-id\naccess_key_id=duplicate\n", false},
		{proxyDNSAliDNS, "access_key_id=test-id\naccess_key_secret=\n", false},
		{proxyDNSAliDNS, "access_key_id=test-id\naccess_key_secret=test-secret\nregion_id=extra\n", false},
		{proxyDNSAliDNS, "access_key_id=test-id\naccess_key_secret=test\x1bsecret", false},
	} {
		secretFile := filepath.Join(t.TempDir(), "dns-secret")
		if err := os.WriteFile(secretFile, []byte(test.contents), 0600); err != nil {
			t.Fatal(err)
		}
		_, _, err := readProxyDNSSecret(test.provider, secretFile)
		if (err == nil) != test.valid {
			t.Errorf("unexpected result for %s credential fixture: %v", test.provider, err)
		}
	}
}

type fakeProxyDNS struct{ appended, deleted bool }

func (p *fakeProxyDNS) AppendRecords(_ context.Context, _ string, records []libdns.Record) ([]libdns.Record, error) {
	p.appended = true
	return records, nil
}

func (p *fakeProxyDNS) DeleteRecords(_ context.Context, _ string, records []libdns.Record) ([]libdns.Record, error) {
	p.deleted = true
	return records, nil
}

func TestProxyACMETightensExistingStoragePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are required")
	}
	dir := t.TempDir()
	storage := filepath.Join(dir, "https-proxy-certificates")
	if err := os.Mkdir(storage, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(storage, 0755); err != nil {
		t.Fatal(err)
	}
	_, stop, err := proxyACMEConfig(dir, &fakeProxyDNS{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	info, err := os.Stat(storage)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("ACME storage has mode %o", info.Mode().Perm())
	}
}

func TestProxyACMEUsesInjectedDNS01ProviderAndRedactsWarnings(t *testing.T) {
	for _, provider := range []string{proxyDNSCloudflare, proxyDNSAliDNS} {
		t.Run(provider, func(t *testing.T) {
			fake := &fakeProxyDNS{}
			var warnings []string
			cfg, stop, err := proxyACMEConfig(t.TempDir(), fake, func(message string) {
				warnings = append(warnings, message)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			if len(cfg.Issuers) != 1 || cfg.OnDemand != nil {
				t.Fatal("expected one ACME issuer and no handshake-triggered issuance")
			}
			issuer := cfg.Issuers[0].(*certmagic.ACMEIssuer)
			solver, ok := issuer.DNS01Solver.(*certmagic.DNS01Solver)
			if !ok || solver.DNSProvider != fake || issuer.CA != certmagic.LetsEncryptProductionCA ||
				issuer.Email != "" || issuer.TestCA != "" || !issuer.Agreed || !issuer.DisableHTTPChallenge || !issuer.DisableTLSALPNChallenge {
				t.Fatal("proxy issuer is not configured for production DNS-01 only")
			}
			_, _ = solver.DNSProvider.AppendRecords(t.Context(), "other.example.", nil)
			_, _ = solver.DNSProvider.DeleteRecords(t.Context(), "other.example.", nil)
			if !fake.appended || !fake.deleted {
				t.Fatal("the DNS solver did not use the injected provider")
			}
			cfg.Logger.Error("provider failure containing fake-token", zap.String("signed_request", "fake-secret"))
			if len(warnings) != 1 || strings.Contains(warnings[0], "fake-") {
				t.Fatal("provider failure was not reported with sensitive content removed")
			}
		})
	}
}

func TestStrictProxySNIRejectsHandshakesBeforeSelectingCertificate(t *testing.T) {
	dir := t.TempDir()
	certificate, err := testCertificate(dir, Settings{Domain: testProxyDomain})
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := loadOrCreateTestRoot(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	for _, name := range []string{"", "wrong.example", strings.ToUpper(testProxyDomain)} {
		t.Run(name, func(t *testing.T) {
			peer, wire := net.Pipe()
			defer peer.Close()
			defer wire.Close()
			want := strings.EqualFold(name, testProxyDomain)
			certSelected := false
			server := tls.Server(peer, strictProxyTLS(testProxyDomain, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				certSelected = true
				return certificate, nil
			}))
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			serverDone := make(chan error, 1)
			go func() { serverDone <- server.HandshakeContext(ctx) }()
			client := tls.Client(wire, &tls.Config{
				RootCAs: roots, ServerName: name, NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: !want,
			})
			err := client.HandshakeContext(ctx)
			serverErr := <-serverDone
			if (err == nil) != want || (serverErr == nil) != want || certSelected != want {
				t.Fatalf("unexpected strict-SNI result for %q: client %v, server %v", name, err, serverErr)
			}
			if want && client.ConnectionState().NegotiatedProtocol != "http/1.1" {
				t.Fatal("the proxy did not negotiate HTTP/1.1")
			}
		})
	}
}

func TestSharedProxyCover(t *testing.T) {
	page, err := generateCoverSite(testCoverKey(1), mainCoverLabel)
	if err != nil {
		t.Fatal(err)
	}
	cover, err := proxyCover("", page)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newHTTPSProxy(cover, nil)
	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		for _, auth := range []string{"", basicProxyAuth("phone", "wrong")} {
			req := httptest.NewRequest(method, "http://11.0.0.80/nonexistent", nil)
			req.Header.Set("Proxy-Authorization", auth)
			w := httptest.NewRecorder()
			proxy.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound || w.Body.String() != "404 page not found\n" || w.Header().Get("Proxy-Authenticate") != "" {
				t.Fatalf("unexpected unauthenticated response for %s", method)
			}
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("dedicated site"), 0600); err != nil {
		t.Fatal(err)
	}
	cover, err = proxyCover(dir, page)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	newHTTPSProxy(cover, nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK || w.Body.String() != "dedicated site" {
		t.Fatal("the --www cover did not serve the configured site")
	}
}
