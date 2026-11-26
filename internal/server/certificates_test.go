// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

func testCertificate(dir string, settings Settings) (*tls.Certificate, error) {
	name := strings.ToLower(settings.webName())
	certificates, err := testCertificates(dir, []string{name})
	return certificates[name], err
}

type certificateTestIssuer func(context.Context, *x509.CertificateRequest) (*certmagic.IssuedCertificate, error)

func (certificateTestIssuer) IssuerKey() string { return "pipe-fixture" }

func (issue certificateTestIssuer) Issue(ctx context.Context, request *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	return issue(ctx, request)
}

func TestStandaloneRescueIssuanceDoesNotBlockRequiredCertificates(t *testing.T) {
	settings := Settings{Domain: "origin.example.test", FastSNI: "fast.example.test", CDNDomain: "cdn.example.test"}
	dir := t.TempDir()
	now := time.Now()
	root, key, err := loadOrCreateTestRoot(dir, now)
	must(t, err)
	config, _, cache, err := managedCertificates(dir, settings)
	must(t, err)
	defer cache.Stop()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	rescueStarted, failRescue, rescueFailed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	config.Issuers = []certmagic.Issuer{certificateTestIssuer(func(ctx context.Context, request *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
		if request.DNSNames[0] == settings.CDNDomain {
			close(rescueStarted)
			select {
			case <-failRescue:
			case <-ctx.Done():
			}
			close(rescueFailed)
			return nil, certmagic.ErrNoRetry{Err: errors.New("fixture cannot issue the Rescue certificate")}
		}
		serial, err := randomSerial()
		if err != nil {
			return nil, err
		}
		leaf := &x509.Certificate{
			SerialNumber: serial, DNSNames: request.DNSNames, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, root, request.PublicKey, key)
		if err != nil {
			return nil, err
		}
		return &certmagic.IssuedCertificate{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
	})}

	must(t, manageStandaloneCertificates(ctx, config, settings, io.Discard))
	select {
	case <-rescueStarted:
	case <-ctx.Done():
		t.Fatal("Rescue did not start obtaining its certificate in the background")
	}
	peer, conn := net.Pipe()
	defer peer.Close()
	defer conn.Close()
	checkRescue := func() error {
		return rescueCertificateProblem(settings.CDNDomain, cachedCertificate(cache, settings.CDNDomain))
	}
	rescueTLS := standaloneRescueTLSConfig(settings.CDNDomain, config.GetCertificate, nil, checkRescue)
	rescueHello := &tls.ClientHelloInfo{Conn: conn, ServerName: settings.CDNDomain}
	assertRescueClosed := func() {
		t.Helper()
		if _, err := rescueTLS.GetConfigForClient(rescueHello); err == nil || !strings.Contains(err.Error(), "waiting for the TLS certificate") {
			t.Fatalf("Rescue TLS should wait for its own certificate: %v", err)
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	assertRequired := func() {
		t.Helper()
		for _, name := range settings.mainNames() {
			pair, err := config.GetCertificate(&tls.ClientHelloInfo{Conn: conn, ServerName: name})
			must(t, err)
			_, err = pair.Leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots})
			must(t, err)
		}
	}
	assertRequired()
	assertRescueClosed()
	close(failRescue)
	select {
	case <-rescueFailed:
	case <-ctx.Done():
		t.Fatal("Rescue issuance did not finish")
	}
	assertRequired()
	assertRescueClosed()
	pair, err := issueLeaf(settings.CDNDomain, now, 24*time.Hour, root, key)
	must(t, err)
	_, err = config.CacheUnmanagedTLSCertificate(ctx, *pair, nil)
	must(t, err)
	_, err = rescueTLS.GetConfigForClient(rescueHello)
	must(t, err)
}

func TestHTTP01UsesTheExistingRedirectHandler(t *testing.T) {
	settings := Settings{Domain: "origin.example.test", CDNDomain: "cdn.example.test", Ports: Ports{HTTP: 18080, HTTPS: 18443}}
	config, issuer, cache, err := managedCertificates(t.TempDir(), settings)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Stop()
	if issuer.ListenHost != "" || issuer.AltHTTPPort != 18080 || issuer.DisableHTTPChallenge || !issuer.DisableTLSALPNChallenge {
		t.Fatal("issuer should reuse the existing HTTP-01 listener")
	}
	// Simulate the distributed solver storing a challenge before Present checks
	// the bound port. The handler can complete it without a second listener.
	handler := issuer.HTTPChallengeHandler(redirectHTTPS(settings))
	for _, domain := range []string{settings.Domain, settings.CDNDomain} {
		key := path.Join("acme", certmagic.StorageKeys.Safe(issuer.IssuerKey()), "challenge_tokens", certmagic.StorageKeys.Safe(domain)+".json")
		challenge := []byte(`{"type":"http-01","token":"pipeToken","keyAuthorization":"pipeToken.testSignature","identifier":{"type":"dns","value":"` + domain + `"}}`)
		must(t, config.Storage.Store(t.Context(), key, challenge))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://"+domain+"/.well-known/acme-challenge/pipeToken", nil))
		if response.Code != http.StatusOK || response.Body.String() != "pipeToken.testSignature" {
			t.Fatalf("HTTP-01 for %s got %d %q", domain, response.Code, response.Body.String())
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://"+settings.Domain+"/", nil))
	if response.Code != http.StatusPermanentRedirect || response.Header().Get("Location") != "https://"+settings.Domain+":18443/" {
		t.Fatal("ordinary HTTP requests should still redirect to HTTPS")
	}
	for _, name := range []string{settings.CDNDomain, "unknown.example.test", "127.0.0.1"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://"+name+"/", nil))
		if response.Code != http.StatusNotFound || response.Header().Get("Location") != "" {
			t.Errorf("unexpected HTTP response for %s: %d", name, response.Code)
		}
	}
}
