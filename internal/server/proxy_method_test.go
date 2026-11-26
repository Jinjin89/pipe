// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

func fakeProbe(occupied bool, err error) func() (bool, error) {
	return func() (bool, error) { return occupied, err }
}

func TestSelectProxyCertMethod(t *testing.T) {
	for _, test := range []struct {
		name   string
		opts   ProxyEnableOptions
		probe  func() (bool, error)
		want   string
		failed string
	}{
		{"explicit http on free port", ProxyEnableOptions{CertMethod: "http"}, fakeProbe(false, nil), "http", ""},
		{"explicit http on busy port", ProxyEnableOptions{CertMethod: "http"}, fakeProbe(true, nil), "", "TCP 80 is busy"},
		{"retired nginx", ProxyEnableOptions{CertMethod: "nginx"}, nil, "", "choose --cert-method"},
		{"explicit files", ProxyEnableOptions{CertMethod: "files"}, nil, "files", ""},
		{"unknown", ProxyEnableOptions{CertMethod: "tls"}, nil, "", "choose --cert-method"},
		{"implicit files", ProxyEnableOptions{CertFile: "c"}, nil, "files", ""},
		{"auto key only", ProxyEnableOptions{KeyFile: "k"}, nil, "files", ""},
		{"auto dns", ProxyEnableOptions{DNS: "cloudflare"}, nil, "dns", ""},
		{"auto free port", ProxyEnableOptions{}, fakeProbe(false, nil), "http", ""},
		{"auto busy port", ProxyEnableOptions{CertMethod: "auto"}, fakeProbe(true, nil), "", "TCP 80 is busy"},
		{"auto probe error", ProxyEnableOptions{}, fakeProbe(false, errors.New("denied")), "", "cannot probe TCP 80"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, reason, err := selectProxyCertMethod(test.opts, test.probe)
			if test.failed != "" {
				if err == nil || !strings.Contains(err.Error(), test.failed) {
					t.Fatalf("expected %q, got %v", test.failed, err)
				}
				return
			}
			if err != nil || got != test.want || reason == "" {
				t.Fatalf("got %q (%q), %v", got, reason, err)
			}
		})
	}
}

func enableWithMethod(t *testing.T, dir string, opts ProxyEnableOptions) error {
	t.Helper()
	opts.Domain = testProxyDomain
	opts.Port = DefaultProxyPort
	setup := testProxySetup()
	setup.issue = func(context.Context, string, string, certmagic.DNSProvider, bool) error {
		t.Fatal("HTTP-01 methods must not issue during enable")
		return nil
	}
	return enableProxy(t.Context(), dir, opts, setup)
}

func TestProxyEnableRejectsRetiredMethodAndMixedHTTP(t *testing.T) {
	dir := initProxyTestState(t)
	if err := enableWithMethod(t, dir, ProxyEnableOptions{CertMethod: "nginx"}); err == nil {
		t.Fatal("accepted the retired certificate method")
	}
	if err := enableWithMethod(t, dir, ProxyEnableOptions{CertMethod: "http", DNS: "cloudflare"}); err == nil {
		t.Fatal("HTTP-01 must not mix with DNS settings")
	}
}

func TestProxyHTTPMethodSavesWithoutIssuing(t *testing.T) {
	dir := initProxyTestState(t)
	if err := enableWithMethod(t, dir, ProxyEnableOptions{CertMethod: "http"}); err != nil {
		t.Fatal(err)
	}
	info, err := ProxyStatus(dir)
	if err != nil || info.Method != "http" || info.Source != "HTTP-01" || !info.Expiry.IsZero() {
		t.Fatalf("unexpected status %+v: %v", info, err)
	}
}

func TestProxyManagedCertificatesConfigureHTTP(t *testing.T) {
	cfg := httpsProxyListenerConfig{Domain: testProxyDomain, CertMethod: "http"}
	config, cache, err := proxyManagedCertificates(t.TempDir(), cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Stop()
	acme := config.Issuers[0].(*certmagic.ACMEIssuer)
	if acme.ListenHost != "" || acme.AltHTTPPort != 0 || acme.DisableHTTPChallenge || acme.DNS01Solver != nil {
		t.Fatalf("http issuer should use certmagic's default listener: %+v", acme)
	}
}

func TestProxyDNSWithoutTerminalNamesTheKeyFileFlag(t *testing.T) {
	dir := initProxyTestState(t)
	for provider, flag := range map[string]string{"cloudflare": "--dns-token-file", "alidns": "--dns-key-file"} {
		err := enableWithMethod(t, dir, ProxyEnableOptions{CertMethod: "dns", DNS: provider})
		if err == nil || !strings.Contains(err.Error(), flag) {
			t.Fatalf("%s: expected an error naming %s, got %v", provider, flag, err)
		}
	}
}

func TestProxyDNSReadsSecretFromTerminalCallback(t *testing.T) {
	dir := initProxyTestState(t)
	var asked string
	var issued bool
	setup := testProxySetup()
	setup.issue = func(_ context.Context, _, _ string, _ certmagic.DNSProvider, _ bool) error { issued = true; return nil }
	err := enableProxy(t.Context(), dir, ProxyEnableOptions{
		Domain: testProxyDomain, Port: DefaultProxyPort, CertMethod: "dns", DNS: "alidns",
		ReadSecret: func(provider string) ([]byte, error) {
			asked = provider
			return []byte("access_key_id=id1\naccess_key_secret=secret1\n"), nil
		},
	}, setup)
	if err != nil || asked != "alidns" || !issued {
		t.Fatalf("asked=%q issued=%v err=%v", asked, issued, err)
	}
}

func TestProxyStatusReadsExpiryFromStorage(t *testing.T) {
	dir := initProxyTestState(t)
	if err := enableWithMethod(t, dir, ProxyEnableOptions{CertMethod: "http"}); err != nil {
		t.Fatal(err)
	}
	info, err := ProxyStatus(dir)
	if err != nil || !info.Expiry.IsZero() {
		t.Fatalf("no certificate yet: %+v %v", info, err)
	}
	certDir := t.TempDir()
	cert, _ := writeProxyTestPair(t, testProxyDomain, certDir)
	data, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey := (&certmagic.ACMEIssuer{CA: certmagic.LetsEncryptProductionCA}).IssuerKey()
	stored := filepath.Join(dir, proxyCertificateStorage, filepath.FromSlash(certmagic.StorageKeys.SiteCert(issuerKey, testProxyDomain)))
	if err := os.MkdirAll(filepath.Dir(stored), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stored, data, 0600); err != nil {
		t.Fatal(err)
	}
	info, err = ProxyStatus(dir)
	if err != nil || info.Expiry.IsZero() || time.Until(info.Expiry) < time.Hour {
		t.Fatalf("expiry should come from storage: %+v %v", info, err)
	}
}
