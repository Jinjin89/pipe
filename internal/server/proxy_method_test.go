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

func fakeProbe(occupied, web bool, err error) func() (bool, bool, error) {
	return func() (bool, bool, error) { return occupied, web, err }
}

func TestSelectProxyCertMethod(t *testing.T) {
	for _, test := range []struct {
		name   string
		opts   ProxyEnableOptions
		probe  func() (bool, bool, error)
		want   string
		failed string
	}{
		{"explicit http skips the probe", ProxyEnableOptions{CertMethod: "http"}, nil, "http", ""},
		{"explicit nginx", ProxyEnableOptions{CertMethod: "nginx"}, nil, "nginx", ""},
		{"explicit files", ProxyEnableOptions{CertMethod: "files"}, nil, "files", ""},
		{"unknown", ProxyEnableOptions{CertMethod: "tls"}, nil, "", "choose --cert-method"},
		{"auto files win", ProxyEnableOptions{CertMethod: "auto", CertFile: "c"}, nil, "files", ""},
		{"auto key only", ProxyEnableOptions{KeyFile: "k"}, nil, "files", ""},
		{"auto dns", ProxyEnableOptions{DNS: "cloudflare"}, nil, "dns", ""},
		{"auto free port", ProxyEnableOptions{}, fakeProbe(false, false, nil), "http", ""},
		{"auto web server", ProxyEnableOptions{}, fakeProbe(true, true, nil), "nginx", ""},
		{"auto unknown service", ProxyEnableOptions{}, fakeProbe(true, false, nil), "", "unidentified"},
		{"auto probe error", ProxyEnableOptions{}, fakeProbe(false, false, errors.New("denied")), "", "cannot probe TCP 80"},
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
	setup.issue = func(context.Context, string, string, certmagic.DNSProvider) error {
		t.Fatal("HTTP-01 methods must not issue during enable")
		return nil
	}
	return enableProxy(t.Context(), dir, opts, setup)
}

func TestProxyNginxMethodDefaultsAndValidation(t *testing.T) {
	dir := initProxyTestState(t)
	if err := enableWithMethod(t, dir, ProxyEnableOptions{CertMethod: "nginx"}); err != nil {
		t.Fatal(err)
	}
	settings, err := ReadSettings(dir)
	if err != nil || settings.HTTPSProxyListener.ACMEListen != "127.0.0.1:18081" || settings.HTTPSProxyListener.CertMethod != "nginx" {
		t.Fatalf("nginx should default to the Rescue IP on 18081: %+v %v", settings.HTTPSProxyListener, err)
	}
	for _, test := range []struct{ name, listen, want string }{
		{"public address", "203.0.113.5:18081", "private IP"},
		{"hostname", "localhost:18081", "private IP"},
		{"port 80", "127.0.0.1:80", "conflicts"},
		{"proxy port", "127.0.0.1:9443", "conflicts"},
		{"stealth port", "127.0.0.1:8443", "conflicts"},
		{"rescue address", "127.0.0.1:10001", "distinct"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := initProxyTestState(t)
			err := enableWithMethod(t, dir, ProxyEnableOptions{CertMethod: "nginx", ACMEListen: test.listen})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}
	other := initProxyTestState(t)
	if err := enableWithMethod(t, other, ProxyEnableOptions{CertMethod: "http", ACMEListen: "127.0.0.1:18081"}); err == nil ||
		!strings.Contains(err.Error(), "--acme-listen requires") {
		t.Fatalf("--acme-listen must need nginx: %v", err)
	}
	if err := enableWithMethod(t, other, ProxyEnableOptions{CertMethod: "http", DNS: "cloudflare"}); err == nil {
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

func TestProxyNginxWithoutRescueNeedsAddress(t *testing.T) {
	cfg, _, err := proxyConfigForEnable(Settings{}, ProxyEnableOptions{Domain: testProxyDomain, CertMethod: "nginx"})
	if err == nil || !strings.Contains(err.Error(), "--acme-listen is required") {
		t.Fatalf("got %+v, %v", cfg, err)
	}
}

func TestProxyManagedCertificatesConfigureACMEListen(t *testing.T) {
	cfg := httpsProxyListenerConfig{Domain: testProxyDomain, CertMethod: "nginx", ACMEListen: "127.0.0.1:18081"}
	config, stop, err := proxyManagedCertificates(t.TempDir(), cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	acme := config.Issuers[0].(*certmagic.ACMEIssuer)
	if acme.ListenHost != "127.0.0.1" || acme.AltHTTPPort != 18081 || acme.DisableHTTPChallenge || acme.DNS01Solver != nil {
		t.Fatalf("nginx issuer misconfigured: %+v", acme)
	}
	config, stop2, err := proxyManagedCertificates(t.TempDir(), httpsProxyListenerConfig{Domain: testProxyDomain, CertMethod: "http"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop2()
	acme = config.Issuers[0].(*certmagic.ACMEIssuer)
	if acme.ListenHost != "" || acme.AltHTTPPort != 0 || acme.DisableHTTPChallenge || acme.DNS01Solver != nil {
		t.Fatalf("http issuer should use certmagic's default listener: %+v", acme)
	}
}

func TestNginxConfigFile(t *testing.T) {
	settings := Settings{
		Mode: Shared, CDNDomain: "static.example.com", RescueListen: "127.0.0.1:10001", WSPath: "/ws",
		HTTPSProxyListener: &httpsProxyListenerConfig{Domain: "gate.example.org", Port: 9443, CertMethod: "nginx", ACMEListen: "127.0.0.1:18081"},
	}
	hostIPv6 := true
	defer func(original func() bool) { hostListensIPv6 = original }(hostListensIPv6)
	hostListensIPv6 = func() bool { return hostIPv6 }
	out := nginxConfig(settings)
	if strings.Count(out, "server {") != 2 || strings.Count(out, "listen 443 ssl;") != 1 ||
		strings.Count(out, "listen [::]:443 ssl;") != 1 || strings.Count(out, "listen 80;") != 1 ||
		strings.Count(out, "listen [::]:80;") != 1 {
		t.Fatalf("expected two full server blocks:\n%s", out)
	}
	// nginx rejects the whole config if it cannot open an IPv6 listen.
	hostIPv6 = false
	if out := nginxConfig(settings); strings.Contains(out, "[::]") || strings.Count(out, "listen 443 ssl;") != 1 || strings.Count(out, "listen 80;") != 1 {
		t.Fatalf("a host without IPv6 must get IPv4 listens only:\n%s", out)
	}
	hostIPv6 = true
	if strings.Count(out, "allow all;") != 1 {
		t.Fatalf("allow all must appear once:\n%s", out)
	}
	acme := out[strings.Index(out, "server_name gate.example.org"):]
	location := acme[strings.Index(acme, "location ^~"):strings.Index(acme, "location / {")]
	for _, want := range []string{"allow all;", "limit_except GET { deny all; }", "proxy_pass http://127.0.0.1:18081;", "proxy_set_header Host $http_host;"} {
		if !strings.Contains(location, want) {
			t.Fatalf("ACME location lacks %q:\n%s", want, location)
		}
	}
	if strings.Count(out, "location / { return 404; }") != 2 || strings.Contains(out, "ssl_certificate") {
		t.Fatalf("both blocks must answer 404 elsewhere without certificate lines:\n%s", out)
	}
	settings.RescueListen, settings.CDNDomain = "", ""
	if out := nginxConfig(settings); strings.Count(out, "server {") != 1 {
		t.Fatalf("without Rescue only the ACME block remains:\n%s", out)
	}
	settings.HTTPSProxyListener.CertMethod = "http"
	if nginxConfig(settings) != "" {
		t.Fatal("http method needs no nginx file")
	}
}

func TestGenerateInstallWritesAndRemovesNginxFile(t *testing.T) {
	dir := initProxyTestState(t)
	if err := enableWithMethod(t, dir, ProxyEnableOptions{CertMethod: "nginx"}); err != nil {
		t.Fatal(err)
	}
	paths, err := GenerateInstall(dir, "/usr/local/bin/pipe")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "install", "pipe-nginx.conf")
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0600 || !contains(paths, file) {
		t.Fatalf("pipe-nginx.conf missing or not 0600: %v", err)
	}
	if err := DisableProxy(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateInstall(dir, "/usr/local/bin/pipe"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(file); err != nil || strings.Contains(string(data), "acme-challenge") {
		t.Fatalf("stale ACME block should be gone: %v", err)
	}
}

func contains(list []string, item string) bool {
	for _, entry := range list {
		if entry == item {
			return true
		}
	}
	return false
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
	setup.issue = func(_ context.Context, _, _ string, _ certmagic.DNSProvider) error { issued = true; return nil }
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
