// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"pipe/internal/link"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/alidns"
	"github.com/libdns/cloudflare"
)

const testProxyDomain = "gate.other.example"

func initProxyTestState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := InitWithOptions(dir, "11.0.0.80", "static.website.example", InitOptions{
		Mode: Shared, FastSNI: "fast.example", RescueListen: "127.0.0.1:10001",
	}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testProxySetup() proxySetup {
	return proxySetup{
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("11.0.0.80")}, nil
		},
		interfaces: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("11.0.0.80"), Mask: net.CIDRMask(24, 32)}}, nil
		},
	}
}

func TestSharedProxyEnableAddDisable(t *testing.T) {
	dir := initProxyTestState(t)
	oldRaw, _, proxy, err := AddWithProxy(dir, "old-phone", false)
	if err != nil || proxy != "" {
		t.Fatalf("unexpected pre-enable enrollment result: %v", err)
	}
	if oldProfile, err := link.Parse(oldRaw); err != nil || oldProfile.HTTPSProxy != "" {
		t.Fatalf("pre-enable link must not set hp: %q %v", oldProfile.HTTPSProxy, err)
	} else if got, ok := link.ProxyURL(oldProfile); ok || got != "" {
		t.Fatalf("pre-enable link must not derive a proxy URL: %q %v", got, ok)
	}
	devices, err := ReadDevices(dir)
	if err != nil || len(devices) != 1 || devices[0].HTTPSProxyPassword == "" {
		t.Fatalf("Add must save a proxy password before the listener is enabled: %v", err)
	}
	devices[0].HTTPSProxyPassword = "" // Simulate state from an earlier build.
	if err := writeJSON(dir, devicesFile, devices); err != nil {
		t.Fatal(err)
	}
	cert, key := writeProxyTestPair(t, testProxyDomain, t.TempDir())
	www := t.TempDir()
	var warnings []string
	opts := ProxyEnableOptions{
		Domain: testProxyDomain, Port: DefaultProxyPort, CertFile: cert, KeyFile: key, WWW: www,
		Warn: func(message string) { warnings = append(warnings, message) },
	}
	if err := enableProxy(t.Context(), dir, opts, testProxySetup()); err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 2 || !strings.Contains(warnings[0], "set rsni=") || !strings.Contains(warnings[1], "old-phone") {
		t.Fatalf("expected the Stealth name notice and a warning naming the device without a password, got %v", warnings)
	}
	saved, err := ReadSettings(dir)
	want := httpsProxyListenerConfig{Domain: testProxyDomain, Port: DefaultProxyPort, CertMethod: "files", Cert: cert, Key: key, WWW: www}
	if err != nil || saved.HTTPSProxy == nil || *saved.HTTPSProxy ||
		saved.HTTPSProxyListener == nil || *saved.HTTPSProxyListener != want {
		t.Fatalf("shared proxy state failed to round-trip separately from the built-in flag: %v", err)
	}
	info, err := ProxyStatus(dir)
	if err != nil || info.Domain != testProxyDomain || info.Port != DefaultProxyPort || info.Source != "certificate files" {
		t.Fatalf("incorrect proxy status: %v", err)
	}
	paths, hints, err := Install(t.Context(), dir, "/tmp/pipe", Auto, nil)
	if err != nil || !strings.Contains(strings.Join(hints, "\n"), "Allow TCP 9443 for the HTTPS proxy") {
		t.Fatalf("missing shared proxy firewall hint: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "install", "pipe.nft"))
	if err != nil || !bytes.Contains(body, []byte("tcp dport 9443 accept")) {
		t.Fatalf("missing shared proxy firewall rule: %v", err)
	}
	for _, path := range paths {
		if filepath.Base(path) == "pipe-hop.service" {
			t.Fatal("generated a hopping service without a hop range")
		}
	}
	raw, _, proxy, err := AddWithProxy(dir, "new-phone", false)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := link.Parse(raw)
	if err != nil || profile.Host != "11.0.0.80" || profile.FastSNI != "fast.example" ||
		profile.StealthServerName() != testProxyDomain || profile.CDN != "static.website.example" {
		t.Fatalf("proxy setup altered the tier profile: %v", err)
	}
	u, err := url.Parse(proxy)
	if err != nil || u.Host != "gate.other.example:9443" || u.Scheme != "https" || u.User.Username() != "new-phone" {
		t.Fatalf("incorrect enrollment proxy endpoint: %v", err)
	}
	password, ok := u.User.Password()
	if !ok || password != link.Derive(profile.Seed).HTTPSProxyPassword {
		t.Fatal("shared proxy export did not use the enrolled device password")
	}
	if fromLink, ok := link.ProxyURL(profile); !ok || fromLink != proxy {
		t.Fatalf("link.ProxyURL(parsed) = (%q, %v), want (%q, true)", fromLink, ok, proxy)
	}
	if exported, err := ProxyExport(dir, "new-phone"); err != nil || exported != proxy {
		t.Fatalf("shared ProxyExport differs from enrollment proxy URL: %v", err)
	}
	if err := DisableProxy(dir); err != nil {
		t.Fatal(err)
	}
	if info, err := ProxyStatus(dir); err != nil || info.Domain != "" {
		t.Fatalf("proxy remains enabled after disable: %v", err)
	}
	if devices, err := ReadDevices(dir); err != nil || devices[1].HTTPSProxyPassword != password {
		t.Fatalf("disable changed device credentials: %v", err)
	}
	for _, path := range []string{cert, key} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("disable removed an operator-managed certificate file: %v", err)
		}
	}
}

func TestStandaloneProxyCommandsPreserveBuiltInProxy(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "origin.example", ""); err != nil {
		t.Fatal(err)
	}
	if err := EnableProxy(t.Context(), dir, ProxyEnableOptions{}); !errors.Is(err, errStandaloneProxy) {
		t.Fatalf("unexpected standalone enable result: %v", err)
	}
	if err := DisableProxy(dir); !errors.Is(err, errStandaloneProxy) {
		t.Fatalf("unexpected standalone disable result: %v", err)
	}
	status, err := ProxyStatus(dir)
	if err != nil || status.Source != "built-in" || status.Domain != "origin.example" || status.Port != 443 {
		t.Fatalf("standalone proxy status changed: %v", err)
	}
	raw, _, added, err := AddWithProxy(dir, "phone", false)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := link.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if fromLink, ok := link.ProxyURL(parsed); !ok || fromLink != added {
		t.Fatalf("standalone link.ProxyURL = (%q, %v), want (%q, true)", fromLink, ok, added)
	}
	if exported, err := ProxyExport(dir, "phone"); err != nil || exported != added {
		t.Fatalf("standalone export differs from the enrollment URL: %v", err)
	}
}

func TestProxyExportUsesStoredDevicePassword(t *testing.T) {
	dir := initProxyTestState(t)
	const name = "phone: $&'📱%"
	if _, _, err := Add(dir, name, false); err != nil {
		t.Fatal(err)
	}
	if url, err := ProxyExport(dir, name); url != "" || err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatal("export succeeded before the proxy was enabled")
	}
	cert, key := writeProxyTestPair(t, testProxyDomain, t.TempDir())
	if err := enableProxy(t.Context(), dir, ProxyEnableOptions{
		Domain: testProxyDomain, Port: DefaultProxyPort, CertFile: cert, KeyFile: key,
	}, testProxySetup()); err != nil {
		t.Fatal(err)
	}
	devices, err := ReadDevices(dir)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := ProxyExport(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(exported)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "gate.other.example:9443" || parsed.User.Username() != name ||
		strings.ContainsAny(exported, " $&'") {
		t.Fatalf("invalid or shell-unsafe export URL: %v", err)
	}
	if password, ok := parsed.User.Password(); !ok || password != devices[0].HTTPSProxyPassword {
		t.Fatal("export did not use the password stored before the proxy was enabled")
	}
	if url, err := ProxyExport(dir, "unknown"); url != "" || err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatal("export returned credentials for an unknown device")
	}
	devices[0].HTTPSProxyPassword = ""
	if err := writeJSON(dir, devicesFile, devices); err != nil {
		t.Fatal(err)
	}
	if url, err := ProxyExport(dir, name); url != "" || err == nil || !strings.Contains(err.Error(), "no HTTPS proxy password") {
		t.Fatal("export succeeded for a device without a stored proxy password")
	}
}

func TestProxyDomainAndPortCollisions(t *testing.T) {
	s, err := ReadSettings(initProxyTestState(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg := httpsProxyListenerConfig{Domain: testProxyDomain, Port: DefaultProxyPort, Cert: "/tmp/cert", Key: "/tmp/key"}
	for _, domain := range []string{"11.0.0.80", "gate.123", "K.example", "static.website.example", "x.Static.website.example", "website.example"} {
		bad := cfg
		bad.Domain = domain
		if err := s.validateProxyListener(bad); err == nil {
			t.Errorf("allowed proxy domain %s", domain)
		}
	}
	for _, port := range []uint16{0, 80, 443, 8443, 10001} {
		bad := cfg
		bad.Port = port
		if err := s.validateProxyListener(bad); err == nil {
			t.Errorf("allowed conflicting or reserved TCP port %d", port)
		}
	}
	for _, domain := range []string{testProxyDomain, s.FastSNI} {
		cfg.Domain = domain
		if err := s.validateProxyListener(cfg); err != nil {
			t.Errorf("refused permitted domain %s: %v", domain, err)
		}
	}
}

func TestProxyDNSWarnsForNAT(t *testing.T) {
	for _, test := range []struct{ name, ip, warning string }{
		{"DNS failure", "", "did not resolve"},
		{"NAT", "11.0.0.81", "NAT mapping"},
		{"private address", "10.0.0.1", "non-public"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setup := testProxySetup()
			setup.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				if test.ip == "" {
					return nil, errors.New("resolver unreachable")
				}
				return []netip.Addr{netip.MustParseAddr(test.ip)}, nil
			}
			var warnings []string
			if err := checkProxyDNS(t.Context(), testProxyDomain, setup, func(message string) {
				warnings = append(warnings, message)
			}); err != nil || !strings.Contains(strings.Join(warnings, "\n"), test.warning) {
				t.Fatalf("expected DNS warning %q without failure: %v", test.warning, err)
			}
		})
	}
}

func TestProxyDNSConfigurationKeepsAndRemovesPrivateCopies(t *testing.T) {
	dir := initProxyTestState(t)
	sources := t.TempDir()
	token := filepath.Join(sources, "cloudflare")
	twoKeys := filepath.Join(sources, "alidns")
	for path, data := range map[string]string{
		token:   "test-cloudflare-token\n",
		twoKeys: "access_key_id=test-ali-id\r\naccess_key_secret=test-ali-secret\r\n",
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	setup := testProxySetup()
	var issued []string
	setup.issue = func(ctx context.Context, state, domain string, provider certmagic.DNSProvider) error {
		if _, ok := ctx.Deadline(); !ok || state != dir || domain != testProxyDomain {
			t.Fatal("missing timeout or incorrect first-issuance configuration")
		}
		switch p := provider.(type) {
		case *cloudflare.Provider:
			if p.APIToken != "test-cloudflare-token" {
				t.Fatal("wrong Cloudflare provider credentials")
			}
			issued = append(issued, proxyDNSCloudflare)
		case *alidns.Provider:
			if p.AccessKeyID != "test-ali-id" || p.AccessKeySecret != "test-ali-secret" {
				t.Fatal("wrong Alibaba provider credentials")
			}
			issued = append(issued, proxyDNSAliDNS)
		default:
			t.Fatal("unexpected DNS provider")
		}
		return nil
	}
	cf := ProxyEnableOptions{Domain: testProxyDomain, Port: DefaultProxyPort, DNS: proxyDNSCloudflare, DNSTokenFile: token}
	ali := ProxyEnableOptions{Domain: testProxyDomain, Port: DefaultProxyPort, DNS: proxyDNSAliDNS, DNSKeyFile: twoKeys}
	enableAndReadSecret := func(opts ProxyEnableOptions) string {
		t.Helper()
		if err := enableProxy(t.Context(), dir, opts, setup); err != nil {
			t.Fatal(err)
		}
		saved, err := ReadSettings(dir)
		if err != nil || saved.HTTPSProxyListener == nil || saved.HTTPSProxyListener.DNS != opts.DNS {
			t.Fatalf("unexpected DNS listener settings: %v", err)
		}
		path := filepath.Join(dir, saved.HTTPSProxyListener.DNSSecret)
		info, err := os.Stat(path)
		if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Fatalf("DNS secret copy needs owner-only permissions: %v", err)
		}
		state, err := os.ReadFile(filepath.Join(dir, settingsFile))
		if err != nil || bytes.Contains(state, []byte("test-cloudflare-token")) || bytes.Contains(state, []byte("test-ali-secret")) {
			t.Fatalf("DNS secret appeared in server.json: %v", err)
		}
		return path
	}
	first := enableAndReadSecret(cf)
	second := enableAndReadSecret(ali)
	if _, err := os.Stat(first); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacing the DNS provider kept its previous secret copy: %v", err)
	}
	cert, key := writeProxyTestPair(t, testProxyDomain, t.TempDir())
	if err := enableProxy(t.Context(), dir, ProxyEnableOptions{
		Domain: testProxyDomain, Port: DefaultProxyPort, CertFile: cert, KeyFile: key,
	}, setup); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(second); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("switching to certificate files kept the DNS secret copy: %v", err)
	}
	third := enableAndReadSecret(ali)
	if err := DisableProxy(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(third); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disable kept the DNS secret copy: %v", err)
	}
	if strings.Join(issued, ",") != "cloudflare,alidns,alidns" {
		t.Fatalf("unexpected first issuances %v", issued)
	}
	for _, path := range []string{token, twoKeys} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("removed the operator's original DNS credentials: %v", err)
		}
	}
}

func TestProxyIssuanceFailureRetainsSettingsAndRedactsError(t *testing.T) {
	dir := initProxyTestState(t)
	cert, key := writeProxyTestPair(t, testProxyDomain, t.TempDir())
	setup := testProxySetup()
	baseline := ProxyEnableOptions{Domain: testProxyDomain, Port: DefaultProxyPort, CertFile: cert, KeyFile: key}
	if err := enableProxy(t.Context(), dir, baseline, setup); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(t.TempDir(), "token")
	const secret = "token-that-must-stay-private"
	if err := os.WriteFile(token, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	setup.issue = func(context.Context, string, string, certmagic.DNSProvider) error {
		return errors.New(secret)
	}
	err := enableProxy(t.Context(), dir, ProxyEnableOptions{
		Domain: testProxyDomain, Port: DefaultProxyPort + 1, DNS: proxyDNSCloudflare, DNSTokenFile: token,
	}, setup)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("initial issuance error was not reported without credentials")
	}
	info, err := ProxyStatus(dir)
	if err != nil || info.Port != DefaultProxyPort || info.Source != "certificate files" {
		t.Fatalf("failed issuance replaced the existing config: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(dir, proxyDNSSecretPrefix+"*"))
	if err != nil || len(files) != 0 {
		t.Fatalf("failed issuance left a DNS credential copy: %v", err)
	}
}
