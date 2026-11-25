// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSetupConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "setup.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// Every scenario template in templates/ must load and keep exactly the
// fields its situation needs.
func TestSetupTemplatesLoad(t *testing.T) {
	shared := SetupOptions{Mode: "shared", Domain: "203.0.113.7", FastHop: "20000-40000", Device: "phone"}
	full := shared
	full.RealityDest = "self"
	full.FastSNI, full.CDNDomain, full.ProxyDomain, full.ProxyCertMethod = "proxy.example.org", "static.example.com", "proxy.example.org", "auto"
	proxy := shared
	proxy.RealityDest = "self"
	proxy.FastSNI, proxy.ProxyDomain = "proxy.example.org", "proxy.example.org"
	with := func(o SetupOptions, f func(*SetupOptions)) SetupOptions { f(&o); return o }
	want := map[string]SetupOptions{
		"standalone.json":            {Mode: "standalone", Domain: "vpn.example.com", FastHop: "20000-40000", Device: "phone"},
		"standalone-cloudflare.json": {Mode: "standalone", Domain: "vpn.example.com", CDNDomain: "static.example.com", FastHop: "20000-40000", Device: "phone"},
		"shared-basic.json":          with(shared, func(o *SetupOptions) { o.FastSNI = "vpn.example.org" }),
		"shared-nginx-docker.json":   with(full, func(o *SetupOptions) { o.RescueListen = "172.17.0.1:18080" }),
		"shared-nginx-host.json":     with(full, func(o *SetupOptions) { o.RescueListen = "127.0.0.1:18080" }),
		"shared-proxy-alidns.json": with(proxy, func(o *SetupOptions) {
			o.ProxyCertMethod, o.DNS, o.DNSKeyFile = "dns", "alidns", "/root/alidns.key"
		}),
		"shared-proxy-cloudflare-dns.json": with(proxy, func(o *SetupOptions) {
			o.ProxyCertMethod, o.DNS, o.DNSTokenFile = "dns", "cloudflare", "/root/cloudflare.token"
		}),
		"shared-proxy-own-cert.json": with(proxy, func(o *SetupOptions) {
			o.ProxyCertMethod, o.Cert, o.Key = "files", "/path/to/fullchain.pem", "/path/to/privkey.pem"
		}),
	}
	files, err := filepath.Glob("../../templates/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(want) {
		t.Fatalf("templates/ has %d files, the test knows %d", len(files), len(want))
	}
	for _, path := range files {
		got, err := LoadSetupConfig(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if w, ok := want[filepath.Base(path)]; !ok || got != w {
			t.Fatalf("%s: got %+v want %+v", path, got, w)
		}
	}
}

func TestLoadSetupConfigUnknownKey(t *testing.T) {
	for _, key := range []string{"domian", "access_key_secret", "token"} {
		_, err := LoadSetupConfig(writeSetupConfig(t, `{"`+key+`":"x"}`))
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Fatalf("key %s: error %v", key, err)
		}
	}
}

func TestLoadSetupConfigComment(t *testing.T) {
	got, err := LoadSetupConfig(writeSetupConfig(t, `{"_comment":"note","_help":"h","mode":"shared"}`))
	if err != nil || got.Mode != "shared" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestLoadSetupConfigRelativePaths(t *testing.T) {
	p := writeSetupConfig(t, `{"mode":"shared","reality_dest":"self","proxy_domain":"p.example.org","proxy_cert_method":"files","cert":"c.pem","key":"/abs/k.pem"}`)
	dir := filepath.Dir(p)
	got, err := LoadSetupConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cert != filepath.Join(dir, "c.pem") || got.Key != "/abs/k.pem" {
		t.Fatalf("paths: %+v", got)
	}
	p = writeSetupConfig(t, `{"mode":"shared","proxy_domain":"p.example.org","proxy_cert_method":"dns","dns":"alidns","dns_key_file":"k/ali","dns_token_file":"t"}`)
	got, err = LoadSetupConfig(p)
	if err != nil || got.DNSKeyFile != filepath.Join(filepath.Dir(p), "k/ali") || got.DNSTokenFile != "" {
		t.Fatalf("dns: %+v %v", got, err)
	}
}

func TestLoadSetupConfigClearsUnused(t *testing.T) {
	load := func(body string) SetupOptions {
		t.Helper()
		got, err := LoadSetupConfig(writeSetupConfig(t, body))
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	const files = `"dns":"alidns","dns_key_file":"/k","dns_token_file":"/t","cert":"/c","key":"/k2","acme_listen":"10.0.0.1:1"`
	got := load(`{"mode":"shared","proxy_domain":"p.example.org","proxy_cert_method":"auto",` + files + `}`)
	if got.DNS != "" || got.DNSKeyFile != "" || got.DNSTokenFile != "" || got.Cert != "" || got.Key != "" || got.ACMEListen == "" {
		t.Fatalf("auto: %+v", got)
	}
	got = load(`{"mode":"shared","proxy_domain":"p.example.org","proxy_cert_method":"files",` + files + `}`)
	if got.Cert != "/c" || got.Key != "/k2" || got.DNS != "" || got.ACMEListen != "" {
		t.Fatalf("files: %+v", got)
	}
	got = load(`{"mode":"shared","proxy_domain":"p.example.org","proxy_cert_method":"dns",` + files + `}`)
	if got.DNS != "alidns" || got.DNSKeyFile != "/k" || got.DNSTokenFile != "" || got.Cert != "" {
		t.Fatalf("dns: %+v", got)
	}
	got = load(`{"mode":"shared","proxy_cert_method":"files","reality_dest":"self",` + files + `}`)
	if got.ProxyCertMethod != "" || got.DNS != "" || got.Cert != "" || got.Key != "" || got.ACMEListen != "" {
		t.Fatalf("no proxy domain: %+v", got)
	}
	got = load(`{"mode":"standalone","fast_sni":"a","rescue_listen":"b","reality_dest":"self","proxy_domain":"p.example.org","proxy_cert_method":"auto","cdn_domain":"c.example.com"}`)
	want := SetupOptions{Mode: "standalone", CDNDomain: "c.example.com"}
	if got != want {
		t.Fatalf("standalone: %+v", got)
	}
}

func TestLoadSetupConfigBadInput(t *testing.T) {
	for _, body := range []string{`{"mode":"shared"} {}`, `{"mode":"shared"} x`, `{} []`, `[]`, ``, `{"mode":1}`} {
		if _, err := LoadSetupConfig(writeSetupConfig(t, body)); err == nil {
			t.Fatalf("expected error for %q", body)
		}
	}
}

func TestLoadSetupConfigSizeLimit(t *testing.T) {
	body := `{"_comment":"` + strings.Repeat("a", maxSetupConfigBytes) + `"}`
	if _, err := LoadSetupConfig(writeSetupConfig(t, body)); err == nil {
		t.Fatal("expected size error")
	}
	if _, err := LoadSetupConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected missing file error")
	}
}

func TestSetupTemplateLoads(t *testing.T) {
	for _, layout := range []DeployMode{Standalone, Shared} {
		p := writeSetupConfig(t, string(SetupTemplate(layout, SetupDetection{})))
		got, err := LoadSetupConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		want := SetupOptions{Mode: string(layout), Domain: "vpn.example.com", CDNDomain: "static.example.com", FastHop: "20000-40000", Device: "phone"}
		if layout == Shared {
			want = SetupOptions{
				Mode: "shared", Domain: "203.0.113.7", FastSNI: "proxy.example.org",
				CDNDomain: "static.example.com", RescueListen: "172.17.0.1:18080",
				RealityDest: "self", FastHop: "20000-40000",
				ProxyDomain: "proxy.example.org", ProxyCertMethod: "auto", Device: "phone",
			}
		}
		if got != want {
			t.Fatalf("%s: got %+v want %+v", layout, got, want)
		}
	}
}

func TestSetupTemplateDetected(t *testing.T) {
	d := SetupDetection{
		PublicIPs:      []netip.Addr{netip.MustParseAddr("198.51.100.9")},
		Bridges:        []netip.Addr{netip.MustParseAddr("172.17.0.1"), netip.MustParseAddr("172.21.0.1")},
		NetworkBridges: []netip.Addr{netip.MustParseAddr("172.21.0.1")},
	}
	out := string(SetupTemplate(Shared, d))
	for _, want := range []string{`"domain": "198.51.100.9"`, `"rescue_listen": "172.21.0.1:18080"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	for _, layout := range []DeployMode{Standalone, Shared} {
		if strings.Contains(string(SetupTemplate(layout, d)), `"_`) {
			t.Fatalf("%s template has note keys", layout)
		}
	}
}

func TestSetupTemplateForNoRoot(t *testing.T) {
	env := SetupEnv{
		GOOS: "linux", EUID: 1000,
		Interfaces: func() ([]SetupInterface, error) { return nil, nil },
		PortProbe:  func(int) (bool, bool) { return true, true },
	}
	out, err := SetupTemplateFor(env, Auto)
	if err != nil || !strings.Contains(string(out), `"mode": "shared"`) {
		t.Fatalf("%v\n%s", err, out)
	}
	env.PortProbe = func(int) (bool, bool) { return false, true }
	out, err = SetupTemplateFor(env, "")
	if err != nil || !strings.Contains(string(out), `"mode": "standalone"`) {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := SetupTemplateFor(env, "bogus"); err == nil {
		t.Fatal("expected layout error")
	}
}

func TestLoadSetupConfigUnderscoreKeys(t *testing.T) {
	got, err := LoadSetupConfig(writeSetupConfig(t, `{"_a":1,"_b":{"x":[1]},"_c":null,"_d":true,"mode":"shared"}`))
	if err != nil || got.Mode != "shared" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := LoadSetupConfig(writeSetupConfig(t, `{"_a":1,"bad":2}`)); err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("error %v", err)
	}
}
