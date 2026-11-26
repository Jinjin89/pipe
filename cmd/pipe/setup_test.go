// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"pipe/internal/server"
)

func setupConfigPath(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "setup.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSetupFlagsMatchJSON(t *testing.T) {
	config := setupConfigPath(t, `{
		"ip":"203.0.113.9", "sni":"gate.example", "cert":{"dns":"alidns","key_file":"/etc/ali.key"},
		"fast":{"port":14443,"hop":"25000-25003"}, "stealth":{"port":18443}, "proxy":{"port":19443},
		"rescue":{"sni":"cdn.example","port":2096,"cert":"/etc/origin.pem","key":"/etc/origin.key"},
		"device":"tablet"
	}`)
	jsonOpts, _, err := parseSetupOptions([]string{"--config", config, "--dir", "/etc/pipe"})
	if err != nil {
		t.Fatal(err)
	}
	flagOpts, _, err := parseSetupOptions([]string{
		"--yes", "--dir", "/etc/pipe", "--ip", "203.0.113.9", "--sni", "gate.example", "--dns", "alidns",
		"--dns-key-file", "/etc/ali.key", "--fast-port", "14443", "--fast-hop", "25000-25003",
		"--stealth-port", "18443", "--proxy-port", "19443", "--rescue-sni", "cdn.example",
		"--rescue-port", "2096", "--rescue-cert", "/etc/origin.pem", "--rescue-key", "/etc/origin.key", "--device", "tablet",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !jsonOpts.FromConfig || flagOpts.FromConfig {
		t.Fatal("invalid distinction between config omissions and omitted flags on reruns")
	}
	jsonOpts.FromConfig = false
	if !reflect.DeepEqual(jsonOpts, flagOpts) {
		t.Fatalf("JSON options %+v differ from flags %+v", jsonOpts, flagOpts)
	}
}

func TestSetupFlagsOverrideJSON(t *testing.T) {
	config := setupConfigPath(t, `{"ip":"203.0.113.9","sni":"gate.example","proxy":{"port":9943},
		"cert":{"dns":"cloudflare","token_file":"/etc/cf-token"},
		"rescue":{"sni":"cdn.example","port":2096,"cert":"/etc/origin.pem","key":"/etc/origin.key"}}`)
	opts, _, err := parseSetupOptions([]string{
		"--config", config, "--ip=", "--proxy-port=9443", "--cert=/other/cert.pem", "--key=/other/key.pem", "--rescue-sni=",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantCert := server.SetupCertificate{File: "/other/cert.pem", Key: "/other/key.pem"}
	if opts.Cert == nil || *opts.Cert != wantCert || opts.Rescue != nil || !opts.ClearRescue || opts.IP != "" || opts.Proxy.Port != 9443 {
		t.Fatalf("unexpected overrides: %+v (cert %+v)", opts, opts.Cert)
	}
	opts, _, err = parseSetupOptions([]string{"--config", config, "--dns", "alidns", "--dns-key-file", "ali.key", "--no-proxy"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.NoProxy || opts.Proxy != nil || *opts.Cert != (server.SetupCertificate{DNS: "alidns", KeyFile: "ali.key"}) {
		t.Fatalf("unexpected provider or proxy override: %+v (cert %+v)", opts, opts.Cert)
	}
}

func TestSetupOperatorIsCLIOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("setup operator resolution targets Linux")
	}
	account, err := user.Current()
	if err != nil || account.Username == "pipe" {
		t.Skip("requires a named account outside the Pipe service")
	}
	config := setupConfigPath(t, `{"sni":"gate.example"}`)
	opts, _, err := parseSetupOptions([]string{"--config", config, "--operator", account.Username})
	if err != nil || opts.Operator != account.Username || opts.SNI != "gate.example" {
		t.Fatalf("parse setup operator: options = %+v, error = %v", opts, err)
	}
	missingConfig := filepath.Join(t.TempDir(), "missing.json")
	_, _, err = parseSetupOptions([]string{"--config", missingConfig, "--operator", "pipe-test-unknown-operator"})
	var unknown user.UnknownUserError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected operator lookup to fail before config read, got %v", err)
	}
	if _, err := user.Lookup("pipe"); err == nil {
		_, _, err = parseSetupOptions([]string{"--config", missingConfig, "--operator", "pipe"})
		if err == nil || !strings.Contains(err.Error(), "cannot be user pipe") {
			t.Fatalf("expected service UID to be rejected before config read, got %v", err)
		}
	}
	config = setupConfigPath(t, `{"sni":"gate.example","operator":"root"}`)
	_, _, err = parseSetupOptions([]string{"--config", config})
	if err == nil || !strings.Contains(err.Error(), `unknown field "operator"`) {
		t.Fatalf("expected operator field in JSON to be rejected, got %v", err)
	}
}

func TestPrintSetupTemplateNoRoot(t *testing.T) {
	env := server.SetupEnv{
		GOOS: "darwin", EUID: 1000,
		Interfaces: func() ([]server.SetupInterface, error) {
			return []server.SetupInterface{{Name: "eth0", Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.42")}}}, nil
		},
		PortProbe: func(port int) (bool, bool) { return port == 80, false },
	}
	var out bytes.Buffer
	if err := printSetupTemplate(env, &out, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	var cfg server.SetupConfig
	if err := json.Unmarshal(out.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.IP != "203.0.113.42" || cfg.Proxy == nil || cfg.Proxy.Port != server.DefaultProxyPort || strings.Contains(out.String(), `"mode"`) {
		t.Fatalf("unexpected template:\n%s", &out)
	}
}

func TestSetupRejectsRetiredFlags(t *testing.T) {
	for _, arg := range []string{"--mode=shared", "--domain=gate.example", "--fast-sni=gate.example", "--reality-dest=self", "--web=/var/www"} {
		if _, _, err := parseSetupOptions([]string{arg}); err == nil {
			t.Errorf("accepted %s", arg)
		}
	}
}
