// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"pipe/templates"
)

func writeSetupConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "setup.json")
	must(t, os.WriteFile(path, []byte(body), 0600))
	return path
}

func setupConfigOptions(t *testing.T, body string) SetupOptions {
	t.Helper()
	opts, err := LoadSetupConfig(writeSetupConfig(t, body))
	must(t, err)
	return opts
}

func TestLoadSetupConfigSections(t *testing.T) {
	path := writeSetupConfig(t, `{
		"ip":"2001:db8::1", "sni":"gate.example.com",
		"cert":{"dns":"cloudflare","token_file":"keys/cf-token"},
		"fast":{"port":5353,"hop":"20000-40000"}, "stealth":{"port":8443},
		"proxy":{"port":9443},
		"rescue":{"sni":"cdn.other.net","port":2096,"cert":"origin.pem","key":"origin.key"},
		"device":"tablet"
	}`)
	got, err := LoadSetupConfig(path)
	must(t, err)
	dir := filepath.Dir(path)
	want := SetupOptions{FromConfig: true, Yes: true, SetupConfig: SetupConfig{
		IP: "2001:db8::1", SNI: "gate.example.com",
		Cert: &SetupCertificate{DNS: "cloudflare", TokenFile: filepath.Join(dir, "keys", "cf-token")},
		Fast: SetupFast{Port: 5353, Hop: "20000-40000"}, Stealth: SetupPort{Port: 8443},
		Proxy:  &SetupPort{Port: 9443},
		Rescue: &SetupRescue{SNI: "cdn.other.net", Port: 2096, Cert: filepath.Join(dir, "origin.pem"), Key: filepath.Join(dir, "origin.key")},
		Device: "tablet",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed setup differs from the expected options: %+v", got)
	}
}

func TestLoadSetupConfigCertificateChoices(t *testing.T) {
	for _, tc := range []struct {
		body, method string
	}{
		{`{"sni":"gate.example","proxy":{}}`, ""},
		{`{"sni":"gate.example","cert":{"dns":"cloudflare","token_file":"cloudflare.token"}}`, "dns"},
		{`{"sni":"gate.example","cert":{"dns":"alidns","key_file":"ali.key"}}`, "dns"},
		{`{"sni":"gate.example","cert":{"file":"cert.pem","key":"key.pem"}}`, "files"},
	} {
		opts := setupConfigOptions(t, tc.body)
		proxy, err := setupCertificateOptions(opts.Cert)
		must(t, err)
		if proxy.CertMethod != tc.method || opts.Rescue != nil {
			t.Fatalf("method %q and Rescue %v for %s", proxy.CertMethod, opts.Rescue, tc.body)
		}
	}
}

func TestLoadSetupConfigOldFormat(t *testing.T) {
	for _, body := range []string{
		`{"mode":"shared","domain":"gate.example"}`,
		`{"sni":"gate.example","fast_sni":"other.example"}`,
		`{"cdn_domain":"cdn.example"}`,
		`{"proxy_domain":"gate.example"}`,
		`{"proxy_cert_method":"nginx"}`,
		`{"acme_listen":"127.0.0.1:80"}`,
		`{"rescue_listen":"127.0.0.1:18080"}`,
		`{"reality_dest":"self"}`,
		`{"cert":"fullchain.pem"}`,
	} {
		_, err := LoadSetupConfig(writeSetupConfig(t, body))
		if err == nil || !strings.Contains(err.Error(), "this is the old setup format; run `pipe server setup --template > setup.json`") {
			t.Fatalf("old config %s got %v", body, err)
		}
	}
}

func TestLoadSetupConfigRejectsUnsupportedFieldsAndTypes(t *testing.T) {
	for _, body := range []string{
		`{"sni":"gate.example","web":"/var/www"}`,
		`{"sni":"gate.example","stealth":{"target":"elsewhere.example"}}`,
		`{"sni":"gate.example","proxy":{"sni":"elsewhere.example"}}`,
		`{"sni":"gate.example","proxy":{"web":"/var/www"}}`,
		`{"sni":"gate.example","cert":{"dns":"cloudflare","token":"inline-token"}}`,
		`{"fast":{"port":65536}}`, `{"proxy":{"port":"9443"}}`, `{"rescue":true}`,
		`null`, `[]`, `{} {}`, `{"sni":`,
	} {
		if _, err := LoadSetupConfig(writeSetupConfig(t, body)); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
}

func TestLoadSetupConfigSizeLimit(t *testing.T) {
	body := `{"sni":"` + strings.Repeat("x", maxSetupConfigBytes) + `"}`
	if _, err := LoadSetupConfig(writeSetupConfig(t, body)); err == nil {
		t.Fatal("accepted an oversized setup file")
	}
	if _, err := LoadSetupConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("accepted a missing setup file")
	}
}

func TestSetupTemplateRoundTrip(t *testing.T) {
	example := setupConfigOptions(t, string(templates.Setup))
	for _, tc := range []struct {
		name       string
		busy       int
		unknown    bool
		shared     bool
		expectsDNS bool
	}{
		{name: "free"},
		{name: "busy 80", busy: 80, shared: true, expectsDNS: true},
		{name: "busy 443", busy: 443, shared: true},
		{name: "unknown", unknown: true, shared: true, expectsDNS: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := SetupEnv{
				GOOS: "darwin", EUID: 1000,
				Interfaces: func() ([]SetupInterface, error) {
					return []SetupInterface{{Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("198.51.100.7")}}}, nil
				},
				PortProbe: func(port int) (bool, bool) { return port == tc.busy, tc.unknown },
			}
			data, err := SetupTemplateFor(env, t.TempDir())
			must(t, err)
			opts := setupConfigOptions(t, string(data))
			want := example.SetupConfig
			want.IP = "198.51.100.7"
			if !tc.shared {
				want.Stealth.Port = 443
				want.Proxy = &SetupPort{Port: 443}
				want.Rescue = &SetupRescue{SNI: example.Rescue.SNI, Port: 443}
			}
			if !tc.expectsDNS {
				want.Cert = nil
			}
			if !reflect.DeepEqual(opts.SetupConfig, want) {
				t.Fatalf("unexpected generated template:\n%s", data)
			}
		})
	}
	data, err := SetupTemplateFor(SetupEnv{PortProbe: func(int) (bool, bool) { return false, false }}, t.TempDir())
	must(t, err)
	if got := setupConfigOptions(t, string(data)).IP; got != "" {
		t.Fatalf("template should omit IP without a public address, got %q", got)
	}
}

func TestSetupTemplateUsesSelectedSavedSettings(t *testing.T) {
	for _, mode := range []DeployMode{Standalone, Shared} {
		t.Run(string(mode), func(t *testing.T) {
			h := newSetupHarness(t, "")
			h.env.PortProbe = func(int) (bool, bool) {
				t.Fatal("template probed live ports despite saved settings")
				return false, false
			}
			const dir = "/chosen-state"
			state := h.env.path(dir)
			must(t, InitWithOptions(state, "203.0.113.8", "", InitOptions{Mode: mode, FastSNI: "fast.example",
				Ports: Ports{Fast: 2443, Stealth: 7443}}))
			saved, err := ReadSettings(state)
			must(t, err)
			name := "fast.example"
			proxyPort := uint16(7443)
			if mode == Shared {
				name, proxyPort = "gate.example", 9643
				saved.HTTPSProxyListener = &httpsProxyListenerConfig{Domain: name, Port: proxyPort, CertMethod: "http"}
				saved.CDNDomain, saved.RescueListen = "cdn.example", "127.0.0.1:18080"
				must(t, writeJSON(state, settingsFile, saved))
			}
			data, err := SetupTemplateFor(h.env, dir)
			must(t, err)
			cfg := setupConfigOptions(t, string(data))
			if cfg.IP != "203.0.113.8" || cfg.SNI != name || cfg.Stealth.Port != 7443 ||
				cfg.Proxy == nil || cfg.Proxy.Port != proxyPort || cfg.Fast != (SetupFast{}) {
				t.Fatalf("template did not use saved settings:\n%s", data)
			}
			if mode == Shared && (cfg.Rescue == nil || cfg.Rescue.SNI != "cdn.example" || cfg.Rescue.Port != DefaultRescuePort || cfg.Rescue.Cert == "") {
				t.Fatalf("shared migration fields missing:\n%s", data)
			}
		})
	}
}

func TestSetupTemplateMigrationRequiresAuthorizedHopping(t *testing.T) {
	saved := SetupFast{Port: 2443, Hop: "25000-25010"}
	for _, tc := range []struct {
		name       string
		installed  SetupFast
		writable   bool
		authorized bool
	}{
		{name: "unit absent"},
		{name: "target differs", installed: SetupFast{Port: 2444, Hop: saved.Hop}},
		{name: "range differs", installed: SetupFast{Port: saved.Port, Hop: "26000-26010"}},
		{name: "writable unit", installed: saved, writable: true},
		{name: "authorized", installed: saved, authorized: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.installed.Hop != "" && os.Geteuid() != 0 {
				t.Skip("requires a root-owned fixture")
			}
			h := newSetupHarness(t, "")
			h.exists = true
			must(t, InitWithOptions(h.env.path(setupStateDir), "origin.example", "", InitOptions{
				Mode: Standalone, FastHop: saved.Hop, Ports: Ports{Fast: saved.Port},
			}))
			for _, file := range systemInstallFiles(setupStateDir, setupBinary, tc.installed) {
				if file.name != hopServiceUnit {
					continue
				}
				dir := h.env.path(setupUnitDir)
				must(t, os.MkdirAll(dir, 0755))
				path := filepath.Join(dir, file.name)
				must(t, os.WriteFile(path, []byte(file.contents), file.mode))
				if tc.writable {
					must(t, os.Chmod(path, 0664))
				}
			}
			data, err := SetupTemplateFor(h.env, "")
			must(t, err)
			opts := setupConfigOptions(t, string(data))
			notes := strings.Count(h.out.String(), "Add the intended fast.hop and fast.port")
			if tc.authorized {
				if opts.Fast != tc.installed || notes != 0 {
					t.Fatalf("authorized settings missing or produced a note: %s%s", data, h.out.String())
				}
				must(t, h.run(opts))
				return
			}
			if opts.Fast != (SetupFast{}) || notes != 1 {
				t.Fatalf("template must omit unconfirmed hopping inputs and print one note: %s%s", data, h.out.String())
			}
			if err := h.run(opts); err == nil || len(h.cmds) != 0 {
				t.Fatalf("applying the generated config did not refuse the unconfirmed settings: %v, commands %v", err, h.argvs())
			}
		})
	}
}

func TestSetupPrivilegedInputsRequireTrustedPath(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("Linux root file validation")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "operator's $dir")
	must(t, os.Mkdir(dir, 0755))
	dst := filepath.Join(dir, "setup.json")
	must(t, os.WriteFile(dst, []byte(`{"sni":"origin.example"}`), 0600))
	if _, err := LoadSetupConfig(dst); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	must(t, os.Symlink(dir, alias))
	if _, err := LoadSetupConfig(filepath.Join(alias, "setup.json")); err == nil {
		t.Fatal("setup followed a symlink parent")
	}
	must(t, os.Chmod(dir, 0775))
	commandPath := "'" + strings.ReplaceAll(parent, "'", `'\''`) + `/operator'\''s $dir'`
	want := fmt.Sprintf("unsafe setup path %q: %q is group- or world-writable; run: chmod go-w %s", dst, dir, commandPath)
	if _, err := LoadSetupConfig(dst); err == nil || err.Error() != want {
		t.Fatalf("writable config parent error = %v, want %q", err, want)
	}
	if _, err := readSetupOperatorFile(dst, 990, trustedSetupOperator(), maxSetupConfigBytes, true); err == nil {
		t.Fatal("setup staged a credential with a writable parent")
	}
	must(t, os.Chmod(dir, 0755))
	must(t, os.Chown(dir, 990, 990))
	want = fmt.Sprintf("unsafe setup path %q: %q must not be owned by user pipe", dst, dir)
	if _, err := readSetupOperatorFile(dst, 990, trustedSetupOperator(), maxSetupConfigBytes, true); err == nil || err.Error() != want {
		t.Fatalf("service-owned config parent error = %v, want %q", err, want)
	}
}

func TestSetupRefusesUnrelatedInputOwner(t *testing.T) {
	if os.Geteuid() != 0 || runtime.GOOS != "linux" {
		t.Skip("fixture needs Linux root to set an unrelated owner")
	}
	path := filepath.Join(t.TempDir(), "settings.json")
	must(t, os.WriteFile(path, []byte(`{"sni":"fixture.example"}`), 0600))
	const operator = 65530
	must(t, os.Chown(path, operator, operator))
	t.Setenv("SUDO_UID", "0")
	if _, err := LoadSetupConfig(path); err == nil {
		t.Fatal("accepted input owned by an unrelated account")
	}
	t.Setenv("SUDO_UID", "65530")
	if _, err := LoadSetupConfig(path); err != nil {
		t.Fatalf("trusted operator input: %v", err)
	}
}

const (
	setupOperator0711Path    = "PIPE_TEST_SETUP_OPERATOR_0711_PATH"
	setupOperator0711JSON    = `{"sni":"fixture.example"}`
	setupOperator0711PipeUID = 990
)

func TestSetupOperatorTraversesSearchOnlyDirectory(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires Linux root to set fixture ownership and child credentials")
	}
	const operatorUID, operatorGID = 65534, 65534
	chown := func(path string, uid, gid int) {
		t.Helper()
		err := os.Chown(path, uid, gid)
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EPERM) {
			t.Skipf("cannot set fixture ownership to UID %d and GID %d in this environment: %v", uid, gid, err)
		}
		must(t, err)
	}
	parent, err := os.MkdirTemp("/tmp", "pipe-setup-0711-")
	must(t, err)
	t.Cleanup(func() { must(t, os.RemoveAll(parent)) })
	must(t, os.Chmod(parent, 0711))
	dir := filepath.Join(parent, "operator")
	must(t, os.Mkdir(dir, 0755))
	chown(dir, operatorUID, operatorGID)
	path := filepath.Join(dir, "setup.json")
	must(t, os.WriteFile(path, []byte(setupOperator0711JSON), 0600))
	chown(path, operatorUID, operatorGID)

	exe, err := os.Executable()
	must(t, err)
	image, err := os.Open(exe)
	must(t, err)
	defer image.Close()
	read := func(path, wantError string) {
		t.Helper()
		// The inherited descriptor lets the child execute the test binary
		// even when the Go build directory is private to root.
		cmd := exec.CommandContext(t.Context(), "/proc/self/fd/3", "-test.run=^TestSetupOperator0711Helper$")
		cmd.ExtraFiles = []*os.File{image}
		cmd.Env = []string{setupOperator0711Path + "=" + path}
		must(t, dropCredentials(cmd, operatorUID, operatorGID))
		out, err := cmd.CombinedOutput()
		if wantError == "" {
			if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EPERM) {
				t.Skipf("cannot start the fixture with UID %d and GID %d in this environment: %v", operatorUID, operatorGID, err)
			}
			if err != nil {
				t.Fatalf("operator read through 0711 failed: %v\n%s", err, out)
			}
		} else if err == nil || !strings.Contains(string(out), wantError) {
			t.Fatalf("read %q = %v, want %q\n%s", path, err, wantError, out)
		}
	}

	read(path, "")
	alias := filepath.Join(parent, "alias")
	must(t, os.Symlink(dir, alias))
	read(filepath.Join(alias, "setup.json"), "without following links")
	must(t, os.Chmod(parent, 0731))
	read(path, "is group- or world-writable")
	must(t, os.Chmod(parent, 0711))
	chown(parent, setupOperator0711PipeUID, -1)
	read(path, "must not be owned by user pipe")
}

func TestSetupOperator0711Helper(t *testing.T) {
	path := os.Getenv(setupOperator0711Path)
	if path == "" {
		t.Skip("runs in the credential-dropped test subprocess")
	}
	var out strings.Builder
	must(t, ReadSetupOperatorInput(path, strconv.Itoa(setupOperator0711PipeUID), "4096", "true", &out))
	if got := out.String(); got != setupOperator0711JSON {
		t.Fatalf("setup input = %q, want %q", got, setupOperator0711JSON)
	}
}
