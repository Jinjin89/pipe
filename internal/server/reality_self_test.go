// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pipe/internal/engine"
	"pipe/internal/link"
)

func initSharedState(t *testing.T) (string, Settings) {
	t.Helper()
	dir := t.TempDir()
	if err := InitWithOptions(dir, "11.0.0.80", "", InitOptions{Mode: Shared, FastSNI: "fast.example"}); err != nil {
		t.Fatal(err)
	}
	settings, err := ReadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, settings
}

// enableTestProxy turns the HTTPS proxy on for domain and port.
func enableTestProxy(t *testing.T, dir, domain string, port uint16, warn func(string)) error {
	t.Helper()
	cert, key := writeProxyTestPair(t, domain, t.TempDir())
	return enableProxy(t.Context(), dir, ProxyEnableOptions{Domain: domain, Port: port, CertFile: cert, KeyFile: key, Warn: warn}, testProxySetup())
}

func stealthTags(s Settings) []string {
	var tags []string
	for _, in := range serverConfig(s, nil, "::", 12345, 0, nil)["inbounds"].([]engine.Object) {
		tags = append(tags, in["tag"].(string))
	}
	return tags
}

func TestSharedWithoutProxyHasNoStealth(t *testing.T) {
	dir, s := initSharedState(t)
	if s.RealityDest != "" || s.RealitySNI != "" || s.RealityAddress != "" || s.realityTargetProblem() == nil {
		t.Fatalf("no proxy, no Stealth: %+v", s)
	}
	if tags := stealthTags(s); !slices.Equal(tags, []string{"fast"}) {
		t.Fatalf("only Fast may run: %v", tags)
	}
	var warned []string
	if _, _, err := Install(t.Context(), dir, "/tmp/pipe", Auto, func(m string) { warned = append(warned, m) }); err != nil || len(warned) != 1 {
		t.Fatalf("install must go on and say Stealth is off: %v %v", err, warned)
	}
	// --reality-dest self is accepted as a no-op. Any other value says what to do.
	if err := InitWithOptions(t.TempDir(), "11.0.0.80", "", InitOptions{Mode: Shared, FastSNI: "f.example", RealityDest: "SELF"}); err != nil {
		t.Fatal(err)
	}
	for _, dest := range []string{"www.example.edu:443", "auto"} {
		err := InitWithOptions(t.TempDir(), "11.0.0.80", "", InitOptions{Mode: Shared, FastSNI: "f.example", RealityDest: dest})
		want := "REALITY now always borrows your own HTTPS proxy site: use reality_dest self (it needs proxy_domain)."
		if err == nil || !strings.Contains(err.Error(), strings.TrimSuffix(want, ".")) {
			t.Errorf("%s: got %v", dest, err)
		}
	}
	if err := InitWithOptions(t.TempDir(), "origin.example", "", InitOptions{Mode: Standalone, RealityDest: "self"}); err == nil {
		t.Error("standalone has no reality_dest")
	}
}

func TestStealthBorrowsTheProxySite(t *testing.T) {
	dir, _ := initSharedState(t)
	if err := enableTestProxy(t, dir, "Gate.Other.Example", 9443, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Install(t.Context(), dir, "/tmp/pipe", Auto, func(m string) { t.Fatal(m) }); err != nil {
		t.Fatal(err)
	}
	raw, _, _, err := AddWithProxy(dir, "phone", false)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := link.Parse(raw)
	if err != nil || profile.StealthServerName() != "gate.other.example" {
		t.Fatalf("link must carry the proxy domain as rsni: %v %q", err, profile.StealthServerName())
	}
	s, err := ReadSettings(dir)
	if err != nil || s.RealityDest != "self" || s.RealityAddress != "127.0.0.1:9443" || s.realityTargetProblem() != nil {
		t.Fatalf("enabling the proxy must turn Stealth on: %v %+v", err, s)
	}
	inbounds := serverConfig(s, nil, "::", 12345, 0, nil)["inbounds"].([]engine.Object)
	if len(inbounds) != 2 || inbounds[1]["tag"] != "stealth" || inbounds[1]["listen"] != "::" || inbounds[1]["listen_port"] != uint16(8443) {
		t.Fatalf("one public Stealth inbound and no front door: %v", inbounds)
	}
	handshake := inbounds[1]["tls"].(engine.Object)["reality"].(engine.Object)["handshake"].(engine.Object)
	if handshake["server"] != "127.0.0.1" || handshake["server_port"] != uint16(9443) {
		t.Fatalf("handshake must be the local proxy: %v", handshake)
	}
	// A new proxy domain or port moves Stealth with it.
	var warnings []string
	if err := enableTestProxy(t, dir, "gate2.other.example", 9555, func(m string) { warnings = append(warnings, m) }); err != nil {
		t.Fatal(err)
	}
	s, err = ReadSettings(dir)
	if err != nil || s.RealitySNI != "gate2.other.example" || s.RealityAddress != "127.0.0.1:9555" ||
		len(warnings) != 1 || !strings.Contains(warnings[0], "set rsni=") {
		t.Fatalf("proxy change did not keep REALITY in sync: %v %+v %v", err, s, warnings)
	}
	// Without the proxy there is no Stealth.
	if err := DisableProxy(dir); err != nil {
		t.Fatal(err)
	}
	s, err = ReadSettings(dir)
	if err != nil || s.RealityDest != "" || s.realityTargetProblem() == nil || !slices.Equal(stealthTags(s), []string{"fast"}) {
		t.Fatalf("disabling the proxy must turn Stealth off: %v %+v", err, s)
	}
}

// An older server saved a third-party REALITY target. It must still start, with
// Stealth off, until "pipe server reality" moves it to the proxy site.
func TestOldThirdPartyTargetKeepsStealthOffUntilMigrated(t *testing.T) {
	dir, s := initSharedState(t)
	if err := enableTestProxy(t, dir, "gate.other.example", 9443, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := AddWithProxy(dir, "phone", false); err != nil {
		t.Fatal(err)
	}
	old, _ := ReadSettings(dir)
	old.RealityDest, old.RealitySNI, old.RealityAddress = "www.example.edu:443", "www.example.edu", "11.0.0.81:443"
	old.Ports.RealityOrigin = 10443
	if err := writeJSON(dir, settingsFile, old); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadSettings(dir)
	if err != nil {
		t.Fatalf("an old state must still load: %v", err)
	}
	if problem := loaded.realityTargetProblem(); problem == nil || !strings.Contains(problem.Error(), "pipe server reality") {
		t.Fatalf("got %v", problem)
	}
	if tags := stealthTags(loaded); !slices.Equal(tags, []string{"fast"}) {
		t.Fatalf("no Stealth and no relay: %v", tags)
	}
	// Adding a device or changing the proxy must not migrate behind the operator's back.
	if err := enableTestProxy(t, dir, "gate.other.example", 9444, nil); err != nil {
		t.Fatal(err)
	}
	if again, _ := ReadSettings(dir); again.RealityDest != "www.example.edu:443" {
		t.Fatalf("proxy change moved an old target: %+v", again)
	}
	devices, _ := os.ReadFile(filepath.Join(dir, devicesFile))
	changed, err := SetRealityTarget(dir)
	if err != nil || !changed {
		t.Fatalf("migrate: %v %v", changed, err)
	}
	now, err := ReadSettings(dir)
	if err != nil || now.RealityDest != "self" || now.RealitySNI != "gate.other.example" || now.RealityAddress != "127.0.0.1:9444" ||
		now.Ports.RealityOrigin != 0 || now.realityTargetProblem() != nil {
		t.Fatalf("target not moved: %v %+v", err, now)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, devicesFile)); string(got) != string(devices) ||
		now.RealityPrivateKey != s.RealityPrivateKey || now.WSPath != s.WSPath || !slices.Equal(now.FastPrivateKey, s.FastPrivateKey) {
		t.Fatal("migration changed keys or devices")
	}
	if changed, err := SetRealityTarget(dir); err != nil || changed {
		t.Fatalf("a second run must be a no-op: %v %v", changed, err)
	}
	// Without a proxy there is nothing to move to.
	other, _ := initSharedState(t)
	if _, err := SetRealityTarget(other); !errors.Is(err, errSelfNeedsProxy) {
		t.Fatalf("got %v", err)
	}
}

func TestSetupSelfFresh(t *testing.T) {
	// reality_dest self is optional: proxy_domain alone gives Stealth.
	for _, dest := range []string{"self", ""} {
		h := newSetupHarness(t, "")
		h.exists = true
		h.busy[443] = true
		err := h.run(SetupOptions{Yes: true, Mode: "shared", Domain: "pipe.example.com", RealityDest: dest,
			ProxyDomain: "proxy.example.com", ProxyCertMethod: "http", Device: "laptop"})
		if err != nil {
			t.Fatal(err)
		}
		got := h.argvs()
		if got[0] != "pipe: "+setupBinary+" server init --dir /var/lib/pipe --mode shared --domain pipe.example.com" ||
			!strings.Contains(got[1], "server proxy enable") {
			t.Fatalf("unexpected commands %v", got)
		}
	}
	h := newSetupHarness(t, "")
	h.exists = true
	err := h.run(SetupOptions{Yes: true, Mode: "shared", Domain: "pipe.example.com", RealityDest: "self"})
	if err == nil || !strings.Contains(err.Error(), "needs the HTTPS proxy on its own domain (proxy_domain)") {
		t.Fatalf("got %v", err)
	}
	h = newSetupHarness(t, "")
	h.exists = true
	err = h.run(SetupOptions{Yes: true, Mode: "shared", Domain: "pipe.example.com", RealityDest: "www.example.edu:443", ProxyDomain: "p.example.com"})
	if err == nil || !strings.Contains(err.Error(), "use reality_dest self") {
		t.Fatalf("got %v", err)
	}
}

func TestSetupSharedWithoutProxySaysNoStealth(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	h.busy[443] = true
	if err := h.run(SetupOptions{Yes: true, Mode: "shared", Domain: "pipe.example.com", Device: "laptop"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.out.String(), "Stealth is not set up") {
		t.Fatalf("setup must say there is no Stealth:\n%s", h.out.String())
	}
}

func TestSetupExistingSharedMigratesOnlyWhenAsked(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	state := filepath.Join(h.env.Root, setupStateDir)
	if err := os.MkdirAll(state, 0755); err != nil {
		t.Fatal(err)
	}
	saved := `{"mode":"shared","domain":"example.com","reality_dest":"legacy.example.com:443","reality_address":"198.51.100.1:443",
		"https_proxy_listener":{"domain":"proxy.example.com","port":9443}}`
	if err := os.WriteFile(filepath.Join(state, settingsFile), []byte(saved), 0600); err != nil {
		t.Fatal(err)
	}
	// Not asked: links keep working as they are, and the operator is told.
	if err := h.run(SetupOptions{Yes: true}); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(h.argvs(), func(a string) bool { return strings.Contains(a, " reality ") }) || !strings.Contains(h.out.String(), "Stealth is off") {
		t.Fatalf("setup moved the target unasked: %v\n%s", h.argvs(), h.out.String())
	}
	h.cmds = nil
	if err := h.run(SetupOptions{Yes: true, RealityDest: "self", ProxyDomain: "proxy.example.com"}); err != nil {
		t.Fatal(err)
	}
	d := "/var/lib/pipe"
	got := h.argvs()
	if len(got) < 2 || got[0] != "pipe: "+setupBinary+" server reality --dir "+d || got[1] != "pipe: "+setupBinary+" server install --dir "+d {
		t.Fatalf("unexpected commands %v", got)
	}
	if !strings.Contains(h.out.String(), "rsni=<proxy domain>") {
		t.Fatalf("missing device link notice:\n%s", h.out.String())
	}
	// Already on self: nothing moves. self without any proxy is an error.
	_ = os.WriteFile(filepath.Join(state, settingsFile), []byte(`{"mode":"shared","domain":"example.com","reality_dest":"self","reality_address":"127.0.0.1:9443","https_proxy_listener":{"domain":"proxy.example.com","port":9443}}`), 0600)
	h.cmds = nil
	if err := h.run(SetupOptions{Yes: true, RealityDest: "self"}); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(h.argvs(), func(a string) bool { return strings.Contains(a, " reality ") }) {
		t.Fatalf("moved a good target: %v", h.argvs())
	}
	_ = os.WriteFile(filepath.Join(state, settingsFile), []byte(`{"mode":"shared","domain":"example.com","reality_dest":"a.example:443"}`), 0600)
	if err := h.run(SetupOptions{Yes: true, RealityDest: "self"}); !errors.Is(err, errSelfNeedsProxy) {
		t.Fatalf("got %v", err)
	}
}

func TestWebUpstreamWarning(t *testing.T) {
	for _, upstream := range []string{"", "http://127.0.0.1:8080", "http://localhost", "https://10.1.2.3/x", "http://[::1]:80"} {
		if w := webUpstreamWarning(upstream); w != "" {
			t.Errorf("%q: %s", upstream, w)
		}
	}
	for _, upstream := range []string{"https://www.example.org", "http://203.0.113.9"} {
		if w := webUpstreamWarning(upstream); !strings.Contains(w, "bandwidth") {
			t.Errorf("%q: no warning", upstream)
		}
	}
}

func TestSelfRealityNeedsOwnedProxySocket(t *testing.T) {
	dir, _ := initSharedState(t)
	cert, key := writeProxyTestPair(t, "gate.other.example", t.TempDir())
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	port := uint16(held.Addr().(*net.TCPAddr).Port)
	cfg := httpsProxyListenerConfig{Domain: "gate.other.example", Port: port, CertMethod: "files", Cert: cert, Key: key}
	warn := func(string) {}
	proxy := newHTTPSProxy(http.NotFoundHandler(), nil)
	if stop, err := startSharedHTTPSProxy(t.Context(), dir, "127.0.0.1", cfg, proxy, io.Discard, warn); err == nil {
		stop()
		t.Fatal("a port held by another process must fail the proxy start")
	}
	// The run path records the failure; the config then has no Stealth inbound.
	s, _ := ReadSettings(dir)
	s.realityBlocked = "the HTTPS proxy that Stealth borrows did not start"
	var tags []string
	for _, in := range serverConfig(s, nil, "::", 12345, 0, nil)["inbounds"].([]engine.Object) {
		tags = append(tags, in["tag"].(string))
	}
	if !slices.Equal(tags, []string{"fast"}) {
		t.Fatalf("Stealth must be off: %v", tags)
	}
	// A free port starts, and the listener is ours.
	held.Close()
	stop, err := startSharedHTTPSProxy(t.Context(), dir, "127.0.0.1", cfg, proxy, io.Discard, warn)
	if err != nil {
		t.Fatal(err)
	}
	stop()
}
