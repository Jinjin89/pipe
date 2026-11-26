// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"errors"
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
	for _, in := range serverConfig(s, nil, "::", serverListeners{masquerade: 12345}, nil)["inbounds"].([]engine.Object) {
		tags = append(tags, in["tag"].(string))
	}
	return tags
}

func TestSharedWithoutProxyKeepsStealthOff(t *testing.T) {
	_, s := initSharedState(t)
	if s.RealityDest != "" || s.RealitySNI != "" || s.RealityAddress != "" || s.realityTargetProblem() == nil {
		t.Fatalf("proxy target should remain unset: %+v", s)
	}
	if tags := stealthTags(s); !slices.Equal(tags, []string{"fast"}) {
		t.Fatalf("expected only Fast: %v", tags)
	}
	// --reality-dest self is accepted as a no-op. Any other value says what to do.
	if err := InitWithOptions(t.TempDir(), "11.0.0.80", "", InitOptions{Mode: Shared, FastSNI: "f.example", RealityDest: "SELF"}); err != nil {
		t.Fatal(err)
	}
	for _, dest := range []string{"www.example.edu:443", "auto"} {
		err := InitWithOptions(t.TempDir(), "11.0.0.80", "", InitOptions{Mode: Shared, FastSNI: "f.example", RealityDest: dest})
		if !errors.Is(err, errRealityNotSelf) {
			t.Errorf("%s: got %v", dest, err)
		}
	}
	must(t, InitWithOptions(t.TempDir(), "origin.example", "", InitOptions{Mode: Standalone, RealityDest: "self"}))
}

func TestStealthBorrowsTheProxySite(t *testing.T) {
	dir, _ := initSharedState(t)
	if err := enableTestProxy(t, dir, "Gate.Other.Example", 9443, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Install(t.Context(), dir, "/tmp/pipe", Auto, nil); err != nil {
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
		t.Fatalf("enabling the proxy must supply Stealth's cover: %v %+v", err, s)
	}
	inbounds := serverConfig(s, nil, "::", serverListeners{masquerade: 12345, borrowProxy: true}, nil)["inbounds"].([]engine.Object)
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
	// Stealth goes off with the HTTPS proxy.
	if err := DisableProxy(dir); err != nil {
		t.Fatal(err)
	}
	s, err = ReadSettings(dir)
	if err != nil || s.RealityDest != "" || s.realityTargetProblem() == nil || !slices.Equal(stealthTags(s), []string{"fast"}) {
		t.Fatalf("disabling the proxy must leave Fast running with Stealth off: %v %+v", err, s)
	}
}

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
		t.Fatalf("expected only Fast until Stealth's target is migrated: %v", tags)
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

func TestSetupSharedWithoutProxyKeepsStealthOff(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	h.busy[443] = true
	if err := h.run(setupConfigOptions(t, `{"sni":"pipe.example.com","device":"laptop"}`)); err != nil {
		t.Fatal(err)
	}
	s, err := ReadSettings(h.env.path(setupStateDir))
	must(t, err)
	if s.Mode != Shared || s.HTTPSProxyListener != nil || s.realityTargetProblem() == nil {
		t.Fatal("expected shared settings with Fast available and Stealth off")
	}
}

func TestSetupExistingSharedPreservesLegacyTargetOnUpgrade(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	state := filepath.Join(h.env.Root, setupStateDir)
	s := initSharedSetupState(t, state)
	s.RealityDest, s.RealityAddress = "legacy.example.com:443", "198.51.100.1:443"
	s.HTTPSProxyListener = &httpsProxyListenerConfig{Domain: "proxy.example.com", Port: 9443, CertMethod: "http"}
	must(t, writeJSON(state, settingsFile, s))
	saved, err := os.ReadFile(filepath.Join(state, settingsFile))
	must(t, err)
	must(t, h.run(SetupOptions{Yes: true}))
	for _, cmd := range h.argvs() {
		if strings.Contains(cmd, " server reality ") {
			t.Fatalf("setup silently migrated the REALITY target: %s", cmd)
		}
	}
	data, err := os.ReadFile(filepath.Join(state, settingsFile))
	must(t, err)
	if string(data) != string(saved) {
		t.Fatal("setup changed the saved state")
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
