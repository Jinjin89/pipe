// SPDX-License-Identifier: GPL-3.0-or-later
//go:build with_quic && with_utls

package server

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pipe/internal/engine"
)

func TestServerEngineOptions(t *testing.T) {
	for _, cdn := range []string{"", "cdn.example.test"} {
		dir := t.TempDir()
		if err := Init(dir, "origin.example.test", cdn); err != nil {
			t.Fatal(err)
		}
		settings, err := ReadSettings(dir)
		if err != nil {
			t.Fatal(err)
		}
		settings.Ports = TestPorts()
		cert, err := testCertificate(filepath.Join(dir, "ca"), settings)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range settings.names() {
			if err := cert.Leaf.VerifyHostname(name); err != nil {
				t.Fatal(err)
			}
		}
		for _, device := range []bool{false, true} {
			if device {
				if _, _, err := Add(dir, "phone", true); err != nil {
					t.Fatal(err)
				}
			}
			devices, err := ReadDevices(dir)
			if err != nil {
				t.Fatal(err)
			}
			var testHosts map[string]netip.Addr
			if device {
				testHosts = map[string]netip.Addr{"other.split.test": netip.MustParseAddr("11.0.0.80")}
			}
			instance, err := engine.New(t.Context(), engine.Options{
				Config:         serverConfig(settings, devices, "127.0.0.1", 12345, 12346, testHosts),
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil },
				Server:         true, DeviceIDs: deviceIDs(devices),
			})
			if err != nil {
				t.Fatalf("sing-box rejected server options (cdn %q, device %t): %v", cdn, device, err)
			}
			instance.Close()
		}
	}
}

func TestServerEngineMixedAddressHostUsesGuardedDirect(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "origin.example.test", ""); err != nil {
		t.Fatal(err)
	}
	settings, err := ReadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	settings.Ports = TestPorts()
	cert, err := testCertificate(filepath.Join(dir, "ca"), settings)
	if err != nil {
		t.Fatal(err)
	}

	const host = "mixed.split.test"
	private := netip.MustParseAddr("10.0.0.1")
	public := netip.MustParseAddr("8.8.8.8")
	config := serverConfig(settings, nil, "127.0.0.1", 12345, 12346, map[string]netip.Addr{host: private})
	dns := config["dns"].(engine.Object)
	var foundTestHosts bool
	for _, server := range dns["servers"].([]engine.Object) {
		if server["tag"] == engine.TestHostsTag {
			server["predefined"] = map[string][]netip.Addr{host: {private, public}}
			foundTestHosts = true
		}
	}
	if !foundTestHosts {
		t.Fatal("server config did not include the test host resolver")
	}
	route := config["route"].(engine.Object)
	if route["final"] != "direct" {
		t.Fatalf("mixed host final route is %v, want direct", route["final"])
	}
	for _, rule := range route["rules"].([]engine.Object) {
		if rule["ip_is_private"] == true && rule["action"] == "reject" {
			t.Fatal("server rejects a mixed answer before the guarded direct outbound")
		}
	}

	instance, err := engine.New(t.Context(), engine.Options{
		Config: config, Server: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil },
	})
	if err != nil {
		t.Fatalf("sing-box rejected mixed test-host answers: %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedEngineOptions(t *testing.T) {
	dir := t.TempDir()
	if err := InitWithOptions(dir, "direct.example", "static.example", InitOptions{
		Mode: Shared, RescueListen: "127.0.0.1:10001",
	}); err != nil {
		t.Fatal(err)
	}
	if err := enableTestProxy(t, dir, "gate.other.example", 9443, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Add(dir, "phone", false); err != nil {
		t.Fatal(err)
	}
	settings, err := ReadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	devices, err := ReadDevices(dir)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := settings.fastKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := engine.New(t.Context(), engine.Options{
		Config: serverConfig(settings, devices, "127.0.0.1", 12345, 0, nil),
		Server: true, DeviceIDs: deviceIDs(devices),
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return certificate, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
}

func TestServerTestHostsRequireCA(t *testing.T) {
	err := Run(t.Context(), RunOptions{
		TestHosts: map[string]netip.Addr{"other.split.test": netip.MustParseAddr("11.0.0.80")},
	})
	if err == nil || err.Error() != "--test-hosts requires --test-ca" {
		t.Fatalf("Run without test CA returned %v", err)
	}
}

func TestLocalTestCA(t *testing.T) {
	dir := t.TempDir()
	settings := Settings{Domain: "origin.example.test", CDNDomain: "cdn.example.test"}
	initial, err := testCertificate(dir, settings)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, TestRootFile))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		t.Fatal("invalid test CA PEM")
	}
	renewed, err := testCertificate(dir, settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range []*tls.Certificate{initial, renewed} {
		for _, name := range settings.names() {
			if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestDecoyAndProbeHandler(t *testing.T) {
	settings := Settings{RealityPrivateKey: testCoverKey(1)}
	page, err := generateCoverSite(settings.RealityPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	decoy, err := makeDecoy(settings, RunOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		handler http.Handler
		url     string
		status  int
		body    string
	}{
		{decoy, "https://origin.example.test/", 200, string(page)},
		{http.HandlerFunc(serveProbe), "http://" + engine.ProbeDomain + engine.ProbePath, 200, "OK"},
		{http.HandlerFunc(serveProbe), "http://" + engine.ProbeDomain + engine.ProbePath + "?burst=1", 200, strings.Repeat("0", engine.ProbeBurstSize)},
		{decoy, "https://" + engine.ProbeDomain + engine.ProbePath, 404, "404"},
		{decoy, "http://" + engine.ProbeDomain + engine.ProbePath, 404, "404"},
	} {
		recorder := httptest.NewRecorder()
		test.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.url, nil))
		if recorder.Code != test.status || !strings.Contains(recorder.Body.String(), test.body) || recorder.Header().Get("Server") != "" {
			t.Fatalf("unexpected response for %s: HTTP %d", test.url, recorder.Code)
		}
	}
}

// Shared Stealth borrows our own HTTPS proxy site, reached where it listens.
func TestSharedStealthHandshakeUsesProxyListenAddress(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "origin.example.test", ""); err != nil {
		t.Fatal(err)
	}
	settings, err := ReadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	settings.Mode = Shared
	settings.HTTPSProxyListener = &httpsProxyListenerConfig{Domain: "gate.example.org", Port: 9443}
	settings.borrowProxySite()
	for listen, want := range map[string]string{"::": "127.0.0.1", "0.0.0.0": "127.0.0.1", "10.83.0.1": "10.83.0.1"} {
		config := serverConfig(settings, nil, listen, 12345, 12346, nil)
		var handshake engine.Object
		for _, inbound := range config["inbounds"].([]engine.Object) {
			if inbound["tag"] == "stealth" {
				handshake = inbound["tls"].(engine.Object)["reality"].(engine.Object)["handshake"].(engine.Object)
			}
		}
		if handshake == nil {
			t.Fatalf("listen %s: no Stealth inbound", listen)
		}
		if handshake["server"] != want || handshake["server_port"] != uint16(9443) && handshake["server_port"] != 9443 {
			t.Fatalf("listen %s: handshake %v, want %s:9443", listen, handshake, want)
		}
	}
}
