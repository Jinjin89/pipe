// SPDX-License-Identifier: GPL-3.0-or-later
//go:build with_quic && with_utls

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pipe/internal/engine"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
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
		certificates, err := testCertificates(filepath.Join(dir, "ca"), settings.names())
		must(t, err)
		for _, name := range settings.names() {
			leaf := certificates[name].Leaf
			if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name {
				t.Fatalf("certificate for %s has identities %v", name, leaf.DNSNames)
			}
		}
		cert := certificates[settings.fastName()]
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
				Config:         serverConfig(settings, devices, "127.0.0.1", serverListeners{masquerade: 12345, probe: 12346, mainTLS: settings.Ports.Decoy, rescueTLS: 12347}, testHosts),
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
	config := serverConfig(settings, nil, "127.0.0.1", serverListeners{masquerade: 12345, probe: 12346, mainTLS: settings.Ports.Decoy}, map[string]netip.Addr{host: private})
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
	const cdn = "static.example"
	cert, key := writeProxyTestPair(t, cdn, t.TempDir())
	if err := InitWithOptions(dir, "direct.example", cdn, InitOptions{
		Mode: Shared, Rescue: RescueConfig{Cert: cert, Key: key},
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
		Config: serverConfig(settings, devices, "127.0.0.1", serverListeners{masquerade: 12345, borrowProxy: true}, nil),
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
	initial, err := testCertificates(dir, settings.names())
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
	renewed, err := testCertificates(dir, settings.names())
	if err != nil {
		t.Fatal(err)
	}
	for _, certificates := range []map[string]*tls.Certificate{initial, renewed} {
		for _, name := range settings.names() {
			if _, err := certificates[name].Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestDecoyAndProbeHandler(t *testing.T) {
	settings := Settings{RealityPrivateKey: testCoverKey(1)}
	page, err := generateCoverSite(settings.RealityPrivateKey, mainCoverLabel)
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
		config := serverConfig(settings, nil, listen, serverListeners{masquerade: 12345, borrowProxy: true}, nil)
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

func TestDecoyCoverSelection(t *testing.T) {
	const origin, cdn = "origin.example", "cdn.example"
	settings := Settings{Domain: origin, CDNDomain: cdn, RealityPrivateKey: testCoverKey(1)}
	main, err := generateCoverSite(settings.RealityPrivateKey, mainCoverLabel)
	must(t, err)
	rescue, err := generateCoverSite(settings.RealityPrivateKey, rescueCoverLabel)
	must(t, err)
	if string(main) == string(rescue) {
		t.Fatal("both names generated the same cover")
	}
	decoy, err := makeDecoy(settings, RunOptions{}, nil)
	must(t, err)
	for _, tc := range []struct {
		name, host string
		tls        *tls.ConnectionState
		want       coverPage
	}{
		{"origin", origin, &tls.ConnectionState{ServerName: origin}, main},
		{"CDN", cdn, &tls.ConnectionState{ServerName: cdn}, rescue},
		{"CDN SNI with another Host", origin, &tls.ConnectionState{ServerName: cdn}, rescue},
		{"origin SNI with CDN Host", cdn, &tls.ConnectionState{ServerName: origin}, main},
		{"CDN Host with missing SNI", cdn, &tls.ConnectionState{}, main},
		{"HTTP/3 masquerade with CDN Host", cdn + ":443", nil, main},
		{"HTTP/3 masquerade with origin Host", origin, nil, main},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host, req.TLS = tc.host, tc.tls
			w := httptest.NewRecorder()
			decoy.ServeHTTP(w, req)
			if w.Code != http.StatusOK || w.Body.String() != string(tc.want) {
				t.Fatalf("unexpected cover for %s", tc.name)
			}
		})
	}

	www := t.TempDir()
	must(t, os.WriteFile(filepath.Join(www, "index.html"), []byte("custom cover"), 0600))
	override, err := makeDecoy(settings, RunOptions{WWW: www}, nil)
	must(t, err)
	for _, sni := range []string{origin, cdn} {
		req := httptest.NewRequest(http.MethodGet, "https://"+sni+"/", nil)
		req.TLS.ServerName = sni
		w := httptest.NewRecorder()
		override.ServeHTTP(w, req)
		if w.Code != http.StatusOK || w.Body.String() != "custom cover" {
			t.Fatalf("custom cover failed for %s", sni)
		}
	}
}

type startupLog struct {
	bytes.Buffer
	ready chan struct{}
}

func (l *startupLog) Write(p []byte) (int, error) {
	n, err := l.Buffer.Write(p)
	if bytes.HasPrefix(p, []byte("Server listening on ")) {
		close(l.ready)
	}
	return n, err
}

func reserveRunTCP(t *testing.T) (uint16, net.Listener) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	must(t, err)
	t.Cleanup(func() { listener.Close() })
	return uint16(listener.Addr().(*net.TCPAddr).Port), listener
}

func TestSharedRunKeepsAvailableTiers(t *testing.T) {
	for _, tc := range []struct {
		name, warning              string
		blockedVMess, blockedProxy bool
	}{
		{name: "unused origin pull CA", warning: "--cf-origin-ca is unused while shared Rescue is disabled"},
		{name: "VMess bind failure", warning: "Rescue is OFF: start server engine", blockedVMess: true},
		{name: "proxy bind failure", warning: "HTTPS proxy is OFF: HTTPS proxy could not bind TCP port", blockedProxy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fast, err := net.ListenPacket("udp4", "127.0.0.1:0")
			must(t, err)
			defer fast.Close()
			stealthPort, stealth := reserveRunTCP(t)
			proxyPort, proxy := reserveRunTCP(t)
			init := InitOptions{Mode: Shared, Ports: Ports{Fast: uint16(fast.LocalAddr().(*net.UDPAddr).Port), Stealth: stealthPort}}
			options := RunOptions{Dir: dir, TestPorts: true, TestCA: t.TempDir()}
			var cdn string
			if tc.blockedVMess {
				cdn = testRescueDomain
				init.Ports.VMess, _ = reserveRunTCP(t)
				rescuePort, rescue := reserveRunTCP(t)
				cert, key := writeProxyTestPair(t, cdn, t.TempDir())
				init.Rescue = RescueConfig{Port: rescuePort, Cert: cert, Key: key}
				must(t, rescue.Close())
			} else {
				options.CFOriginCA = filepath.Join(dir, "unused-ca.pem")
			}
			must(t, InitWithOptions(dir, "origin.example", cdn, init))
			cert, key := writeProxyTestPair(t, testProxyDomain, options.TestCA)
			must(t, enableProxy(t.Context(), dir, ProxyEnableOptions{Domain: testProxyDomain, Port: proxyPort, CertFile: cert, KeyFile: key}, testProxySetup()))
			must(t, fast.Close())
			must(t, stealth.Close())
			if !tc.blockedProxy {
				must(t, proxy.Close())
			}

			output := &startupLog{ready: make(chan struct{})}
			options.Log = output
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			finished := make(chan error, 1)
			go func() { finished <- Run(ctx, options) }()
			select {
			case <-output.ready:
			case err := <-finished:
				t.Fatalf("server exited before starting the other tiers: %v\n%s", err, output.String())
			case <-ctx.Done():
				t.Fatal("server startup timed out")
			}
			wantLogs := []string{tc.warning}
			switch {
			case tc.blockedProxy:
				listener, err := net.Listen("tcp4", loopback(stealthPort))
				if err != nil {
					t.Fatalf("Stealth port must stay free after a proxy bind failure: %v", err)
				}
				listener.Close()
				wantLogs = append(wantLogs, "(UDP Fast)\n", "Stealth is OFF: the HTTPS proxy that Stealth borrows did not start")
			default:
				wantLogs = append(wantLogs, "(UDP Fast) and "+loopback(stealthPort), "HTTPS proxy listening on "+loopback(proxyPort))
				if tc.blockedVMess {
					listener, err := net.Listen("tcp4", loopback(init.Rescue.Port))
					if err != nil {
						t.Fatalf("the server retained its Rescue TLS socket: %v", err)
					}
					listener.Close()
				}
			}
			cancel()
			must(t, <-finished)
			log := output.String()
			for _, want := range wantLogs {
				if !strings.Contains(log, want) {
					t.Errorf("missing %q in server log:\n%s", want, log)
				}
			}
		})
	}
}

func TestSharedStealthTracksProxyCertificate(t *testing.T) {
	dir, caDir := t.TempDir(), t.TempDir()
	fast, err := net.ListenPacket("udp4", "127.0.0.1:0")
	must(t, err)
	defer fast.Close()
	fastPort := uint16(fast.LocalAddr().(*net.UDPAddr).Port)
	stealthPort, stealth := reserveRunTCP(t)
	proxyPort, proxy := reserveRunTCP(t)
	must(t, InitWithOptions(dir, "origin.example", "", InitOptions{
		Mode: Shared, Ports: Ports{Fast: fastPort, Stealth: stealthPort},
	}))
	cert, key := writeProxyTestPair(t, testProxyDomain, caDir)
	must(t, enableProxy(t.Context(), dir, ProxyEnableOptions{Domain: testProxyDomain, Port: proxyPort, CertFile: cert, KeyFile: key}, testProxySetup()))
	must(t, os.Remove(cert))
	must(t, fast.Close())
	must(t, stealth.Close())
	must(t, proxy.Close())

	ctx, cancel := context.WithTimeout(t.Context(), 18*time.Second)
	defer cancel()
	output := &startupLog{ready: make(chan struct{})}
	finished := make(chan error, 1)
	go func() { finished <- Run(ctx, RunOptions{Dir: dir, TestCA: caDir, TestPorts: true, Log: output}) }()
	select {
	case <-output.ready:
	case err := <-finished:
		t.Fatalf("server exited before starting Fast: %v\n%s", err, output.String())
	case <-ctx.Done():
		t.Fatal("server startup timed out")
	}
	address := loopback(stealthPort)
	if conn, err := net.DialTimeout("tcp4", address, time.Second); err == nil {
		conn.Close()
		t.Fatal("Stealth opened before the proxy had a certificate")
	}
	awaitStealth := func(wantOpen bool) {
		t.Helper()
		for {
			conn, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
			if err == nil {
				conn.Close()
			}
			if (err == nil) == wantOpen {
				return
			}
			select {
			case err := <-finished:
				t.Fatalf("server exited while waiting for Stealth to be open=%t: %v\n%s", wantOpen, err, output.String())
			case <-ctx.Done():
				t.Fatalf("timed out waiting for Stealth to be open=%t", wantOpen)
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	now := time.Now()
	root, rootKey, err := loadOrCreateTestRoot(caDir, now)
	must(t, err)
	trusted, err := issueLeaf(testProxyDomain, now, 9*time.Second, root, rootKey)
	must(t, err)
	writeProxyTestPEM(t, caDir, trusted)
	awaitStealth(true)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	dialer := &net.Dialer{Timeout: time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp4", address, &tls.Config{RootCAs: roots, ServerName: testProxyDomain})
	must(t, err)
	conn.Close()

	untrusted, err := issueLeaf(testProxyDomain, time.Now(), time.Hour, nil, nil)
	must(t, err)
	writeProxyTestPEM(t, caDir, untrusted)
	awaitStealth(false)
	// A replacement that cannot be used for Stealth can still serve the HTTPS proxy.
	conn, err = tls.DialWithDialer(dialer, "tcp4", loopback(proxyPort), &tls.Config{InsecureSkipVerify: true, ServerName: testProxyDomain})
	must(t, err)
	got := conn.ConnectionState().PeerCertificates[0]
	conn.Close()
	if !got.Equal(untrusted.Leaf) {
		t.Fatal("the HTTPS proxy did not load the replacement certificate")
	}
	cancel()
	must(t, <-finished)
	for _, text := range []string{
		"Stealth is OFF: HTTPS proxy certificate is unavailable",
		"Stealth listening on " + address,
		"Stealth is OFF: HTTPS proxy certificate for " + testProxyDomain + " failed server certificate verification",
	} {
		if strings.Count(output.String(), text) != 1 {
			t.Fatalf("expected one %q entry in server log:\n%s", text, output.String())
		}
	}
}

func TestStandaloneIgnoresUnusedOriginPullCA(t *testing.T) {
	dir := t.TempDir()
	must(t, Init(dir, "origin.example", ""))
	output := &startupLog{ready: make(chan struct{})}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- Run(ctx, RunOptions{
			Dir: dir, TestPorts: true, TestCA: dir, CFOriginCA: filepath.Join(dir, "unused.pem"), Log: output,
		})
	}()
	select {
	case <-output.ready:
	case err := <-finished:
		t.Fatalf("server exited before startup: %v", err)
	case <-ctx.Done():
		t.Fatal("server startup timed out")
	}
	cancel()
	must(t, <-finished)
	if !strings.Contains(output.String(), "--cf-origin-ca is unused while standalone Rescue is disabled") {
		t.Fatalf("missing unused CA warning: %s", output.String())
	}
}

func TestStandaloneRescueStartupFailureKeepsMainRoutes(t *testing.T) {
	for _, tc := range []struct {
		name, originCA, blocked, reason string
	}{
		{name: "unreadable origin pull CA", originCA: "missing", reason: "load --cf-origin-ca"},
		{name: "invalid origin pull CA", originCA: "invalid", reason: "--cf-origin-ca contains no PEM certificates"},
		{name: "VMess port busy", blocked: "VMess", reason: "start server engine"},
		{name: "CDN REALITY port busy", blocked: "CDN REALITY", reason: "start server engine"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, caDir := t.TempDir(), t.TempDir()
			fast, err := net.ListenPacket("udp4", "127.0.0.1:0")
			must(t, err)
			defer fast.Close()
			ports := Ports{Fast: uint16(fast.LocalAddr().(*net.UDPAddr).Port)}
			bindings := []struct {
				name string
				port *uint16
			}{
				{"Stealth", &ports.HTTPS}, {"HTTP", &ports.HTTP}, {"main TLS", &ports.Decoy},
				{"VMess", &ports.VMess}, {"origin REALITY", &ports.RealityOrigin}, {"CDN REALITY", &ports.RealityCDN},
			}
			var release []net.Listener
			for _, binding := range bindings {
				port, held := reserveRunTCP(t)
				*binding.port = port
				if binding.name != tc.blocked {
					release = append(release, held)
				}
			}
			must(t, InitWithOptions(dir, "origin.example", testRescueDomain, InitOptions{
				Mode: Standalone, Ports: ports, FastSNI: "fast.example",
			}))
			settings, err := ReadSettings(dir)
			must(t, err)
			options := RunOptions{Dir: dir, TestPorts: true, TestCA: caDir}
			if tc.originCA != "" {
				options.CFOriginCA = filepath.Join(dir, "origin-ca.pem")
				if tc.originCA == "invalid" {
					must(t, os.WriteFile(options.CFOriginCA, []byte("invalid PEM"), 0600))
				}
			}
			must(t, fast.Close())
			for _, listener := range release {
				must(t, listener.Close())
			}

			output := &startupLog{ready: make(chan struct{})}
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			finished := make(chan error, 1)
			go func() { finished <- runStandalone(ctx, options, settings, nil, "127.0.0.1", output) }()
			select {
			case <-output.ready:
			case err := <-finished:
				t.Fatalf("server exited before starting Fast and Stealth: %v\n%s", err, output.String())
			case <-ctx.Done():
				t.Fatal("server startup timed out")
			}
			data, err := os.ReadFile(filepath.Join(caDir, TestRootFile))
			must(t, err)
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(data) {
				t.Fatal("invalid fixture CA")
			}
			dialer := &net.Dialer{Timeout: 2 * time.Second}
			main, err := tls.DialWithDialer(dialer, "tcp4", loopback(ports.HTTPS), &tls.Config{
				ServerName: settings.webName(), RootCAs: roots,
			})
			must(t, err)
			main.Close()
			conn, err := quic.DialAddr(ctx, loopback(ports.Fast), &tls.Config{
				ServerName: settings.fastName(), RootCAs: roots, NextProtos: []string{http3.NextProtoH3},
			}, nil)
			must(t, err)
			conn.CloseWithError(0, "")
			cdn, err := tls.DialWithDialer(dialer, "tcp4", loopback(ports.HTTPS), &tls.Config{
				ServerName: testRescueDomain, InsecureSkipVerify: true,
			})
			if err == nil {
				cdn.Close()
				t.Fatal("the disabled Rescue route completed a CDN handshake")
			}
			for _, binding := range bindings[3:] {
				if binding.name != tc.blocked {
					listener, err := net.Listen("tcp4", loopback(*binding.port))
					if err != nil {
						t.Fatalf("%s listener was retained after disabling Rescue: %v", binding.name, err)
					}
					listener.Close()
				}
			}
			cancel()
			must(t, <-finished)
			log := output.String()
			if strings.Count(log, "Warning: Rescue is OFF:") != 1 || !strings.Contains(log, tc.reason) {
				t.Fatalf("expected one Rescue warning with %q:\n%s", tc.reason, log)
			}
			for _, binding := range bindings {
				if binding.name == tc.blocked && !strings.Contains(log, fmt.Sprintf(":%d", *binding.port)) {
					t.Fatalf("warning did not identify the busy %s port:\n%s", binding.name, log)
				}
			}
		})
	}
}

type delayedClientHello struct {
	net.Conn
	split bool
}

func (c *delayedClientHello) Write(p []byte) (int, error) {
	if c.split || len(p) <= 5 {
		return c.Conn.Write(p)
	}
	c.split = true
	n, err := c.Conn.Write(p[:5])
	if err != nil {
		return n, err
	}
	// Let the front listener finish sniffing before sending the rest of the record.
	time.Sleep(750 * time.Millisecond)
	m, err := c.Conn.Write(p[5:])
	return n + m, err
}

func TestStandaloneRescueTLSCannotUseTheIncompleteHelloFallback(t *testing.T) {
	dir := t.TempDir()
	const cdn = "cdn.example"
	must(t, Init(dir, "origin.example", cdn))
	output := &startupLog{ready: make(chan struct{})}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- Run(ctx, RunOptions{Dir: dir, TestPorts: true, TestCA: dir, Log: output}) }()
	select {
	case <-output.ready:
	case err := <-finished:
		t.Fatalf("server exited before startup: %v", err)
	case <-ctx.Done():
		t.Fatal("server startup timed out")
	}
	address := loopback(TestPorts().HTTPS)
	config := &tls.Config{ServerName: cdn, InsecureSkipVerify: true}
	ordinary, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp4", address, config)
	must(t, err)
	ordinary.Close()
	wire, err := net.DialTimeout("tcp4", address, 3*time.Second)
	must(t, err)
	defer wire.Close()
	client := tls.Client(&delayedClientHello{Conn: wire}, config)
	if err := client.HandshakeContext(ctx); err == nil {
		t.Fatal("a delayed CDN ClientHello succeeded via the main TLS listener")
	}
	cancel()
	must(t, <-finished)
}

func TestBorrowedHTTPSProxyListenerFailureIsFatal(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	must(t, err)
	defer listener.Close()
	failures, fatal := make(chan error, 1), make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	web := serveOn(webServer(http.NotFoundHandler(), nil), listener, failures)
	defer web.Close()
	go watchSharedProxy(ctx, failures, fatal, func(string) {})
	// Closing the socket directly simulates losing it before the service stops.
	must(t, listener.Close())
	select {
	case err := <-fatal:
		if !errors.Is(err, net.ErrClosed) || !strings.Contains(err.Error(), "HTTPS proxy listener used by Stealth stopped") {
			t.Fatalf("unexpected supervision error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("the failed listener did not reach engine supervision")
	}
}
