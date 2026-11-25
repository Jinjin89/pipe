// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"pipe/internal/engine"
)

func TestIncompleteTLSHelloUsesDecoyListener(t *testing.T) {
	settings := Settings{Domain: "origin.example", CDNDomain: "cdn.example", Ports: TestPorts()}
	config := serverConfig(settings, nil, "127.0.0.1", 20001, 20002, nil)
	var routes []engine.Object
	for _, rule := range config["route"].(engine.Object)["rules"].([]engine.Object) {
		if rule["inbound"] == engine.RealityFrontTag {
			routes = append(routes, rule)
		}
	}
	if len(routes) != 4 || routes[0]["action"] != "sniff" ||
		routes[1]["protocol"] != "tls" || routes[1]["domain"] != settings.CDNDomain || routes[1]["override_port"] != settings.Ports.RealityCDN ||
		routes[2]["protocol"] != "tls" || routes[2]["domain"] != settings.Domain || routes[2]["override_port"] != settings.Ports.RealityOrigin ||
		routes[3]["protocol"] != nil || routes[3]["domain"] != nil || routes[3]["override_port"] != settings.Ports.Decoy {
		t.Fatal("only a complete ClientHello for a known SNI should use REALITY")
	}
}

func TestDecoyConcealsRescuePathWithoutCredentials(t *testing.T) {
	settings := Settings{Domain: "origin.example", CDNDomain: "cdn.example", WSPath: "/ws/private", RealityPrivateKey: testCoverKey(1)}
	for _, test := range []struct {
		name     string
		options  RunOptions
		known    bool
		callAuth bool
	}{
		{name: "unknown device", callAuth: true},
		{name: "known device without origin certificate", options: RunOptions{CFOriginCA: "ca.pem"}, known: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			decoy, err := makeDecoy(settings, test.options, func(context.Context, string) bool {
				called = true
				return test.known
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "https://"+settings.CDNDomain+settings.WSPath, nil)
			req.TLS.ServerName = settings.CDNDomain
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
			recorder := httptest.NewRecorder()
			decoy.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusNotFound || recorder.Body.String() != "404 page not found\n" || called != test.callAuth {
				t.Fatalf("expected normal 404, got %d %q (VMess auth called: %t)", recorder.Code, recorder.Body.String(), called)
			}
		})
	}
}

func TestDecoyDirectoryTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	const body = "<h1>My own site</h1>"
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	decoy, err := makeDecoy(Settings{RealityPrivateKey: testCoverKey(1)}, RunOptions{WWW: dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	decoy.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK || w.Body.String() != body {
		t.Fatalf("expected the configured website, got %d %q", w.Code, w.Body.String())
	}
}

func TestWebServerDiscardsErrorLog(t *testing.T) {
	server := webServer(http.NotFoundHandler(), nil)
	if server.ErrorLog == nil || server.ErrorLog.Writer() != io.Discard {
		t.Fatal("expected HTTP server errors to be discarded")
	}
}

func TestDecoyServesUpstream404ForUnauthorizedRescue(t *testing.T) {
	settings := Settings{Domain: "origin.example", CDNDomain: "cdn.example", WSPath: "/ws/private"}
	var paths []string
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = testDecoyTransport(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.Path)
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     http.Header{"Content-Type": {"text/html"}, "X-Custom-Page": {"missing"}},
			Body:       io.NopCloser(strings.NewReader("<h1>Custom missing page</h1>")),
		}, nil
	})
	decoy, err := makeDecoy(settings, RunOptions{WebUpstream: "http://site.example"}, func(context.Context, string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	request := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "https://"+settings.CDNDomain+path, nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		w := httptest.NewRecorder()
		decoy.ServeHTTP(w, req)
		return w
	}
	ordinary, rescue := request("/missing"), request(settings.WSPath)
	if ordinary.Code != http.StatusNotFound || rescue.Code != ordinary.Code ||
		rescue.Body.String() != ordinary.Body.String() || !reflect.DeepEqual(rescue.Header(), ordinary.Header()) ||
		!slices.Equal(paths, []string{"/missing", settings.WSPath}) {
		t.Fatalf("expected both paths to use the same upstream 404, got %d %q and %d %q via %v",
			ordinary.Code, ordinary.Body.String(), rescue.Code, rescue.Body.String(), paths)
	}
}

type testDecoyTransport func(*http.Request) (*http.Response, error)

func (f testDecoyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOriginPullCAIsRequestedOnlyOnCDNSNI(t *testing.T) {
	settings := Settings{Domain: "origin.example", CDNDomain: "cdn.example"}
	roots := x509.NewCertPool()
	config := decoyTLSConfig(settings, nil, roots)
	ordinary, err := config.GetConfigForClient(&tls.ClientHelloInfo{ServerName: settings.Domain})
	if err != nil || ordinary != nil || config.ClientAuth != tls.NoClientCert {
		t.Fatalf("origin TLS should retain its normal certificate behavior: %v", err)
	}
	cdn, err := config.GetConfigForClient(&tls.ClientHelloInfo{ServerName: settings.CDNDomain})
	if err != nil || cdn == nil || cdn.ClientAuth != tls.VerifyClientCertIfGiven || cdn.ClientCAs != roots {
		t.Fatalf("CDN TLS should verify supplied certificates against the configured pull CA: %v", err)
	}
}

func TestHysteriaMasqueradePreservesHostAndUsesSeparateListener(t *testing.T) {
	settings := Settings{Domain: "origin.example", Ports: TestPorts()}
	config := serverConfig(settings, nil, "127.0.0.1", 20001, 20002, nil)
	masquerade := config["inbounds"].([]engine.Object)[0]["masquerade"].(engine.Object)
	if masquerade["rewrite_host"] != false || !strings.HasSuffix(masquerade["url"].(string), ":20001") {
		t.Fatal("masquerade must preserve the incoming Host on its own listener")
	}
	for _, rule := range config["route"].(engine.Object)["rules"].([]engine.Object) {
		if rule["domain"] == engine.ProbeDomain && rule["outbound"] == "probe-direct" && rule["override_port"] == 20002 {
			return
		}
	}
	t.Fatal("missing route to the separate probe listener")
}
