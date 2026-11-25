// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/caddyserver/certmagic"
)

func TestHTTP01UsesTheExistingRedirectHandler(t *testing.T) {
	settings := Settings{Domain: "origin.example.test", Ports: Ports{HTTP: 18080, HTTPS: 18443}}
	config, issuer, stop, err := managedCertificates(t.TempDir(), settings)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if issuer.ListenHost != "" || issuer.AltHTTPPort != 18080 || issuer.DisableHTTPChallenge || !issuer.DisableTLSALPNChallenge {
		t.Fatal("issuer should reuse the existing HTTP-01 listener")
	}
	// Simulate the distributed solver storing a challenge before Present checks
	// the bound port. The handler can complete it without a second listener.
	key := path.Join("acme", certmagic.StorageKeys.Safe(issuer.IssuerKey()), "challenge_tokens", certmagic.StorageKeys.Safe(settings.Domain)+".json")
	challenge := []byte(`{"type":"http-01","token":"pipeToken","keyAuthorization":"pipeToken.testSignature","identifier":{"type":"dns","value":"origin.example.test"}}`)
	if err := config.Storage.Store(t.Context(), key, challenge); err != nil {
		t.Fatal(err)
	}
	handler := issuer.HTTPChallengeHandler(redirectHTTPS(settings))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://"+settings.Domain+"/.well-known/acme-challenge/pipeToken", nil))
	if response.Code != http.StatusOK || response.Body.String() != "pipeToken.testSignature" {
		t.Fatalf("HTTP-01 response was %d %q", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://"+settings.Domain+"/", nil))
	if response.Code != http.StatusPermanentRedirect || response.Header().Get("Location") != "https://"+settings.Domain+":18443/" {
		t.Fatal("ordinary HTTP requests should still redirect to HTTPS")
	}
}
