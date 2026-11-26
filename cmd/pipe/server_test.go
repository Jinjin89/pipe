// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pipe/internal/link"
	"pipe/internal/server"
)

func TestServerRescueCommandSetsAndClearsState(t *testing.T) {
	dir := t.TempDir()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	check(server.InitWithOptions(dir, "direct.example", "", server.InitOptions{Mode: server.Shared}))
	_, _, err := server.Add(dir, "phone", false)
	check(err)
	before, err := server.ReadSettings(dir)
	check(err)

	const cdn = "cdn.example"
	public, key, err := ed25519.GenerateKey(rand.Reader)
	check(err)
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{cdn}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	certDER, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, key)
	check(err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	check(err)
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	check(os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0600))
	check(os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600))

	check(runServer(t.Context(), []string{
		"rescue", "--dir", dir, "--cdn-domain", cdn, "--rescue-port", "2087", "--rescue-cert", certPath, "--rescue-key", keyPath,
	}))
	raw, _, err := server.Add(dir, "rescue-device", false)
	check(err)
	profile, err := link.Parse(raw)
	check(err)
	if profile.CDN != cdn || profile.CDNPort != 2087 {
		t.Fatalf("device link did not carry the new Rescue endpoint, got %s:%d", profile.CDN, profile.CDNPort)
	}
	check(server.Revoke(dir, "rescue-device"))
	check(runServer(t.Context(), []string{"rescue", "--dir", dir, "--cdn-domain="}))
	after, err := server.ReadSettings(dir)
	check(err)
	devices, err := server.ReadDevices(dir)
	check(err)
	if after.CDNDomain != "" || after.Rescue != nil || len(devices) != 1 || devices[0].Name != "phone" ||
		before.RealityPrivateKey != after.RealityPrivateKey || !bytes.Equal(before.FastPrivateKey, after.FastPrivateKey) {
		t.Fatal("clearing Rescue did not preserve server keys and devices")
	}
}

func TestServerInitSharedFastName(t *testing.T) {
	for _, tc := range []struct {
		name, domain, proxy, fast, want, wantError string
	}{
		{name: "IP uses proxy", domain: "203.0.113.7", proxy: "Proxy.Example", want: "proxy.example"},
		{name: "DNS uses proxy", domain: "origin.example", proxy: "proxy.example", want: "proxy.example"},
		{name: "explicit override", domain: "203.0.113.7", proxy: "proxy.example", fast: "fast.example", want: "fast.example"},
		{name: "IP with explicit name", domain: "2001:db8::7", fast: "fast.example", want: "fast.example"},
		{name: "DNS without proxy", domain: "origin.example", want: "origin.example"},
		{name: "IP without a name", domain: "203.0.113.7", wantError: "require --fast-sni"},
		{name: "invalid proxy name", domain: "203.0.113.7", proxy: "203.0.113.8", wantError: "--proxy-domain must be a DNS name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			args := []string{"init", "--mode", "shared", "--dir", dir, "--domain", tc.domain}
			if tc.proxy != "" {
				args = append(args, "--proxy-domain", tc.proxy)
			}
			if tc.fast != "" {
				args = append(args, "--fast-sni", tc.fast)
			}
			err := runServer(t.Context(), args)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("init error = %v, want %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			settings, err := server.ReadSettings(dir)
			if err != nil {
				t.Fatal(err)
			}
			if settings.HTTPSProxyListener != nil {
				t.Fatal("init configured a separate HTTPS proxy")
			}
			cert, err := x509.ParseCertificate(settings.FastCertificate)
			if err != nil {
				t.Fatal(err)
			}
			if err := cert.VerifyHostname(tc.want); err != nil {
				t.Fatal(err)
			}
			raw, _, err := server.Add(dir, "phone", false)
			if err != nil {
				t.Fatal(err)
			}
			profile, err := link.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if profile.FastServerName() != tc.want {
				t.Fatalf("link Fast name = %q, want %q", profile.FastServerName(), tc.want)
			}
		})
	}
}
