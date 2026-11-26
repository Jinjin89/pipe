// SPDX-License-Identifier: GPL-3.0-or-later
//go:build with_quic

package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"pipe/internal/link"

	"github.com/sagernet/quic-go/http3"
)

func TestSharedFastPublicChainAndPinnedKeyRenewal(t *testing.T) {
	const name = "fast.example"
	now := time.Now()
	dir := t.TempDir()
	must(t, InitWithOptions(dir, name, "", InitOptions{Mode: Shared}))
	settings, err := ReadSettings(dir)
	must(t, err)
	pinned, err := settings.fastKeyPair()
	must(t, err)
	encoded, _, err := Add(dir, "fixture", false)
	must(t, err)
	profile, err := link.Parse(encoded)
	must(t, err)
	pin, err := link.DecodeKey(profile.FastPin)
	must(t, err)
	csrPEM, err := FastCertificateRequest(dir)
	must(t, err)
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("missing certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	must(t, err)
	must(t, csr.CheckSignature())
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != name || !bytes.Equal(csr.RawSubjectPublicKeyInfo, pinned.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("certificate request does not match the enrolled Fast name and key")
	}
	root, rootKey, err := loadOrCreateTestRoot(dir, now)
	must(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	path := filepath.Join(dir, "fast-chain.pem")
	issue := func(subject string, key *ecdsa.PrivateKey, when time.Time, extraNames ...string) {
		t.Helper()
		serial, err := randomSerial()
		must(t, err)
		leaf := &x509.Certificate{SerialNumber: serial, DNSNames: append([]string{subject}, extraNames...),
			NotBefore: when.Add(-time.Minute), NotAfter: when.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
		must(t, err)
		must(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	must(t, err)
	defer listener.Close()
	var current atomic.Pointer[tls.Certificate]
	current.Store(pinned)
	getCertificate := fastCertificateForName(name, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return current.Load(), nil })
	h3 := &http3.Server{TLSConfig: &tls.Config{GetCertificate: getCertificate}, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "cover fixture")
	})}
	defer h3.Close()
	go h3.Serve(listener)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	fetch := func(config *tls.Config) error {
		transport := &http3.Transport{TLSClientConfig: config}
		defer transport.Close()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+listener.LocalAddr().String()+"/", nil)
		if err != nil {
			return err
		}
		resp, err := transport.RoundTrip(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil && (resp.StatusCode != http.StatusOK || string(body) != "cover fixture") {
			err = errors.New("unexpected cover response")
		}
		return err
	}
	oldLink := &tls.Config{ServerName: name, InsecureSkipVerify: true, VerifyConnection: func(conn tls.ConnectionState) error {
		if sha256.Sum256(conn.PeerCertificates[0].RawSubjectPublicKeyInfo) != pin {
			return errors.New("the enrolled key changed")
		}
		return nil
	}}
	public := &tls.Config{ServerName: name, RootCAs: roots}
	must(t, fetch(oldLink))
	if err := fetch(public); err == nil {
		t.Fatal("the fixture root unexpectedly trusted the pinned fallback")
	}
	key := pinned.PrivateKey.(*ecdsa.PrivateKey)
	issue(name, key, now)
	first, err := chooseFastCertificate(path, name, pinned, current.Load(), roots, now)
	must(t, err)
	current.Store(first)
	must(t, fetch(public))
	issue(name, key, now.Add(time.Minute))
	renewed, err := chooseFastCertificate(path, name, pinned, current.Load(), roots, now)
	must(t, err)
	if bytes.Equal(first.Leaf.Raw, renewed.Leaf.Raw) {
		t.Fatal("renewal did not select the new certificate")
	}
	current.Store(renewed)
	must(t, fetch(oldLink))
	must(t, fetch(public))
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	for _, fixture := range []struct {
		label, name string
		key         *ecdsa.PrivateKey
		extraNames  []string
	}{
		{label: "wrong name", name: "different.example", key: key},
		{label: "wrong key", name: name, key: other},
		{label: "wildcard", name: "*.example", key: key},
		{label: "multiple SANs", name: name, key: key, extraNames: []string{"additional.example"}},
	} {
		t.Run(fixture.label, func(t *testing.T) {
			issue(fixture.name, fixture.key, now, fixture.extraNames...)
			next, err := chooseFastCertificate(path, name, pinned, current.Load(), roots, now)
			if err == nil || next != renewed {
				t.Fatal("invalid renewal displaced the last verified chain")
			}
			current.Store(next)
			must(t, fetch(public))
			must(t, fetch(oldLink))
		})
	}
}
