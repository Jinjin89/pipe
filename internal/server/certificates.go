// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

const TestRootFile = "ca.pem"

const httpsCertificateStorage = "certificates"

func (s Settings) names() []string {
	names := s.mainNames()
	if s.CDNDomain != "" && !slices.Contains(names, s.CDNDomain) {
		names = append(names, s.CDNDomain)
	}
	return names
}

func (s Settings) mainNames() []string {
	names := []string{s.webName()}
	if name := s.fastName(); name != "" && name != names[0] {
		names = append(names, name)
	}
	return names
}

func managedCertificates(dir string, settings Settings) (*certmagic.Config, *certmagic.ACMEIssuer, *certmagic.Cache, error) {
	path := filepath.Join(dir, httpsCertificateStorage)
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, nil, nil, err
	}
	var config *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return config, nil },
	})
	config = certmagic.New(cache, certmagic.Config{Storage: &certmagic.FileStorage{Path: path}})
	issuer := certmagic.NewACMEIssuer(config, certmagic.ACMEIssuer{
		CA:                      certmagic.LetsEncryptProductionCA,
		Agreed:                  true,
		DisableTLSALPNChallenge: true,
		AltHTTPPort:             int(settings.Ports.HTTP),
	})
	config.Issuers = []certmagic.Issuer{issuer}
	return config, issuer, cache, nil
}

func cachedCertificate(cache *certmagic.Cache, name string) *tls.Certificate {
	matches := cache.AllMatchingCertificates(strings.ToLower(name))
	if len(matches) == 0 {
		return nil
	}
	return &matches[0].Certificate
}

func manageStandaloneCertificates(ctx context.Context, config *certmagic.Config, settings Settings, log io.Writer) error {
	names := settings.mainNames()
	if err := config.ManageSync(ctx, names); err != nil {
		return err
	}
	if name := settings.CDNDomain; name != "" && !slices.Contains(names, name) {
		if err := config.ManageAsync(ctx, []string{name}); err != nil {
			fmt.Fprintf(log, "Warning: start background certificate management for Rescue: %v\n", err)
		}
	}
	return nil
}

func testCertificates(dir string, names []string) (map[string]*tls.Certificate, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	unlock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	now := time.Now()
	root, rootKey, err := loadOrCreateTestRoot(dir, now)
	if err != nil {
		return nil, err
	}
	certificates := make(map[string]*tls.Certificate, len(names))
	for _, name := range names {
		name = strings.ToLower(name)
		if certificates[name] != nil {
			continue
		}
		cert, err := issueLeaf(name, now, 24*time.Hour, root, rootKey)
		if err != nil {
			return nil, err
		}
		certificates[name] = cert
	}
	return certificates, nil
}

func issueLeaf(name string, now time.Time, lifetime time.Duration, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) (*tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{
		SerialNumber: serial, DNSNames: []string{name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(lifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if issuer == nil {
		issuer, issuerKey = leaf, leafKey
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &leafKey.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	parsedLeaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey, Leaf: parsedLeaf}, nil
}

func fastCertificateForName(name string, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if !equalDNS(hello.ServerName, name) {
			return nil, errTLSName
		}
		cert, err := getCertificate(hello)
		if err != nil {
			return nil, err
		}
		if cert == nil || len(cert.Certificate) == 0 {
			return nil, errors.New("missing Fast TLS certificate")
		}
		leaf := cert.Leaf
		if leaf == nil {
			leaf, err = x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, err
			}
		}
		if len(leaf.DNSNames) != 1 || len(leaf.IPAddresses) != 0 || !equalDNS(leaf.DNSNames[0], name) {
			return nil, fmt.Errorf("Fast TLS certificate must cover only %s", name)
		}
		return cert, nil
	}
}

func loadOrCreateTestRoot(dir string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	const keyFile = "ca-key.pem"
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, TestRootFile), filepath.Join(dir, keyFile))
	if err == nil {
		key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
		if !ok || pair.Leaf == nil || !pair.Leaf.IsCA || now.Before(pair.Leaf.NotBefore) || now.After(pair.Leaf.NotAfter) {
			return nil, nil, errors.New("invalid or expired test CA")
		}
		return pair.Leaf, key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("load test CA: %w", err)
	}
	for _, filename := range []string{TestRootFile, keyFile} {
		if _, err := os.Lstat(filepath.Join(dir, filename)); !errors.Is(err, os.ErrNotExist) {
			return nil, nil, errors.New("incomplete test CA certificate and key pair")
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	root := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Pipe Test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0),
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	if err := writeAtomic(dir, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return nil, nil, err
	}
	if err := writeAtomic(dir, TestRootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return nil, nil, err
	}
	root, err = x509.ParseCertificate(der)
	return root, key, err
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return serial.Add(serial, big.NewInt(1)), nil
}
