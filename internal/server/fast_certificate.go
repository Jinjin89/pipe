// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"pipe/internal/link"
	"pipe/internal/localfile"
)

const fastCertRotation = 60 * 24 * time.Hour
const fastCertLifetime = 90 * 24 * time.Hour
const fastCertSkew = time.Minute

func (s *Settings) refreshFastCertificate(now time.Time) error {
	var key *ecdsa.PrivateKey
	if len(s.FastPrivateKey) == 0 && len(s.FastCertificate) == 0 {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		s.FastPrivateKey, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
	} else {
		current, err := s.fastKeyPair()
		if err != nil {
			return err
		}
		issued := current.Leaf.NotBefore.Add(fastCertSkew)
		if now.Before(issued.Add(fastCertRotation)) && !now.Before(current.Leaf.NotBefore) {
			return nil
		}
		key = current.PrivateKey.(*ecdsa.PrivateKey)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{
		SerialNumber: serial, DNSNames: []string{s.fastName()},
		NotBefore: now.Add(-fastCertSkew), NotAfter: now.Add(fastCertLifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	s.FastCertificate, err = x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	return err
}

func (s Settings) fastKeyPair() (*tls.Certificate, error) {
	key, keyErr := x509.ParseECPrivateKey(s.FastPrivateKey)
	cert, certErr := x509.ParseCertificate(s.FastCertificate)
	if keyErr != nil || certErr != nil || key.Curve != elliptic.P256() ||
		!key.PublicKey.Equal(cert.PublicKey) || cert.VerifyHostname(s.fastName()) != nil ||
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) != nil {
		return nil, errors.New("invalid shared Fast key pair or certificate")
	}
	return &tls.Certificate{Certificate: [][]byte{s.FastCertificate}, PrivateKey: key, Leaf: cert}, nil
}

func (s Settings) fastPin() (string, error) {
	pair, err := s.fastKeyPair()
	if err != nil {
		return "", err
	}
	return link.EncodeKey(sha256.Sum256(pair.Leaf.RawSubjectPublicKeyInfo)), nil
}

func renewFastCertificate(dir string, now time.Time) (*tls.Certificate, error) {
	unlock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	settings, err := ReadSettings(dir)
	if err != nil {
		return nil, err
	}
	previous := settings.FastCertificate
	if err := settings.refreshFastCertificate(now); err != nil {
		return nil, err
	}
	if !bytes.Equal(previous, settings.FastCertificate) {
		if err := writeJSON(dir, settingsFile, settings); err != nil {
			return nil, err
		}
	}
	return settings.fastKeyPair()
}

// FastCertificateRequest creates a CSR using the same key that existing
// shared Fast links already pin.
func FastCertificateRequest(dir string) ([]byte, error) {
	s, err := ReadSettings(dir)
	if err != nil {
		return nil, err
	}
	if s.Mode != Shared {
		return nil, errors.New("the server manages Fast certificates in standalone mode")
	}
	pair, err := s.fastKeyPair()
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{s.fastName()}}, pair.PrivateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func chooseFastCertificate(path, name string, pinned, current *tls.Certificate, roots *x509.CertPool, now time.Time) (*tls.Certificate, error) {
	public, err := readPublicFastCertificate(path, name, pinned, roots, now)
	if err == nil {
		return public, nil
	}
	if current != nil && verifyPublicFastCertificate(current, pinned, name, roots, now) == nil {
		return current, err
	}
	return pinned, err
}

func readPublicFastCertificate(path, name string, pinned *tls.Certificate, roots *x509.CertPool, now time.Time) (*tls.Certificate, error) {
	data, err := localfile.Read(path, localfile.MaxConfigBytes, false)
	if err != nil {
		return nil, err
	}
	var certificates [][]byte
	var leaf *x509.Certificate
	for data = bytes.TrimSpace(data); len(data) != 0; data = bytes.TrimSpace(data) {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("invalid Fast certificate chain PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid Fast certificate")
		}
		if leaf == nil {
			leaf = cert
		}
		certificates = append(certificates, block.Bytes)
		data = rest
	}
	pair := &tls.Certificate{Certificate: certificates, Leaf: leaf, PrivateKey: pinned.PrivateKey}
	if err := verifyPublicFastCertificate(pair, pinned, name, roots, now); err != nil {
		return nil, err
	}
	return pair, nil
}

func verifyPublicFastCertificate(pair, pinned *tls.Certificate, name string, roots *x509.CertPool, now time.Time) error {
	if pair.Leaf == nil || !bytes.Equal(pair.Leaf.RawSubjectPublicKeyInfo, pinned.Leaf.RawSubjectPublicKeyInfo) {
		return errors.New("Fast certificate must use the existing pinned key")
	}
	if err := checkFastSAN(pair.Leaf, name); err != nil {
		return err
	}
	chain := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		chain.AddCert(cert)
	}
	_, err := pair.Leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: chain, CurrentTime: now})
	return err
}
