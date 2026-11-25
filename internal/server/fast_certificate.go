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
	"errors"
	"time"

	"pipe/internal/link"
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
