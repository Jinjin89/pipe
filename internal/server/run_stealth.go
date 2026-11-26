// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	"pipe/internal/engine"
	"pipe/internal/localfile"
)

const stealthCertificateGrace = 10 * time.Second

type verifiedStealthCover struct {
	pair          *tls.Certificate
	from, expires time.Time
}

func (c *verifiedStealthCover) validAt(now time.Time) bool {
	return !now.Before(c.from) && now.Before(c.expires)
}

type sharedStealth struct {
	verify               x509.VerifyOptions
	trustErr             error
	load                 func(time.Time) (*tls.Certificate, error)
	published            atomic.Pointer[verifiedStealthCover]
	warnUnavailableAfter time.Time
	warnedOff            bool
}

func newSharedStealth(name, testCA string) *sharedStealth {
	stealth := &sharedStealth{
		verify:               x509.VerifyOptions{DNSName: name},
		warnUnavailableAfter: time.Now().Add(stealthCertificateGrace),
	}
	if testCA == "" {
		return stealth // A nil root pool uses the system roots.
	}
	data, err := localfile.Read(filepath.Join(testCA, TestRootFile), localfile.MaxConfigBytes, false)
	if err != nil {
		stealth.trustErr = fmt.Errorf("load Stealth test CA: %w", err)
		return stealth
	}
	stealth.verify.Roots = x509.NewCertPool()
	if !stealth.verify.Roots.AppendCertsFromPEM(data) {
		stealth.trustErr = errors.New("Stealth test CA contains no PEM certificates")
	}
	return stealth
}

func (s *sharedStealth) proxyCertificate(fallback func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if cover := s.published.Load(); cover != nil {
			// Stealth borrows the same chain that passed verification.
			if !cover.validAt(time.Now()) {
				return nil, errors.New("Stealth cover certificate is outside its validity period")
			}
			return cover.pair, nil
		}
		return fallback(hello)
	}
}

func (s *sharedStealth) check(now time.Time, current *verifiedStealthCover) (*verifiedStealthCover, error) {
	if s.trustErr != nil {
		return nil, s.trustErr
	}
	pair, err := s.load(now)
	if err != nil {
		return nil, err
	}
	if pair == nil || len(pair.Certificate) == 0 {
		return nil, errProxyCertificateUnavailable
	}
	if current != nil && current.validAt(now) && slices.EqualFunc(current.pair.Certificate, pair.Certificate, bytes.Equal) {
		return &verifiedStealthCover{pair: pair, from: current.from, expires: current.expires}, nil
	}
	verify := s.verify
	verify.CurrentTime = now
	verify.Intermediates = x509.NewCertPool()
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	for _, der := range pair.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		verify.Intermediates.AddCert(intermediate)
	}
	chains, err := leaf.Verify(verify)
	if err != nil {
		return nil, fmt.Errorf("HTTPS proxy certificate for %s failed server certificate verification: %w", verify.DNSName, err)
	}
	cover := &verifiedStealthCover{pair: pair, from: leaf.NotBefore, expires: leaf.NotAfter}
	for _, cert := range chains[0] {
		if cert.NotBefore.After(cover.from) {
			cover.from = cert.NotBefore
		}
		if cert.NotAfter.Before(cover.expires) {
			cover.expires = cert.NotAfter
		}
	}
	if !cover.validAt(now) {
		return nil, errors.New("Stealth cover certificate is outside its validity period")
	}
	return cover, nil
}

func (s *sharedStealth) refresh(instance *engine.Instance, warn func(string)) (bool, error) {
	now := time.Now()
	previous := s.published.Load()
	cover, err := s.check(now, previous)
	if err == nil {
		s.published.Store(cover)
		if previous == nil {
			err = instance.SetInboundEnabled("stealth", true)
			if err != nil {
				s.published.Store(nil)
				err = fmt.Errorf("could not open the Stealth listener: %w", err)
			}
		}
	} else if previous != nil {
		if stopErr := instance.SetInboundEnabled("stealth", false); stopErr != nil {
			return false, fmt.Errorf("close Stealth listener: %w", stopErr)
		}
		s.published.Store(nil)
	}
	if err == nil {
		s.warnUnavailableAfter = time.Time{}
		s.warnedOff = false
	} else if !s.warnedOff && (!errors.Is(err, errProxyCertificateUnavailable) || !now.Before(s.warnUnavailableAfter)) {
		warn("Stealth is OFF: " + err.Error())
		s.warnedOff = true
	}
	return err == nil, nil
}
