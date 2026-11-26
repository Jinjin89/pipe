// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"pipe/internal/localfile"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/alidns"
	"github.com/libdns/cloudflare"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const proxyCertificateStorage = "https-proxy-certificates"

var errProxyCertificateUnavailable = errors.New("HTTPS proxy certificate is unavailable")

// dnsPropagationDelay is how long DNS-01 waits after adding the TXT record.
// Cloudflare and AliDNS publish within seconds; this leaves a wide margin.
const dnsPropagationDelay = 30 * time.Second

func readProxyDNSSecret(provider, path string) (certmagic.DNSProvider, []byte, error) {
	data, err := localfile.Read(path, 4096, true)
	if err != nil {
		return nil, nil, fmt.Errorf("read HTTPS proxy DNS credentials: %w", err)
	}
	defer clear(data)
	return parseProxyDNSSecret(provider, data)
}

func parseProxyDNSSecret(provider string, data []byte) (certmagic.DNSProvider, []byte, error) {
	if len(data) > 4096 {
		return nil, nil, errors.New("HTTPS proxy DNS credentials exceed 4096 bytes")
	}
	secret := strings.TrimSuffix(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	switch provider {
	case proxyDNSCloudflare:
		if !validProxyDNSValue(secret) {
			return nil, nil, errors.New("Cloudflare token file must contain one nonempty token without whitespace or control characters")
		}
		return &cloudflare.Provider{APIToken: secret}, []byte(secret), nil
	case proxyDNSAliDNS:
		info, err := parseAliDNSSecret(secret)
		if err != nil {
			return nil, nil, err
		}
		return &alidns.Provider{CredentialInfo: info}, []byte(secret), nil
	default:
		return nil, nil, errors.New("unsupported HTTPS proxy DNS provider")
	}
}

func validProxyDNSValue(value string) bool {
	return value != "" && utf8.ValidString(value) && strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) == -1
}

func parseAliDNSSecret(secret string) (alidns.CredentialInfo, error) {
	var info alidns.CredentialInfo
	fieldError := errors.New("AliDNS key file must contain one access_key_id and one access_key_secret on separate lines")
	lines := strings.Split(secret, "\n")
	if len(lines) != 2 {
		return info, fieldError
	}
	for _, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !validProxyDNSValue(value) {
			return alidns.CredentialInfo{}, fieldError
		}
		switch key {
		case "access_key_id":
			info.AccessKeyID = value
		case "access_key_secret":
			info.AccessKeySecret = value
		default:
			return alidns.CredentialInfo{}, fieldError
		}
	}
	if info.AccessKeyID == "" || info.AccessKeySecret == "" {
		return alidns.CredentialInfo{}, fieldError
	}
	return info, nil
}

func issueProxyCertificate(ctx context.Context, dir, domain string, provider certmagic.DNSProvider, fresh bool) error {
	state := dir
	if fresh {
		// An empty store forces a new certificate and a new ACME account,
		// so even cached ACME authorizations cannot skip the DNS challenge.
		var err error
		state, err = os.MkdirTemp(dir, ".proxy-acme-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(state)
	}
	config, stop, err := proxyACMEConfig(state, provider, nil)
	if err != nil {
		return err
	}
	defer stop()
	// ObtainCertAsync blocks here with bounded retries and no interactive prompts.
	if err := config.ObtainCertAsync(ctx, domain); err != nil || !fresh {
		return err
	}
	issued, live := filepath.Join(state, proxyCertificateStorage), filepath.Join(dir, proxyCertificateStorage)
	if err := os.Rename(issued, live); err == nil {
		return nil
	}
	// Keep existing certificates and account data. Publish the new site
	// as a complete directory if this name has no certificate store yet.
	site := certmagic.StorageKeys.CertsSitePrefix(config.Issuers[0].IssuerKey(), domain)
	dest := filepath.Join(live, filepath.FromSlash(site))
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(issued, filepath.FromSlash(site)), dest); err != nil {
		if info, statErr := os.Stat(dest); statErr != nil || !info.IsDir() {
			return err
		}
	}
	return nil
}

func proxyACMEConfig(dir string, provider certmagic.DNSProvider, warn func(string)) (*certmagic.Config, func(), error) {
	config, cache, err := proxyManagedCertificates(dir, httpsProxyListenerConfig{CertMethod: "dns"}, provider, warn)
	if err != nil {
		return nil, nil, err
	}
	return config, cache.Stop, nil
}

func proxyManagedCertificates(dir string, cfg httpsProxyListenerConfig, provider certmagic.DNSProvider, warn func(string)) (*certmagic.Config, *certmagic.Cache, error) {
	path := filepath.Join(dir, proxyCertificateStorage)
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(path, 0700); err != nil {
		return nil, nil, err
	}
	logger := zap.NewNop()
	if warn != nil {
		message := "HTTPS proxy HTTP-01 certificate management reported an error. Check that TCP 80 is open and free"
		if cfg.method() == "dns" {
			message = "HTTPS proxy DNS-01 certificate management reported an error. Check the DNS zone and provider credentials"
		}
		logger = zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(zapcore.EncoderConfig{}),
			zapcore.AddSync(proxyACMEWarning(func() { warn(message) })), zap.ErrorLevel,
		))
	}
	var config *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return config, nil },
		Logger:           logger,
	})
	config = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: path}, Logger: logger,
	})
	template := certmagic.ACMEIssuer{
		CA: certmagic.LetsEncryptProductionCA, Agreed: true,
		DisableTLSALPNChallenge: true, Logger: logger,
	}
	if cfg.method() == "dns" {
		template.DisableHTTPChallenge = true
		// No local propagation check: it trusts this host's resolvers and
		// network (one dead IPv6 resolver or a negative cache stalls it).
		// Wait, then let Let's Encrypt check from its own vantage points.
		template.DNS01Solver = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
			DNSProvider: provider, Logger: logger,
			PropagationDelay: dnsPropagationDelay, PropagationTimeout: -1,
		}}
	}
	issuer := certmagic.NewACMEIssuer(config, template)
	// Keep issuance and unattended retries on the production directory.
	issuer.TestCA = ""
	config.Issuers = []certmagic.Issuer{issuer}
	return config, cache, nil
}

// Certmagic can include provider responses and signed request details in its
// errors. Report a fixed warning without forwarding log content or fields.
type proxyACMEWarning func()

func (warn proxyACMEWarning) Write(p []byte) (int, error) {
	warn()
	return len(p), nil
}

func certificateExpiry(dir, domain, storage, path string) (time.Time, error) {
	if path == "" {
		issuer := &certmagic.ACMEIssuer{CA: certmagic.LetsEncryptProductionCA}
		key := certmagic.StorageKeys.SiteCert(issuer.IssuerKey(), domain)
		path = filepath.Join(dir, storage, filepath.FromSlash(key))
	}
	data, err := localfile.Read(path, localfile.MaxConfigBytes, false)
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return time.Time{}, err
			}
			return leaf.NotAfter, nil
		}
	}
	return time.Time{}, errors.New("no certificate found in the HTTPS certificate file")
}

func loadProxyPEM(cfg httpsProxyListenerConfig, now time.Time) (*tls.Certificate, error) {
	return loadPEMFiles(cfg.Domain, cfg.Cert, cfg.Key, "HTTPS proxy", now)
}

func loadPEMFiles(domain, certPath, keyPath, service string, now time.Time) (*tls.Certificate, error) {
	certPEM, keyPEM, err := readPEMFiles(certPath, keyPath, service)
	if err != nil {
		return nil, err
	}
	defer clear(keyPEM)
	return parsePEMFiles(domain, service, certPEM, keyPEM, now)
}

func readPEMFiles(certPath, keyPath, service string) (certPEM, keyPEM []byte, err error) {
	certPEM, err = localfile.Read(certPath, localfile.MaxConfigBytes, false)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s certificate: %w", service, err)
	}
	keyPEM, err = localfile.Read(keyPath, localfile.MaxConfigBytes, true)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s key: %w", service, err)
	}
	return certPEM, keyPEM, nil
}

func parsePEMFiles(domain, service string, certPEM, keyPEM []byte, now time.Time) (*tls.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load %s certificate and key: %w", service, err)
	}
	if pair.Leaf == nil {
		pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse %s certificate: %w", service, err)
		}
	}
	if err := pair.Leaf.VerifyHostname(domain); err != nil {
		return nil, fmt.Errorf("%s certificate does not match the configured domain", service)
	}
	if err := pemValidity(pair.Leaf, service, now); err != nil {
		return nil, err
	}
	return &pair, nil
}

func pemValidity(cert *x509.Certificate, service string, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%s certificate is not yet valid", service)
	}
	if !now.Before(cert.NotAfter) {
		return fmt.Errorf("%s certificate has expired", service)
	}
	return nil
}

type proxyPEMCertificates struct {
	cfg  httpsProxyListenerConfig
	warn func(string)

	mu        sync.Mutex
	nextCheck time.Time
	certInfo  os.FileInfo
	keyInfo   os.FileInfo
	current   *tls.Certificate
}

func newProxyPEMCertificates(cfg httpsProxyListenerConfig, warn func(string)) *proxyPEMCertificates {
	p := &proxyPEMCertificates{cfg: cfg, warn: warn}
	_, _ = p.certificateAt(time.Now())
	return p
}

func (p *proxyPEMCertificates) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.certificateAt(time.Now())
}

func (p *proxyPEMCertificates) certificateAt(now time.Time) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current != nil && pemValidity(p.current.Leaf, "HTTPS proxy", now) != nil {
		p.current = nil
		p.nextCheck = time.Time{}
	}
	if !now.Before(p.nextCheck) {
		if err := p.reload(now); err != nil && p.warn != nil {
			p.warn("HTTPS proxy certificate reload failed: " + err.Error())
		}
		interval := time.Minute
		if p.current == nil {
			interval = 5 * time.Second
		}
		p.nextCheck = now.Add(interval)
	}
	if p.current == nil {
		return nil, errProxyCertificateUnavailable
	}
	return p.current, nil
}

func (p *proxyPEMCertificates) reload(now time.Time) error {
	certInfo, err := os.Stat(p.cfg.Cert)
	if err != nil {
		return err
	}
	keyInfo, err := os.Stat(p.cfg.Key)
	if err != nil {
		return err
	}
	if p.current != nil && sameProxyPEMFile(certInfo, p.certInfo) && sameProxyPEMFile(keyInfo, p.keyInfo) {
		return nil
	}
	pair, err := loadProxyPEM(p.cfg, now)
	if err != nil {
		return err
	}
	p.current, p.certInfo, p.keyInfo = pair, certInfo, keyInfo
	return nil
}

func sameProxyPEMFile(current, previous os.FileInfo) bool {
	return previous != nil && os.SameFile(current, previous) &&
		current.ModTime().Equal(previous.ModTime()) && current.Mode() == previous.Mode() && current.Size() == previous.Size()
}
