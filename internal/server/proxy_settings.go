// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pipe/internal/engine"
	"pipe/internal/link"
	"pipe/internal/localfile"

	"github.com/caddyserver/certmagic"
)

const (
	DefaultProxyPort     = 9443
	proxyDNSSecretPrefix = "https-proxy-dns-"
	proxyDNSCloudflare   = "cloudflare"
	proxyDNSAliDNS       = "alidns"
)

var errStandaloneProxy = errors.New("standalone already serves the HTTPS proxy on its HTTPS port")

type httpsProxyListenerConfig struct {
	Domain     string `json:"domain"`
	Port       uint16 `json:"port"`
	CertMethod string `json:"cert_method,omitempty"`
	ACMEListen string `json:"acme_listen,omitempty"` // retired
	DNS        string `json:"dns,omitempty"`
	DNSSecret  string `json:"dns_secret,omitempty"`
	Cert       string `json:"cert,omitempty"`
	Key        string `json:"key,omitempty"`
	WWW        string `json:"www,omitempty"`
}

func (cfg httpsProxyListenerConfig) method() string {
	if cfg.CertMethod != "" {
		return cfg.CertMethod
	}
	// M3 configs predate cert_method.
	if cfg.DNS != "" {
		return "dns"
	}
	return "files"
}

const retiredProxy = "HTTPS proxy nginx certificate mode is retired. Add a proxy section and configure cert.dns or cert.file and cert.key in setup JSON (keys and devices are kept)"

func (cfg httpsProxyListenerConfig) retired() bool {
	return cfg.method() == "nginx" || cfg.ACMEListen != ""
}

func validProxyDNSSecretName(name string) bool {
	nonce, ok := strings.CutPrefix(name, proxyDNSSecretPrefix)
	return ok && isHex(nonce, 16)
}

type ProxyEnableOptions struct {
	Domain       string
	Port         uint16
	CertMethod   string
	DNS          string
	DNSTokenFile string
	DNSKeyFile   string
	CertFile     string
	KeyFile      string
	WWW          string
	Warn         func(string)
	Inform       func(string)
	ReadSecret   func(string) ([]byte, error)
}

type proxySetup struct {
	lookup     func(context.Context, string, string) ([]netip.Addr, error)
	interfaces func() ([]net.Addr, error)
	issue      func(context.Context, string, string, certmagic.DNSProvider, bool) error
	probeHTTP  func() (occupied bool, err error)
}

func EnableProxy(ctx context.Context, dir string, opts ProxyEnableOptions) error {
	return enableProxy(ctx, dir, opts, realProxySetup())
}

func realProxySetup() proxySetup {
	return proxySetup{
		lookup: net.DefaultResolver.LookupNetIP, interfaces: net.InterfaceAddrs,
		issue: issueProxyCertificate, probeHTTP: probeProxyHTTP,
	}
}

func enableProxy(ctx context.Context, dir string, opts ProxyEnableOptions, setup proxySetup) error {
	settings, err := ReadSettings(dir)
	if err != nil {
		return err
	}
	if settings.Mode != Shared {
		return errStandaloneProxy
	}
	method, reason, err := selectProxyCertMethod(opts, setup.probeHTTP)
	if err != nil {
		return err
	}
	if opts.Inform != nil {
		opts.Inform(fmt.Sprintf("HTTPS proxy certificate method: %s (%s).", method, reason))
	}
	opts.CertMethod = method
	cfg, secretSource, err := proxyConfigForEnable(opts)
	if err != nil {
		return err
	}
	if err := settings.validateProxyEnable(cfg); err != nil {
		return err
	}
	cfg.Domain = strings.ToLower(cfg.Domain)
	secret, err := prepareProxyCertificate(ctx, dir, &cfg, settings.HTTPSProxyListener, secretSource, opts, setup)
	if err != nil {
		return err
	}
	defer clear(secret)
	// Issuing a certificate can take minutes. Device revocations and other
	// state updates use this lock, so acquire it only for the commit.
	return saveEnabledProxy(dir, cfg, secret, opts.Warn)
}

// prepareProxyCertificate checks the inputs and obtains DNS certificates before
// the caller changes the active listener configuration.
func prepareProxyCertificate(ctx context.Context, dir string, cfg, previous *httpsProxyListenerConfig, secretSource string, opts ProxyEnableOptions, setup proxySetup) ([]byte, error) {
	if cfg.WWW != "" {
		cover, err := proxyCover(cfg.WWW, nil)
		if err != nil {
			return nil, err
		}
		cover.(*staticCover).dir.Close()
	}
	if err := checkProxyDNS(ctx, cfg.Domain, setup, opts.Warn); err != nil {
		return nil, err
	}
	var secret []byte
	switch cfg.method() {
	case "files":
		if _, err := loadProxyPEM(*cfg, time.Now()); err != nil {
			return nil, err
		}
	case "dns":
		var provider certmagic.DNSProvider
		var data []byte
		var err error
		if secretSource != "" {
			provider, data, err = readProxyDNSSecret(cfg.DNS, secretSource)
		} else if opts.ReadSecret == nil {
			flag := "--dns-token-file"
			if cfg.DNS == proxyDNSAliDNS {
				flag = "--dns-key-file"
			}
			err = errors.New("DNS credentials need a terminal or " + flag)
		} else {
			var raw []byte
			raw, err = opts.ReadSecret(cfg.DNS)
			if err == nil {
				provider, data, err = parseProxyDNSSecret(cfg.DNS, raw)
			}
			clear(raw)
		}
		if err != nil {
			return nil, err
		}
		secret = data
		changed := true
		if previous != nil && previous.DNSSecret != "" && previous.DNS == cfg.DNS && equalDNS(previous.Domain, cfg.Domain) {
			old, err := localfile.Read(filepath.Join(dir, previous.DNSSecret), 4096, true)
			changed = err != nil || !bytes.Equal(old, secret)
			clear(old)
		}
		if !changed {
			cfg.DNSSecret = previous.DNSSecret
			clear(secret)
			secret = nil
		}
		issueCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		err = setup.issue(issueCtx, dir, cfg.Domain, provider, changed)
		timedOut := errors.Is(issueCtx.Err(), context.DeadlineExceeded)
		cancel()
		if err != nil {
			clear(secret)
			if timedOut {
				return nil, fmt.Errorf("initial HTTPS proxy DNS-01 issuance timed out for %s", cfg.Domain)
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// Provider errors can contain credentials or signed requests.
			return nil, fmt.Errorf("initial HTTPS proxy DNS-01 issuance failed for %s. Check the DNS zone and provider credentials", cfg.Domain)
		}
	}
	if err := ctx.Err(); err != nil {
		clear(secret)
		return nil, err
	}
	return secret, nil
}

func proxyConfigForEnable(opts ProxyEnableOptions) (httpsProxyListenerConfig, string, error) {
	cfg := httpsProxyListenerConfig{Domain: opts.Domain, Port: opts.Port, CertMethod: opts.CertMethod, DNS: opts.DNS}
	if opts.Port == 0 {
		cfg.Port = DefaultProxyPort
	}
	hasFiles := opts.CertFile != "" || opts.KeyFile != ""
	hasDNS := opts.DNS != "" || opts.DNSTokenFile != "" || opts.DNSKeyFile != ""
	var source string
	switch cfg.CertMethod {
	case "files":
		if hasDNS || opts.CertFile == "" || opts.KeyFile == "" {
			return cfg, "", errors.New("certificate files require --cert and --key and cannot be combined with DNS settings")
		}
		var err error
		cfg.Cert, err = filepath.Abs(opts.CertFile)
		if err != nil {
			return cfg, "", err
		}
		cfg.Key, err = filepath.Abs(opts.KeyFile)
		if err != nil {
			return cfg, "", err
		}
	case "dns":
		switch {
		case !hasFiles && opts.DNS == proxyDNSCloudflare && opts.DNSKeyFile == "":
			source = opts.DNSTokenFile
		case !hasFiles && opts.DNS == proxyDNSAliDNS && opts.DNSTokenFile == "":
			source = opts.DNSKeyFile
		default:
			return cfg, "", errors.New("choose --dns cloudflare (optional --dns-token-file) or --dns alidns (optional --dns-key-file)")
		}
		var nonce [16]byte
		rand.Read(nonce[:])
		cfg.DNSSecret = proxyDNSSecretPrefix + hex.EncodeToString(nonce[:])
	case "http":
		if hasFiles || hasDNS {
			return cfg, "", errors.New("HTTP-01 cannot be combined with certificate files or DNS settings")
		}
	default:
		return cfg, "", errors.New("certificate method must be http, dns or files")
	}
	if opts.WWW != "" {
		www, err := filepath.Abs(opts.WWW)
		if err != nil {
			return cfg, "", err
		}
		cfg.WWW = www
	}
	return cfg, source, nil
}

func (s Settings) validateProxyEnable(cfg httpsProxyListenerConfig) error {
	if s.RealityDest == "" {
		s.RealityDest = realitySelf
	}
	return s.validateProxyListener(cfg)
}

func (s Settings) validateProxyListener(cfg httpsProxyListenerConfig) error {
	if !link.ValidDNSName(cfg.Domain) {
		return errors.New("HTTPS proxy --domain must be a DNS name")
	}
	domain, cdn := strings.ToLower(cfg.Domain), strings.ToLower(s.CDNDomain)
	if cdn != "" && (domain == cdn || strings.HasSuffix(domain, "."+cdn) || strings.HasSuffix(cdn, "."+domain)) {
		return errors.New("the HTTPS proxy domain must be separate from the CDN domain")
	}
	if err := s.validateSharedTCPPorts(&cfg); err != nil {
		return err
	}
	if cfg.DNSSecret != "" && !validProxyDNSSecretName(cfg.DNSSecret) {
		return errors.New("invalid saved HTTPS proxy certificate configuration")
	}
	if cfg.retired() {
		return nil
	}
	if cfg.WWW != "" && !filepath.IsAbs(cfg.WWW) {
		return errors.New("saved HTTPS proxy web directory must be absolute")
	}
	noDNS := cfg.DNS == "" && cfg.DNSSecret == ""
	noFiles := cfg.Cert == "" && cfg.Key == ""
	switch cfg.method() {
	case "files":
		if noDNS && filepath.IsAbs(cfg.Cert) && filepath.IsAbs(cfg.Key) {
			return nil
		}
	case "dns":
		if noFiles && cfg.DNSSecret != "" &&
			(cfg.DNS == proxyDNSCloudflare || cfg.DNS == proxyDNSAliDNS) {
			return nil
		}
	case "http":
		if noDNS && noFiles {
			return nil
		}
	}
	return errors.New("invalid saved HTTPS proxy certificate configuration")
}

func checkProxyDNS(ctx context.Context, domain string, setup proxySetup, warn func(string)) error {
	dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := setup.lookup(dnsCtx, "ip", domain)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err != nil || len(addresses) == 0 {
		if warn != nil {
			warn("The HTTPS proxy domain did not resolve. Verify its DNS-only record before connecting")
		}
		return nil
	}
	if warn == nil {
		return nil
	}
	local, err := setup.interfaces()
	if err != nil {
		warn("Could not verify whether the HTTPS proxy DNS record points to a local address")
	}
	var nonPublic, matchesLocal bool
	for _, address := range addresses {
		ip := address.Unmap()
		nonPublic = nonPublic || !engine.PublicDestination(ip)
		for _, address := range local {
			host, _, _ := strings.Cut(address.String(), "/")
			localIP, err := netip.ParseAddr(host)
			if err == nil && localIP.WithZone("").Unmap() == ip {
				matchesLocal = true
			}
		}
	}
	if nonPublic {
		warn("The HTTPS proxy domain resolves to a non-public address")
	}
	if err == nil && !matchesLocal {
		warn("The HTTPS proxy domain does not resolve to a local address. Verify the DNS record or NAT mapping")
	}
	return nil
}

func saveEnabledProxy(dir string, cfg httpsProxyListenerConfig, secret []byte, warn func(string)) error {
	unlock, err := lockDir(dir)
	if err != nil {
		return err
	}
	defer unlock()
	settings, err := ReadSettings(dir)
	if err != nil {
		return err
	}
	if settings.Mode != Shared {
		return errStandaloneProxy
	}
	if err := settings.validateProxyEnable(cfg); err != nil {
		return err
	}
	devices, err := ReadDevices(dir)
	if err != nil {
		return err
	}
	previous := settings.HTTPSProxyListener
	if cfg.DNSSecret != "" && len(secret) == 0 && (previous == nil || previous.DNSSecret != cfg.DNSSecret) {
		return errors.New("HTTPS proxy DNS credentials changed during setup; retry the command")
	}
	if len(secret) != 0 {
		if err := writeAtomic(dir, cfg.DNSSecret, secret, 0600); err != nil {
			return fmt.Errorf("store HTTPS proxy DNS credentials: %w", err)
		}
	}
	settings.HTTPSProxyListener = &cfg
	settings.LastProxyDomain = ""
	// Stealth borrows the proxy site: a new proxy domain or port moves the
	// REALITY name and fallback along with it, so Stealth never points at a
	// dead site. An older third-party target is left for "pipe server reality".
	linksChanged := false
	if settings.RealityDest == "" || settings.RealityDest == realitySelf {
		previous := settings.RealitySNI
		settings.borrowProxySite()
		linksChanged = settings.RealitySNI != previous
	}
	if err := writeJSON(dir, settingsFile, settings); err != nil {
		if len(secret) != 0 {
			_ = removeProxyDNSSecret(dir, &cfg)
		}
		return err
	}
	if linksChanged && len(devices) > 0 && warn != nil {
		warn("Stealth follows the HTTPS proxy domain. Device links need the new Stealth name: in each saved link, set rsni=<proxy domain> (or add the device again)")
	}
	warnMissingProxyPasswords(devices, warn)
	if previous != nil && previous.DNSSecret != cfg.DNSSecret {
		return removeProxyDNSSecret(dir, previous)
	}
	return nil
}

func warnMissingProxyPasswords(devices []Device, warn func(string)) {
	if warn == nil {
		return
	}
	for _, d := range devices {
		if d.HTTPSProxyPassword == "" {
			warn(fmt.Sprintf("Re-add device %q to give it an HTTPS proxy password", d.Name))
		}
	}
}

func DisableProxy(dir string) error {
	unlock, err := lockDir(dir)
	if err != nil {
		return err
	}
	defer unlock()
	settings, err := ReadSettings(dir)
	if err != nil {
		return err
	}
	if settings.Mode != Shared {
		return errStandaloneProxy
	}
	previous := settings.HTTPSProxyListener
	if previous == nil {
		return nil
	}
	settings.HTTPSProxyListener = nil
	settings.LastProxyDomain = previous.Domain
	if settings.RealityDest == realitySelf {
		// Stealth borrows the proxy site, so it goes off with it.
		settings.RealityDest, settings.RealitySNI, settings.RealityAddress = "", "", ""
	}
	if err := writeJSON(dir, settingsFile, settings); err != nil {
		return err
	}
	return removeProxyDNSSecret(dir, previous)
}

func removeProxyDNSSecret(dir string, cfg *httpsProxyListenerConfig) error {
	if cfg == nil || cfg.DNSSecret == "" {
		return nil
	}
	// Only remove the managed copy. The original path is never stored here.
	if err := os.Remove(filepath.Join(dir, cfg.DNSSecret)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the previous HTTPS proxy DNS credential copy: %w", err)
	}
	return nil
}

type ProxyInfo struct {
	Domain string
	Port   uint16
	Source string
	Method string
	Expiry time.Time
}

func ProxyStatus(dir string) (ProxyInfo, error) {
	settings, err := ReadSettings(dir)
	if err != nil {
		return ProxyInfo{}, err
	}
	domain, port := settings.proxyEndpoint()
	info := ProxyInfo{Domain: domain, Port: port}
	if domain == "" {
		return info, nil
	}
	if settings.Mode == Standalone {
		info.Source = "built-in"
		info.Method = "http"
		info.Expiry, err = certificateExpiry(dir, domain, httpsCertificateStorage, "")
		return info, err
	}
	cfg := settings.HTTPSProxyListener
	info.Method = cfg.method()
	info.Source = "HTTP-01"
	switch info.Method {
	case "dns":
		info.Source = cfg.DNS + " DNS-01"
	case "files":
		info.Source = "certificate files"
	}
	info.Expiry, err = certificateExpiry(dir, domain, proxyCertificateStorage, cfg.Cert)
	return info, err
}

func ProxyExport(dir, name string) (string, error) {
	unlock, err := lockDir(dir)
	if err != nil {
		return "", err
	}
	defer unlock()
	settings, err := ReadSettings(dir)
	if err != nil {
		return "", err
	}
	authority := settings.proxyAuthority()
	if authority == "" {
		return "", errors.New("HTTPS proxy is disabled")
	}
	devices, err := ReadDevices(dir)
	if err != nil {
		return "", err
	}
	index := deviceIndex(devices, name)
	if index < 0 {
		return "", errors.New("device does not exist")
	}
	device := devices[index]
	if device.HTTPSProxyPassword == "" {
		return "", errors.New("device has no HTTPS proxy password. Re-enroll it to generate one")
	}
	return link.FormatProxyURL(authority, device.Name, device.HTTPSProxyPassword), nil
}
