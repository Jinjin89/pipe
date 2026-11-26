// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultRescuePort = 2053

const retiredRescue = "Rescue now runs inside Pipe. Add a rescue section with sni, cert and key to setup JSON and run setup again (keys and devices are kept)"
const rescueFilePrefix = "rescue-"

var errRescueFastName = errors.New("the Rescue CDN name must differ from the Fast TLS name")

// RescueConfig is the dedicated shared Rescue listener and its certificate files.
type RescueConfig struct {
	Port uint16 `json:"port"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func (s Settings) sharedRescuePort() uint16 {
	if s.Mode == Shared && s.Rescue != nil && s.RescueListen == "" && !s.rescueMatchesFastName() {
		return s.Rescue.Port
	}
	return 0
}

func (s Settings) rescueMatchesFastName() bool {
	return s.CDNDomain != "" && equalDNS(s.CDNDomain, s.fastName())
}

func (s Settings) rescuePort() uint16 {
	if s.CDNDomain == "" || s.rescueMatchesFastName() {
		return 0
	}
	if s.Mode == Standalone {
		return s.stealthPort()
	}
	return s.sharedRescuePort()
}

func RescuePortWarning(port uint16) string {
	switch port {
	case 0, 443, 2053, 2083, 2087, 2096, 8443:
		return ""
	default:
		return fmt.Sprintf("Rescue TCP port %d is outside Cloudflare's supported HTTPS ports", port)
	}
}

func (s Settings) validateRescue() error {
	cfg := s.Rescue
	if cfg == nil {
		return nil // Older states are readable even before migrating Rescue.
	}
	if s.CDNDomain == "" || cfg.Port == 0 || !filepath.IsAbs(cfg.Cert) || !filepath.IsAbs(cfg.Key) || s.Ports.VMess == 0 {
		return errors.New("shared Rescue requires a CDN domain, dedicated TLS port, certificate, key and loopback VMess port")
	}
	return nil
}

func (s Settings) validateSharedTCPPorts(proxy *httpsProxyListenerConfig) error {
	ports := make(map[uint16]string)
	if proxy != nil && !proxy.retired() && s.RealityDest == realitySelf {
		ports[s.stealthPort()] = "Stealth"
	}
	check := func(port uint16, name string) error {
		if port == 0 {
			return nil
		}
		if other := ports[port]; other != "" {
			return fmt.Errorf("%s TCP port %d conflicts with %s", name, port, other)
		}
		ports[port] = name
		return nil
	}
	if err := check(s.sharedRescuePort(), "Rescue"); err != nil {
		return err
	}
	if err := check(s.Ports.VMess, "VMess"); err != nil {
		return err
	}
	if proxy != nil && !proxy.retired() {
		switch proxy.Port {
		case 0, 80, 443:
			return fmt.Errorf("HTTPS proxy TCP port %d is reserved", proxy.Port)
		}
		if err := check(proxy.Port, "HTTPS proxy"); err != nil {
			return err
		}
		if proxy.method() == "http" {
			return check(80, "HTTP-01")
		}
	}
	return nil
}

func (s *Settings) configureRescue(cfg RescueConfig) error {
	if s.CDNDomain == "" {
		if cfg != (RescueConfig{}) {
			return errors.New("dedicated Rescue options require --cdn-domain")
		}
		s.Rescue, s.Ports.VMess = nil, 0
		return nil
	}
	if s.rescueMatchesFastName() {
		return errRescueFastName
	}
	if cfg.Cert == "" || cfg.Key == "" {
		return errors.New("shared Rescue requires --rescue-cert and --rescue-key with --cdn-domain")
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultRescuePort
	}
	var err error
	if cfg.Cert, err = filepath.Abs(cfg.Cert); err != nil {
		return err
	}
	if cfg.Key, err = filepath.Abs(cfg.Key); err != nil {
		return err
	}
	s.Rescue = &cfg
	if err := s.validateSharedTCPPorts(s.HTTPSProxyListener); err != nil {
		return err
	}
	if s.Ports.VMess == 0 {
		return s.allocateRescueVMess(s.HTTPSProxyListener, checkRescueLoopback)
	}
	return nil
}

func (s *Settings) allocateRescueVMess(proxy *httpsProxyListenerConfig, probe func(uint16) error) error {
	for port := uint16(10001); port != 0; port++ {
		s.Ports.VMess = port
		if s.validateSharedTCPPorts(proxy) != nil {
			continue
		}
		err := probe(port)
		switch {
		case err == nil:
			return nil
		case portInUse(err):
			continue
		default:
			return err
		}
	}
	return errors.New("no free loopback VMess port for Rescue")
}

func checkRescueLoopback(port uint16) error {
	listener, err := net.Listen("tcp4", loopback(port))
	if err != nil {
		return err
	}
	return listener.Close()
}

// SetRescue changes only the shared Rescue endpoint and its certificate.
// A nil domain keeps the saved name. An explicit empty domain disables Rescue.
func SetRescue(dir string, domain *string, options RescueConfig) (uint16, error) {
	unlock, err := lockDir(dir)
	if err != nil {
		return 0, err
	}
	defer unlock()
	s, err := ReadSettings(dir)
	if err != nil {
		return 0, err
	}
	if s.Mode != Shared {
		return 0, errors.New("a dedicated Rescue listener requires shared mode")
	}
	if domain != nil {
		s.CDNDomain = strings.ToLower(*domain)
	}
	old := s.Rescue
	cfg := options
	newFiles := cfg.Cert != "" || cfg.Key != ""
	if s.CDNDomain != "" && old != nil {
		if !newFiles {
			cfg.Cert, cfg.Key = old.Cert, old.Key
		}
		if cfg.Port == 0 {
			cfg.Port = old.Port
		}
	}
	s.RescueListen = ""
	if err := s.configureRescue(cfg); err != nil {
		return 0, err
	}
	if err := s.normalizeDeployment(); err != nil {
		return 0, err
	}
	if s.Rescue != nil {
		if newFiles {
			if err := s.storeRescueFiles(dir); err != nil {
				return 0, err
			}
		} else if _, err := loadRescuePEM(s, time.Now()); err != nil {
			return 0, err
		}
	}
	if err := writeJSON(dir, settingsFile, s); err != nil {
		if newFiles {
			err = errors.Join(err, removeRescueFiles(dir, s.Rescue))
		}
		return 0, err
	}
	if s.Rescue == nil || newFiles {
		return s.sharedRescuePort(), removeRescueFiles(dir, old)
	}
	return s.sharedRescuePort(), nil
}

func loadRescuePEM(s Settings, now time.Time) (*tls.Certificate, error) {
	return loadPEMFiles(s.CDNDomain, s.Rescue.Cert, s.Rescue.Key, "Rescue", now)
}

func (s *Settings) storeRescueFiles(dir string) error {
	if s.Rescue == nil {
		return nil
	}
	cert, key, err := readPEMFiles(s.Rescue.Cert, s.Rescue.Key, "Rescue")
	if err != nil {
		return err
	}
	defer clear(key)
	if _, err := parsePEMFiles(s.CDNDomain, "Rescue", cert, key, time.Now()); err != nil {
		return err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	prefix := rescueFilePrefix + hex.EncodeToString(nonce[:])
	cfg := &RescueConfig{Port: s.Rescue.Port, Cert: filepath.Join(abs, prefix+"-cert.pem"), Key: filepath.Join(abs, prefix+"-key.pem")}
	if err := writeAtomic(abs, filepath.Base(cfg.Cert), cert, 0600); err != nil {
		return err
	}
	if err := writeAtomic(abs, filepath.Base(cfg.Key), key, 0600); err != nil {
		return errors.Join(err, removeRescueFiles(abs, cfg))
	}
	s.Rescue = cfg
	return nil
}

func removeRescueFiles(dir string, cfg *RescueConfig) error {
	if cfg == nil {
		return nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, file := range []struct{ path, suffix string }{{cfg.Cert, "-cert.pem"}, {cfg.Key, "-key.pem"}} {
		name, prefixed := strings.CutPrefix(filepath.Base(file.path), rescueFilePrefix)
		nonce, suffixed := strings.CutSuffix(name, file.suffix)
		if filepath.Dir(file.path) == abs && prefixed && suffixed && isHex(nonce, 16) {
			if err := os.Remove(file.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func rescueTLSConfig(domain string, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), originCA *x509.CertPool) *tls.Config {
	config := strictSiteTLS(domain, getCertificate)
	if originCA != nil {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = originCA
	}
	return config
}
