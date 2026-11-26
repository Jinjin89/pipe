// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"pipe/internal/link"
)

type DeployMode string

const (
	Auto       DeployMode = "auto"
	Standalone DeployMode = "standalone"
	Shared     DeployMode = "shared"
)

type InitOptions struct {
	Mode         DeployMode
	Ports        Ports
	FastSNI      string
	ProxyDomain  string // Default Fast SNI for shared initialization.
	FastHop      string
	RealityDest  string // retired: only "self" is accepted, as a no-op
	Rescue       RescueConfig
	NoHTTPSProxy bool
	Warn         func(string)
}

func deployment(domain, cdn string, opts InitOptions) (Settings, error) {
	s := Settings{
		Mode: opts.Mode, Domain: domain, CDNDomain: cdn, FastSNI: opts.FastSNI,
		FastHop: opts.FastHop, Ports: opts.Ports,
	}
	if s.Ports.HTTPS == 0 {
		s.Ports.HTTPS = 443
	}
	if s.Ports.HTTP == 0 {
		s.Ports.HTTP = 80
	}
	if err := CheckRealityDest(opts.RealityDest); err != nil {
		return s, err
	}
	if s.Mode == "" || s.Mode == Auto {
		var err error
		var http3Occupied bool
		s.Mode, http3Occupied, err = detectMode(80, 443, 443, net.Listen, net.ListenPacket, net.DialTimeout)
		if err != nil {
			return s, err
		}
		if http3Occupied && s.fastPort() == 443 {
			return s, errors.New("UDP 443 is already in use. Select an available --fast-port for shared mode")
		}
	}
	enabled := s.Mode == Standalone && !opts.NoHTTPSProxy
	s.HTTPSProxy = &enabled
	switch s.Mode {
	case Standalone:
		if s.rescueMatchesFastName() {
			return s, errRescueFastName
		}
		s.assignInternalPorts()
		if opts.ProxyDomain != "" || opts.Rescue != (RescueConfig{}) {
			return s, errors.New("--proxy-domain and dedicated Rescue options require shared mode")
		}
	case Shared:
		if opts.ProxyDomain != "" && !link.ValidDNSName(opts.ProxyDomain) {
			return s, errors.New("--proxy-domain must be a DNS name")
		}
		if s.FastSNI == "" {
			s.FastSNI = strings.ToLower(opts.ProxyDomain)
		}
		if s.Ports.Stealth == 0 {
			s.Ports.Stealth = 8443
		}
		if err := s.configureRescue(opts.Rescue); err != nil {
			return s, err
		}
	default:
		return s, errors.New("--mode must be auto, standalone or shared")
	}
	if err := s.normalizeDeployment(); err != nil {
		return s, err
	}
	if s.Mode == Shared {
		if err := s.refreshFastCertificate(time.Now()); err != nil {
			return s, err
		}
	} else if opts.Warn != nil {
		if warning := RescuePortWarning(s.rescuePort()); warning != "" {
			opts.Warn(warning)
		}
	}
	return s, nil
}

func (s *Settings) assignInternalPorts() {
	preferred := []struct {
		port *uint16
		base uint16
	}{
		{&s.Ports.Decoy, 8443},
		{&s.Ports.VMess, 10001},
		{&s.Ports.RealityOrigin, 10443},
		{&s.Ports.RealityCDN, 10444},
	}
	used := map[uint16]bool{s.stealthPort(): true, s.Ports.HTTP: true}
	for _, entry := range preferred {
		if *entry.port != 0 {
			used[*entry.port] = true
		}
	}
	for _, entry := range preferred {
		if *entry.port == 0 {
			port := entry.base
			for used[port] {
				port++
			}
			*entry.port, used[port] = port, true
		}
	}
}

func detectMode(httpPort, stealthPort, fastPort uint16,
	listen func(string, string) (net.Listener, error),
	packet func(string, string) (net.PacketConn, error),
	dial func(string, string, time.Duration) (net.Conn, error),
) (DeployMode, bool, error) {
	mode := Standalone
	for _, port := range []uint16{httpPort, stealthPort} {
		listener, err := listenTCP("::", port, listen)
		switch {
		case err == nil:
			_ = listener.Close()
		case portInUse(err):
			mode = Shared
		case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
			for _, host := range []string{"127.0.0.1", "::1"} {
				conn, err := dial("tcp", addrPort(host, port), 200*time.Millisecond)
				if err == nil {
					_ = conn.Close()
					mode = Shared
					break
				}
			}
		default:
			return "", false, fmt.Errorf("probe TCP port %d: %w", port, err)
		}
	}
	listener, _, err := bindWithIPv4Fallback("::", func(host string) (net.PacketConn, error) {
		network := "udp"
		if host == "0.0.0.0" {
			network = "udp4"
		}
		return packet(network, addrPort(host, fastPort))
	})
	switch {
	case err == nil:
		_ = listener.Close()
	case portInUse(err):
		return Shared, true, nil
	case !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM):
		return "", false, fmt.Errorf("probe UDP port %d: %w", fastPort, err)
	}
	return mode, false, nil
}

func (s *Settings) normalizeDeployment() error {
	if !link.ValidHost(s.Domain) {
		return errors.New("invalid server domain")
	}
	if !link.ValidDNSName(s.Domain) && s.FastSNI == "" {
		if s.Mode == Shared {
			return errors.New("literal IPs require --fast-sni or --proxy-domain")
		}
		return errors.New("literal IPs require --fast-sni")
	}
	if s.CDNDomain != "" && (!link.ValidDNSName(s.CDNDomain) || equalDNS(s.Domain, s.CDNDomain)) {
		return errors.New("CDN domain must be a distinct DNS name")
	}
	if s.FastSNI != "" && !link.ValidDNSName(s.FastSNI) {
		return errors.New("--fast-sni must be a DNS name")
	}
	if s.FastHop != "" {
		if _, _, err := link.ParseHop(s.FastHop); err != nil {
			return err
		}
	}
	switch s.Mode {
	case Standalone:
		if s.HTTPSProxyListener != nil {
			return errors.New("a separate HTTPS proxy requires shared mode")
		}
		if s.RealityDest != "" || s.RealitySNI != "" || s.RealityAddress != "" || s.RescueListen != "" || s.Rescue != nil ||
			len(s.FastPrivateKey) != 0 || len(s.FastCertificate) != 0 {
			return errors.New("shared deployment fields are invalid in standalone mode")
		}
		ports := []uint16{s.stealthPort(), s.Ports.HTTP, s.Ports.Decoy, s.Ports.VMess}
		if s.CDNDomain != "" {
			ports = append(ports, s.Ports.RealityOrigin, s.Ports.RealityCDN)
		}
		seen := make(map[uint16]bool, len(ports))
		for _, port := range ports {
			if port == 0 || seen[port] {
				return errors.New("standalone TCP ports must be distinct and nonzero")
			}
			seen[port] = true
		}
	case Shared:
		if s.HTTPSProxy != nil && *s.HTTPSProxy {
			return errors.New("the built-in HTTPS proxy requires standalone mode")
		}
		if s.Ports.Decoy != 0 || s.Ports.RealityCDN != 0 {
			return errors.New("standalone loopback ports are invalid in shared mode")
		}
		if err := s.validateRescue(); err != nil {
			return err
		}
		if s.HTTPSProxyListener != nil {
			if err := s.validateProxyListener(*s.HTTPSProxyListener); err != nil {
				return err
			}
		} else if err := s.validateSharedTCPPorts(nil); err != nil {
			return err
		}
	default:
		return errors.New("invalid saved deploy mode")
	}
	if s.Ports.HTTPS == 0 || s.Ports.HTTP == 0 || s.fastPort() == 0 || s.stealthPort() == 0 {
		return errors.New("server ports must be nonzero")
	}
	return nil
}

func (s Settings) validateSharedState() error {
	switch s.RealityDest {
	case "":
		if s.RealitySNI != "" || s.RealityAddress != "" {
			return errors.New("invalid saved REALITY destination")
		}
	case realitySelf:
		address, err := netip.ParseAddrPort(s.RealityAddress)
		cfg := s.HTTPSProxyListener
		if err != nil || address.Addr() != netip.MustParseAddr("127.0.0.1") || address.Port() == 0 ||
			!link.ValidDNSName(s.RealitySNI) ||
			(cfg != nil && (cfg.Port != address.Port() || !equalDNS(cfg.Domain, s.RealitySNI))) {
			return errors.New("invalid saved REALITY destination")
		}
	}
	// Any other value is an older third-party target: Stealth stays off (realityTargetProblem).
	_, err := s.fastKeyPair()
	return err
}

func (s Settings) fastPort() uint16 {
	if s.Ports.Fast != 0 {
		return s.Ports.Fast
	}
	return s.Ports.HTTPS
}

func (s Settings) stealthPort() uint16 {
	if s.Ports.Stealth != 0 {
		return s.Ports.Stealth
	}
	return s.Ports.HTTPS
}

func (s Settings) fastName() string {
	if s.FastSNI != "" {
		return s.FastSNI
	}
	return s.Domain
}

func (s Settings) webName() string {
	if link.ValidDNSName(s.Domain) {
		return s.Domain
	}
	return s.FastSNI
}

func (s Settings) stealthName() string {
	if s.Mode == Shared && link.ValidDNSName(s.RealitySNI) {
		return strings.ToLower(s.RealitySNI)
	}
	return s.webName()
}

func (s Settings) proxyEnabled() bool {
	return s.Mode == Standalone && (s.HTTPSProxy == nil || *s.HTTPSProxy)
}

func (s Settings) proxyEndpoint() (string, uint16) {
	if s.proxyEnabled() {
		return s.webName(), s.stealthPort()
	}
	if s.Mode == Shared && s.HTTPSProxyListener != nil && !s.HTTPSProxyListener.retired() {
		return s.HTTPSProxyListener.Domain, s.HTTPSProxyListener.Port
	}
	return "", 0
}
