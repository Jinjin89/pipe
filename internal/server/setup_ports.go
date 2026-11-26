// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

type setupBinding struct {
	name, network string
	port          uint16
	loopback      bool
}

func setupBindings(s Settings) []setupBinding {
	bindings := []setupBinding{{"Fast", "udp", s.fastPort(), false}}
	if s.realityTargetProblem() == nil {
		bindings = append(bindings, setupBinding{"Stealth", "tcp", s.stealthPort(), false})
	}
	if s.Mode == Standalone {
		bindings = append(bindings, setupBinding{"HTTP-01", "tcp", s.Ports.HTTP, false},
			setupBinding{"cover", "tcp", s.Ports.Decoy, true})
		if s.CDNDomain != "" {
			bindings = append(bindings, setupBinding{"Rescue VMess", "tcp", s.Ports.VMess, true},
				setupBinding{"REALITY origin", "tcp", s.Ports.RealityOrigin, true},
				setupBinding{"REALITY CDN", "tcp", s.Ports.RealityCDN, true})
		}
		return bindings
	}
	if p := s.HTTPSProxyListener; p != nil && !p.retired() {
		bindings = append(bindings, setupBinding{"HTTPS proxy", "tcp", p.Port, false})
		if p.method() == "http" {
			bindings = append(bindings, setupBinding{"HTTPS proxy HTTP-01", "tcp", 80, false})
		}
	}
	if port := s.sharedRescuePort(); port != 0 {
		bindings = append(bindings, setupBinding{"Rescue", "tcp", port, false},
			setupBinding{"Rescue VMess", "tcp", s.Ports.VMess, true})
	}
	return bindings
}

func savedSetupPort(s Settings, b setupBinding) bool {
	for _, old := range setupBindings(s) {
		if old.port == b.port && old.network == b.network {
			return true
		}
	}
	if b.network != "tcp" || s.Mode != Shared {
		return false
	}
	if s.RealityDest != "" && b.port == s.stealthPort() {
		return true
	}
	if old := s.HTTPSProxyListener; old != nil && old.retired() {
		acme, _ := netip.ParseAddrPort(old.ACMEListen)
		if b.port == old.Port || b.port == acme.Port() {
			return true
		}
	}
	rescue, _ := netip.ParseAddrPort(s.RescueListen)
	return b.port == rescue.Port()
}

func (r *setupRun) checkPorts(s Settings, saved *Settings) error {
	// nftables prerouting redirects hop ports to Fast before socket lookup,
	// so only the Fast listener itself needs to be checked.
	for _, b := range setupBindings(s) {
		if saved != nil && savedSetupPort(*saved, b) {
			continue
		}
		if err := r.probePort(b); err != nil {
			return fmt.Errorf("check %s %s port %d: %w", b.name, strings.ToUpper(b.network), b.port, err)
		}
	}
	return nil
}

func (r *setupRun) probePort(b setupBinding) error {
	// Layout detection and VMess allocation can already have tried this bind.
	key := setupBinding{network: b.network, port: b.port, loopback: b.loopback}
	if err, ok := r.portChecks[key]; ok {
		return err
	}
	probe := r.probeBinding
	if probe == nil {
		probe = probeSetupBinding
	}
	err := probe(b)
	if r.portChecks == nil {
		r.portChecks = make(map[setupBinding]error)
	}
	r.portChecks[key] = err
	return err
}

func probeSetupBinding(b setupBinding) error {
	host, network := "", b.network
	if b.loopback {
		host, network = "127.0.0.1", network+"4"
	}
	if b.network == "tcp" {
		listener, err := net.Listen(network, addrPort(host, b.port))
		if err != nil {
			return err
		}
		return listener.Close()
	}
	listener, err := net.ListenPacket(network, addrPort(host, b.port))
	if err != nil {
		return err
	}
	return listener.Close()
}
