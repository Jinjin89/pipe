// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"pipe/internal/link"
)

type setupBinding struct {
	name, network string
	port          uint16
	loopback      bool
	address       netip.Addr
}

func setupBindings(s Settings) []setupBinding {
	bindings := []setupBinding{{name: "Fast", network: "udp", port: s.fastPort()}}
	if s.realityTargetProblem() == nil {
		bindings = append(bindings, setupBinding{name: "Stealth", network: "tcp", port: s.stealthPort()})
	}
	if s.Mode == Standalone {
		bindings = append(bindings, setupBinding{name: "HTTP-01", network: "tcp", port: s.Ports.HTTP},
			setupBinding{name: "cover", network: "tcp", port: s.Ports.Decoy, loopback: true})
		if s.CDNDomain != "" {
			bindings = append(bindings, setupBinding{name: "Rescue VMess", network: "tcp", port: s.Ports.VMess, loopback: true},
				setupBinding{name: "REALITY origin", network: "tcp", port: s.Ports.RealityOrigin, loopback: true},
				setupBinding{name: "REALITY CDN", network: "tcp", port: s.Ports.RealityCDN, loopback: true})
		}
		return bindings
	}
	if p := s.HTTPSProxyListener; p != nil && !p.retired() {
		bindings = append(bindings, setupBinding{name: "HTTPS proxy", network: "tcp", port: p.Port})
		if p.method() == "http" {
			bindings = append(bindings, setupBinding{name: "HTTPS proxy HTTP-01", network: "tcp", port: 80})
		}
	}
	if port := s.sharedRescuePort(); port != 0 {
		bindings = append(bindings, setupBinding{name: "Rescue", network: "tcp", port: port},
			setupBinding{name: "Rescue VMess", network: "tcp", port: s.Ports.VMess, loopback: true})
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

func (r *setupRun) checkPorts(s Settings, saved *Settings, hopDestinations []netip.Addr) error {
	for _, b := range setupBindings(s) {
		if saved != nil && savedSetupPort(*saved, b) {
			continue
		}
		if err := r.probePort(b); err != nil {
			return fmt.Errorf("check %s %s port %d: %w", b.name, strings.ToUpper(b.network), b.port, err)
		}
	}
	occupied := r.occupiedUDPPorts
	if occupied == nil {
		occupied = occupiedUDPPorts
	}
	return checkHopPorts(s.FastHop, s.fastPort(), hopDestinations, occupied, r.probePort)
}

func checkHopPorts(ports string, fast uint16, destinations []netip.Addr, occupied func() ([]uint16, error), probe func(setupBinding) error) error {
	if ports == "" {
		return nil
	}
	first, last, err := link.ParseHop(ports)
	if err != nil {
		return err
	}
	candidates, err := occupied()
	if err != nil {
		return fmt.Errorf("check occupied Fast hop ports: %w", err)
	}
	// Ask the kernel about each occupied candidate at the exact destination.
	// A scoped bind also detects wildcard sockets that cover that address.
	for _, port := range candidates {
		if port < first || port > last || port == fast {
			continue
		}
		for _, address := range destinations {
			family := "udp4"
			if address.Is6() {
				family = "udp6"
			}
			binding := setupBinding{name: "Fast hop", network: family, port: port, address: address}
			if err := probe(binding); err != nil {
				return fmt.Errorf("check Fast hop UDP port %d on %s: %w", port, address, err)
			}
		}
	}
	return nil
}

func occupiedUDPPorts() ([]uint16, error) {
	ports := make(map[uint16]struct{})
	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		file, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) && path == "/proc/net/udp6" {
			continue // IPv6 may be disabled in the kernel.
		}
		if err != nil {
			return nil, err
		}
		err = readUDPPorts(file, ports)
		file.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
	}
	return slices.Sorted(maps.Keys(ports)), nil
}

func readUDPPorts(r io.Reader, ports map[uint16]struct{}) error {
	rows := bufio.NewScanner(r)
	rows.Scan() // Header.
	for rows.Scan() {
		fields := strings.Fields(rows.Text())
		if len(fields) < 2 {
			return errors.New("invalid UDP socket table row")
		}
		_, port, _ := strings.Cut(fields[1], ":")
		number, err := strconv.ParseUint(port, 16, 16)
		if err != nil {
			return errors.New("invalid port in UDP socket table")
		}
		ports[uint16(number)] = struct{}{}
	}
	return rows.Err()
}

func fastHopDestinations(ifaces []SetupInterface, explicit netip.Addr) ([]netip.Addr, error) {
	var public, private [2][]netip.Addr
	for _, iface := range ifaces {
		for _, addr := range iface.Addrs {
			addr = addr.Unmap()
			if !addr.IsGlobalUnicast() {
				continue
			}
			if addr == explicit {
				return []netip.Addr{addr}, nil
			}
			if iface.Loopback {
				continue
			}
			family := 0
			if addr.Is6() {
				family = 1
			}
			if publicAddress(addr) {
				public[family] = append(public[family], addr)
			} else {
				private[family] = append(private[family], addr)
			}
		}
	}
	if explicit.IsValid() {
		return nil, errors.New("Fast hop address must be assigned to this server")
	}
	var destinations []netip.Addr
	for family, addrs := range public {
		if len(addrs) == 0 {
			addrs = private[family]
		}
		if len(addrs) > 1 {
			return nil, errors.New("multiple local Fast addresses; specify a Fast hop address")
		}
		destinations = append(destinations, addrs...)
	}
	if len(destinations) == 0 {
		return nil, errors.New("no local Fast hop address")
	}
	return destinations, nil
}

func (r *setupRun) probePort(b setupBinding) error {
	// Layout detection and VMess allocation can already have tried this bind.
	key := b
	key.name = ""
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
	if b.address.IsValid() {
		host = b.address.String()
	} else if b.loopback {
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
