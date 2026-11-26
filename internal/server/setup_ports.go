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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

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
	warnings, err := checkHopPorts(s.FastHop, s.fastPort(), hopDestinations, occupied, r.probePort, r.readPortSysctl)
	for _, warning := range warnings {
		r.printf("Warning: %s.\n", warning)
	}
	return err
}

func checkHopPorts(ports string, fast uint16, destinations []netip.Addr, occupied func() ([]uint16, error), probe func(setupBinding) error, readSysctl func(string) ([]byte, error)) ([]string, error) {
	if ports == "" {
		return nil, nil
	}
	first, last, err := link.ParseHop(ports)
	if err != nil {
		return nil, err
	}
	candidates, err := occupied()
	if err != nil {
		return nil, fmt.Errorf("check occupied Fast hop ports: %w", err)
	}
	ephemeral := sync.OnceValue(func() ephemeralUDPPorts { return readEphemeralUDPPorts(readSysctl) })
	var warnings []string
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
				if errors.Is(err, syscall.EADDRINUSE) && ephemeral().allows(port) {
					warnings = append(warnings, fmt.Sprintf("Fast hop UDP port %d on %s is currently in use within the local ephemeral port range; live local sockets stay exempted", port, address))
					continue
				}
				return warnings, fmt.Errorf("check Fast hop UDP port %d on %s: %w", port, address, err)
			}
		}
	}
	return warnings, nil
}

const (
	ipLocalPortRange     = "/proc/sys/net/ipv4/ip_local_port_range"
	ipLocalReservedPorts = "/proc/sys/net/ipv4/ip_local_reserved_ports"
)

type udpPortRange struct{ first, last uint16 }

func (r udpPortRange) contains(port uint16) bool {
	return port >= r.first && port <= r.last
}

type ephemeralUDPPorts struct {
	allocation udpPortRange
	reserved   []udpPortRange
}

func (p ephemeralUDPPorts) allows(port uint16) bool {
	return p.allocation.first != 0 && p.allocation.contains(port) && !slices.ContainsFunc(p.reserved, func(r udpPortRange) bool {
		return r.contains(port)
	})
}

// A zero allocation range preserves strict conflict checks when either
// setting is unavailable or invalid.
func readEphemeralUDPPorts(readSysctl func(string) ([]byte, error)) ephemeralUDPPorts {
	if readSysctl == nil {
		if runtime.GOOS != "linux" {
			return ephemeralUDPPorts{}
		}
		readSysctl = os.ReadFile
	}
	data, err := readSysctl(ipLocalPortRange)
	fields := strings.Fields(string(data))
	if err != nil || len(fields) != 2 {
		return ephemeralUDPPorts{}
	}
	allocation, ok := parseUDPPortRange(fields[0], fields[1])
	if !ok || allocation.first == 0 {
		return ephemeralUDPPorts{}
	}
	data, err = readSysctl(ipLocalReservedPorts)
	if err != nil {
		return ephemeralUDPPorts{}
	}
	ports := ephemeralUDPPorts{allocation: allocation}
	if entries := strings.TrimSpace(string(data)); entries != "" {
		for entry := range strings.SplitSeq(entries, ",") {
			first, last, ok := strings.Cut(entry, "-")
			if !ok {
				last = first
			}
			reserved, ok := parseUDPPortRange(first, last)
			if !ok {
				return ephemeralUDPPorts{}
			}
			ports.reserved = append(ports.reserved, reserved)
		}
	}
	return ports
}

func parseUDPPortRange(first, last string) (udpPortRange, bool) {
	start, firstErr := strconv.ParseUint(first, 10, 16)
	end, lastErr := strconv.ParseUint(last, 10, 16)
	return udpPortRange{uint16(start), uint16(end)}, firstErr == nil && lastErr == nil && start <= end
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

func fastHopDestinations(ifaces []SetupInterface, explicit netip.Addr) ([]netip.Addr, []string, error) {
	var public, private [2][]netip.Addr
	seen := make(map[netip.Addr]bool)
	for _, iface := range ifaces {
		for _, addr := range iface.Addrs {
			addr = addr.Unmap()
			if !addr.IsGlobalUnicast() {
				continue
			}
			if addr == explicit {
				return []netip.Addr{addr}, nil, nil
			}
			if iface.Loopback || seen[addr] {
				continue
			}
			seen[addr] = true
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
		return nil, nil, errors.New("Fast hop address must be assigned to this server")
	}
	var destinations []netip.Addr
	var warnings []string
	for family, addrs := range public {
		if len(addrs) == 0 {
			addrs = private[family]
		}
		switch len(addrs) {
		case 0:
		case 1:
			destinations = append(destinations, addrs[0])
		default:
			name := [2]string{"IPv4", "IPv6"}[family]
			warnings = append(warnings, fmt.Sprintf("skipping %s Fast hopping (multiple %s addresses); pass --fast-hop-address to pin one", name, name))
		}
	}
	if len(destinations) == 0 {
		if len(warnings) != 0 {
			return nil, warnings, errors.New("multiple local Fast addresses; specify a Fast hop address")
		}
		return nil, nil, errors.New("no local Fast hop address")
	}
	return destinations, warnings, nil
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
