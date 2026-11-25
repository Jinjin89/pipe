// SPDX-License-Identifier: GPL-3.0-or-later

package relay

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"pipe/internal/config"
	"pipe/internal/engine"
	"pipe/internal/link"
)

const DefaultStatePath = "/etc/pipe-relay.conf"
const ownedHeader = "# Managed by Pipe relay\n"

// Request describes the server side of a route.
type Request struct {
	IPv4      netip.Addr `json:"ipv4,omitzero"`
	IPv6      netip.Addr `json:"ipv6,omitzero"`
	ServerTCP uint16     `json:"server_tcp,omitempty"`
	ServerUDP uint16     `json:"server_udp,omitempty"`
	ServerHop portRange  `json:"server_hop,omitzero"`
}

type route struct {
	Request
	Host     string    `json:"host"`
	RelayTCP uint16    `json:"relay_tcp,omitempty"`
	RelayUDP portRange `json:"relay_udp,omitzero"`
}

type portRange struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}

func single(port uint16) portRange { return portRange{port, port} }

func (p portRange) valid() bool {
	return p.First != 0 && p.Last >= p.First
}

func (p portRange) String() string {
	first := strconv.Itoa(int(p.First))
	if p.First == p.Last {
		return first
	}
	return first + "-" + strconv.Itoa(int(p.Last))
}

var globalIPv6 = netip.MustParsePrefix("2000::/3")

// PublicTarget reports whether an address can be used as a relay target.
func PublicTarget(address netip.Addr) bool {
	return engine.PublicDestination(address) && (!address.Unmap().Is6() || globalIPv6.Contains(address))
}

func parseTargets(to string) (Request, error) {
	var request Request
	for field := range strings.SplitSeq(to, ",") {
		ip, err := netip.ParseAddr(strings.TrimSpace(field))
		if err != nil || !PublicTarget(ip) {
			return Request{}, errors.New("--to requires one public IPv4 and/or one public IPv6 literal")
		}
		ip = ip.Unmap()
		address := &request.IPv4
		if ip.Is6() {
			address = &request.IPv6
		}
		if address.IsValid() {
			return Request{}, errors.New("--to accepts only one address per family")
		}
		*address = ip
	}
	return request, nil
}

func ParseRequest(to, tcp, udp string) (Request, error) {
	request, err := parseTargets(to)
	if err != nil {
		return Request{}, err
	}
	if tcp != "" {
		port, err := parsePort(tcp)
		if err != nil {
			return Request{}, fmt.Errorf("--tcp: %w", err)
		}
		request.ServerTCP = port
	}
	if udp != "" {
		base, hop, hopping := strings.Cut(udp, ",")
		port, err := parsePort(base)
		if err != nil {
			return Request{}, fmt.Errorf("--udp: %w", err)
		}
		request.ServerUDP = port
		if hopping {
			start, end, err := link.ParseHop(hop)
			if err != nil {
				return Request{}, fmt.Errorf("--udp: %w", err)
			}
			request.ServerHop = portRange{start, end}
		}
	}
	return request, request.validate()
}

func parsePort(raw string) (uint16, error) {
	port, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != raw {
		return 0, errors.New("expected a single port from 1 to 65535 without leading zeros")
	}
	return uint16(port), nil
}

func (r Request) validate() error {
	if !r.IPv4.IsValid() && !r.IPv6.IsValid() ||
		r.IPv4.IsValid() && (!r.IPv4.Is4() || !PublicTarget(r.IPv4)) ||
		r.IPv6.IsValid() && (!r.IPv6.Is6() || r.IPv6.Is4In6() || !PublicTarget(r.IPv6)) {
		return errors.New("relay route requires a public address for each configured family")
	}
	if r.ServerTCP == 0 && r.ServerUDP == 0 {
		return errors.New("provide at least one --tcp or --udp port")
	}
	if r.ServerHop != (portRange{}) && (r.ServerUDP == 0 || r.ServerHop.First == 0 || r.ServerHop.First >= r.ServerHop.Last) {
		return errors.New("relay route requires a Fast port and an increasing hop range")
	}
	return nil
}

func (r Request) targets() string {
	if !r.IPv4.IsValid() {
		return r.IPv6.String()
	}
	if !r.IPv6.IsValid() {
		return r.IPv4.String()
	}
	return r.IPv4.String() + "," + r.IPv6.String()
}

func (r Request) overlaps(other Request) bool {
	return r.IPv4.IsValid() && r.IPv4 == other.IPv4 || r.IPv6.IsValid() && r.IPv6 == other.IPv6
}

// AddCommand returns a shell command containing only validated addresses and ports.
func (r Request) AddCommand() string {
	line := "pipe relay add --to " + r.targets()
	if r.ServerTCP != 0 {
		line += " --tcp " + strconv.Itoa(int(r.ServerTCP))
	}
	if r.ServerUDP != 0 {
		line += " --udp " + strconv.Itoa(int(r.ServerUDP))
		if r.ServerHop.valid() {
			line += "," + r.ServerHop.String()
		}
	}
	return line
}

func (r Request) validHost(host string) bool {
	if !link.ValidHost(host) {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		return ip.IsGlobalUnicast() && ip != r.IPv4 && ip != r.IPv6 &&
			(ip.Is4() && r.IPv4.IsValid() || ip.Is6() && r.IPv6.IsValid())
	}
	return true
}

func (r Request) serverUDPPorts() portRange {
	if r.ServerHop.valid() {
		return r.ServerHop
	}
	return single(r.ServerUDP)
}

func (r route) code() string {
	code := config.Relay{Host: r.Host}
	if r.RelayTCP == 0 || !r.RelayUDP.valid() ||
		r.RelayTCP != r.ServerTCP || r.RelayUDP != r.serverUDPPorts() {
		code.StealthPort = r.RelayTCP
		if r.RelayUDP.First == r.RelayUDP.Last {
			code.FastPort = r.RelayUDP.First
		} else {
			code.FastHop = r.RelayUDP.String()
		}
	}
	return code.String()
}

func (r route) exposedPorts() string {
	var parts []string
	if r.RelayTCP != 0 {
		parts = append(parts, "TCP "+strconv.Itoa(int(r.RelayTCP)))
	}
	if r.RelayUDP.valid() {
		parts = append(parts, "UDP "+r.RelayUDP.String())
	}
	return strings.Join(parts, ", ")
}
