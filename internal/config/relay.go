// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"pipe/internal/link"
)

// Relay is the parsed form of a relay code.
type Relay struct {
	Host        string // IP address or DNS name without brackets
	StealthPort uint16
	FastPort    uint16
	FastHop     string // a-b for a hopping Fast relay
}

// ParseRelay parses a code for a server. An empty code disables the relay.
func ParseRelay(code, serverHost string) (Relay, error) {
	if code == "" {
		return Relay{}, nil
	}
	endpoint, udp, hasUDP := strings.Cut(code, "/")
	host, tcp, hasTCP := endpoint, "", false
	if inner, bracketed := strings.CutPrefix(endpoint, "["); bracketed {
		var suffix string
		var closed bool
		host, suffix, closed = strings.Cut(inner, "]")
		if ip, _ := netip.ParseAddr(host); !closed || !ip.Is6() {
			return Relay{}, errors.New("relay brackets require an IPv6 address")
		}
		if suffix != "" {
			tcp, hasTCP = strings.CutPrefix(suffix, ":")
			if !hasTCP {
				return Relay{}, errors.New("invalid suffix after relay IPv6 address")
			}
		}
	} else if ip, _ := netip.ParseAddr(endpoint); !ip.Is6() {
		host, tcp, hasTCP = strings.Cut(endpoint, ":")
	} else if hasUDP {
		return Relay{}, errors.New("IPv6 relay addresses with ports require brackets")
	}
	if !link.ValidHost(host) {
		return Relay{}, errors.New("relay must have an IP address or DNS name")
	}
	addr, _ := netip.ParseAddr(host)
	serverAddr, _ := netip.ParseAddr(serverHost)
	if strings.EqualFold(host, serverHost) || (addr.IsValid() && addr.Unmap() == serverAddr.Unmap()) {
		return Relay{}, errors.New("relay must use a different host from the server")
	}
	r := Relay{Host: canonicalRelayHost(host)}
	if hasTCP {
		port, err := parseRelayPort(tcp)
		if err != nil {
			return Relay{}, err
		}
		r.StealthPort = port
	}
	if hasUDP {
		if strings.Contains(udp, "-") {
			if _, _, err := link.ParseHop(udp); err != nil {
				return Relay{}, err
			}
			r.FastHop = udp
		} else {
			port, err := parseRelayPort(udp)
			if err != nil {
				return Relay{}, err
			}
			r.FastPort = port
		}
	}
	return r, nil
}

func parseRelayPort(value string) (uint16, error) {
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil || port == 0 || value != strconv.FormatUint(port, 10) {
		return 0, errors.New("relay port must be between 1 and 65535 without leading zeros")
	}
	return uint16(port), nil
}

func canonicalRelayHost(host string) string {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.String()
	}
	return strings.ToLower(host)
}

func (r Relay) bare() bool {
	return r.StealthPort == 0 && r.FastPort == 0 && r.FastHop == ""
}

// String returns the canonical relay code.
func (r Relay) String() string {
	code := canonicalRelayHost(r.Host)
	if code == "" || r.bare() {
		return code
	}
	if strings.Contains(code, ":") {
		code = "[" + code + "]"
	}
	if r.StealthPort != 0 {
		code += ":" + strconv.Itoa(int(r.StealthPort))
	}
	if r.FastHop != "" {
		return code + "/" + r.FastHop
	}
	if r.FastPort != 0 {
		return code + "/" + strconv.Itoa(int(r.FastPort))
	}
	return code
}
