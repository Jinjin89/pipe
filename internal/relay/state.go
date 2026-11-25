// SPDX-License-Identifier: GPL-3.0-or-later

package relay

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"

	"pipe/internal/localfile"
)

const maxStateBytes = localfile.MaxConfigBytes

type ingress struct {
	IPv4 []string `json:"ingress4,omitempty"`
	IPv6 []string `json:"ingress6,omitempty"`
}

type state struct {
	ingress
	routes []route
}

func stateText(s state) (string, error) {
	var out strings.Builder
	out.WriteString(ownedHeader)
	encoder := json.NewEncoder(&out)
	if err := encoder.Encode(s.ingress); err != nil {
		return "", err
	}
	for _, route := range s.routes {
		if err := encoder.Encode(route); err != nil {
			return "", err
		}
		if out.Len() > maxStateBytes {
			return "", errors.New("Pipe relay state is too large")
		}
	}
	return out.String(), nil
}

func parseState(text string) (state, error) {
	if len(text) > maxStateBytes {
		return state{}, errors.New("Pipe relay state is too large")
	}
	var s state
	body, owned := strings.CutPrefix(text, ownedHeader)
	if !owned {
		return state{}, errors.New("missing Pipe relay ownership header")
	}
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(nil, maxStateBytes)
	if !scanner.Scan() {
		return state{}, errors.New("missing relay ingress line")
	}
	if err := decodeStateLine(scanner.Text(), &s.ingress); err != nil {
		return state{}, fmt.Errorf("read relay ingress: %w", err)
	}
	for scanner.Scan() {
		var r route
		if err := decodeStateLine(scanner.Text(), &r); err != nil {
			return state{}, fmt.Errorf("read route on line %d: %w", len(s.routes)+3, err)
		}
		s.routes = append(s.routes, r)
	}
	if err := scanner.Err(); err != nil {
		return state{}, err
	}
	return s, s.validate()
}

func decodeStateLine(line string, target any) error {
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("expected exactly one JSON value on the line")
	}
	return nil
}

func (s state) validate() error {
	if len(s.routes) == 0 {
		return errors.New("relay state requires at least one route")
	}
	var used usedPorts
	var ipv4, ipv6 bool
	targets := make(map[netip.Addr]bool)
	for _, r := range s.routes {
		if err := r.Request.validate(); err != nil {
			return err
		}
		if !r.Request.validHost(r.Host) {
			return fmt.Errorf("invalid relay host %q for %s", r.Host, r.targets())
		}
		if (r.ServerTCP == 0) != (r.RelayTCP == 0) ||
			(r.ServerUDP == 0) != (r.RelayUDP == (portRange{})) ||
			r.ServerUDP != 0 && (!r.RelayUDP.valid() || !r.ServerHop.valid() && r.RelayUDP.First != r.RelayUDP.Last) {
			return fmt.Errorf("invalid relay ports for %s", r.targets())
		}
		for _, addr := range []netip.Addr{r.IPv4, r.IPv6} {
			if !addr.IsValid() {
				continue
			}
			if targets[addr] {
				return fmt.Errorf("duplicate relay target %s", addr)
			}
			targets[addr] = true
		}
		if r.RelayTCP != 0 && used.tcp[r.RelayTCP] || r.RelayUDP.valid() && !used.udp.free(r.RelayUDP) {
			return fmt.Errorf("overlapping relay ports for %s", r.targets())
		}
		used.reserve(r)
		ipv4 = ipv4 || r.IPv4.IsValid()
		ipv6 = ipv6 || r.IPv6.IsValid()
	}
	if ipv4 != (len(s.IPv4) != 0) || ipv6 != (len(s.IPv6) != 0) {
		return errors.New("relay requires ingress interfaces for each target family")
	}
	for _, names := range [][]string{s.IPv4, s.IPv6} {
		seen := make(map[string]bool)
		for _, name := range names {
			if !validIngressName(name) || seen[name] {
				return fmt.Errorf("invalid or duplicate relay ingress interface %q", name)
			}
			seen[name] = true
		}
	}
	return nil
}

func (p *usedPorts) reserve(r route) {
	p.tcp[r.RelayTCP] = true
	p.udp.reserve(r.RelayUDP)
}

func (s state) match(r Request) (int, error) {
	index := -1
	for i, existing := range s.routes {
		if existing.overlaps(r) {
			if index >= 0 {
				return -1, errors.New("--to overlaps two existing relay routes")
			}
			index = i
		}
	}
	return index, nil
}

func (s *state) replace(r Request, host string, used *usedPorts) (int, error) {
	index, err := s.match(r)
	if err != nil {
		return -1, err
	}
	var old route
	for i, existing := range s.routes {
		if i == index {
			old = existing
		} else {
			used.reserve(existing)
		}
	}
	next, err := r.allocate(host, old, used)
	if err != nil {
		return -1, err
	}
	if index < 0 {
		index = len(s.routes)
		s.routes = append(s.routes, next)
	} else {
		s.routes[index] = next
	}
	return index, nil
}

func (s *state) remove(raw string) error {
	if raw == "" {
		s.routes = nil
		return nil
	}
	targets, err := parseTargets(raw)
	if err != nil {
		return err
	}
	index, err := s.match(targets)
	if err != nil {
		return err
	}
	if index < 0 {
		return fmt.Errorf("no relay route for %s", targets.targets())
	}
	s.routes = slices.Delete(s.routes, index, index+1)
	return nil
}
