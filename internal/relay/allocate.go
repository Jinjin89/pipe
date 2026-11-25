// SPDX-License-Identifier: GPL-3.0-or-later

package relay

import "errors"

const (
	firstRelayPort = 8443
	firstHopPort   = 10000
	maxHopWidth    = 10000
	minShortHop    = 1000
	lastPort       = 65535
)

// Both IP families share allocations within each transport protocol.
type usedPorts struct {
	tcp, udp portSet
}

type portSet [lastPort + 1]bool

func (p *portSet) reserve(ports portRange) {
	for i := int(ports.First); i <= int(ports.Last); i++ {
		p[i] = true
	}
}

func (p *portSet) free(ports portRange) bool {
	if !ports.valid() {
		return false
	}
	for i := int(ports.First); i <= int(ports.Last); i++ {
		if p[i] {
			return false
		}
	}
	return true
}

func (p *portSet) allocateSingle(preferred uint16) uint16 {
	if preferred != 0 && !p[preferred] {
		return preferred
	}
	for i := firstRelayPort; i <= lastPort; i++ {
		if !p[i] {
			return uint16(i)
		}
	}
	return 0
}

func (p *portSet) allocateHop(preferred portRange) portRange {
	if p.free(preferred) {
		return preferred
	}
	width := min(int(preferred.Last)-int(preferred.First)+1, maxHopWidth)
	start := max(int(preferred.First), firstHopPort)
	order := func(first int) int {
		return (first - start + lastPort - firstHopPort + 1) % (lastPort - firstHopPort + 1)
	}
	var best, short portRange
	for i := firstHopPort; i <= lastPort; {
		if p[i] {
			i++
			continue
		}
		first := i
		for i <= lastPort && !p[i] {
			i++
		}
		length := i - first
		if length >= width {
			candidate := first
			if first < start && start+width <= i {
				candidate = start
			}
			if !best.valid() || order(candidate) < order(int(best.First)) {
				best = portRange{uint16(candidate), uint16(candidate + width - 1)}
			}
		} else if length >= minShortHop {
			shortWidth := int(short.Last) - int(short.First) + 1
			if !short.valid() || length > shortWidth ||
				length == shortWidth && order(first) < order(int(short.First)) {
				short = portRange{uint16(first), uint16(i - 1)}
			}
		}
	}
	if best.valid() {
		return best
	}
	return short
}

func (r Request) allocate(host string, old route, used *usedPorts) (route, error) {
	if host == "" && r.validHost(old.Host) {
		host = old.Host
	}
	next := route{Request: r, Host: host}
	if r.ServerTCP != 0 {
		next.RelayTCP = old.RelayTCP
		if next.RelayTCP == 0 || used.tcp[next.RelayTCP] {
			next.RelayTCP = used.tcp.allocateSingle(r.ServerTCP)
		}
		if next.RelayTCP == 0 {
			return route{}, errors.New("no free relay TCP port")
		}
	}
	if r.ServerUDP != 0 {
		oldFree := used.udp.free(old.RelayUDP)
		oldHop := old.RelayUDP.First < old.RelayUDP.Last
		wantHop := r.ServerHop.valid()
		if oldFree && oldHop == wantHop {
			next.RelayUDP = old.RelayUDP
		} else if wantHop {
			next.RelayUDP = used.udp.allocateHop(r.ServerHop)
		}
		if !next.RelayUDP.valid() {
			preferred := r.ServerUDP
			if oldFree && !oldHop {
				preferred = old.RelayUDP.First
			}
			next.RelayUDP = single(used.udp.allocateSingle(preferred))
		}
		if !next.RelayUDP.valid() {
			return route{}, errors.New("no free relay UDP port")
		}
	}
	return next, nil
}
