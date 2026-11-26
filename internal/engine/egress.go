// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const egressRefreshInterval = time.Second

// EgressPolicy excludes the server's own addresses from public forwarding.
type EgressPolicy struct {
	configured map[netip.Addr]struct{}
	interfaces func() ([]net.Addr, error)
	now        func() time.Time
	refresh    sync.Mutex
	local      atomic.Pointer[egressSnapshot]
}

type egressSnapshot struct {
	addresses map[netip.Addr]struct{} // nil if the loader failed
	until     time.Time
}

func NewEgressPolicy(configured ...netip.Addr) *EgressPolicy {
	addresses := make(map[netip.Addr]struct{}, len(configured))
	for _, addr := range configured {
		addresses[addr.Unmap()] = struct{}{}
	}
	return &EgressPolicy{configured: addresses, interfaces: net.InterfaceAddrs, now: time.Now}
}

var interfaceEgressPolicy = NewEgressPolicy()

func (p *EgressPolicy) withDefault() *EgressPolicy {
	if p == nil {
		return interfaceEgressPolicy
	}
	return p
}

// Invalidate expires the address snapshot when the interfaces change.
func (p *EgressPolicy) Invalidate() {
	p = p.withDefault()
	// A new pointer also prevents an in-flight enumeration from caching
	// a snapshot that began before this interface update.
	p.local.Store(&egressSnapshot{})
}

// Allows checks a numeric destination against a short-lived interface snapshot.
func (p *EgressPolicy) Allows(destination netip.Addr) bool {
	p = p.withDefault()
	return p.allows(destination, p.interfaceAddresses)
}

// AllowsFresh checks a numeric destination against the live interface addresses.
func (p *EgressPolicy) AllowsFresh(destination netip.Addr) bool {
	p = p.withDefault()
	return p.allows(destination, p.loadInterfaceAddresses)
}

// NewFreshCheck uses one current interface enumeration across a validation pass.
func (p *EgressPolicy) NewFreshCheck() func(netip.Addr) bool {
	return p.freshCheck()
}

// freshCheck uses one current interface enumeration per TCP dial, including
// dials with several DNS candidates.
func (p *EgressPolicy) freshCheck() func(netip.Addr) bool {
	p = p.withDefault()
	addresses := sync.OnceValue(p.loadInterfaceAddresses)
	return func(destination netip.Addr) bool {
		return p.allows(destination, addresses)
	}
}

func (p *EgressPolicy) allows(destination netip.Addr, interfaceAddresses func() map[netip.Addr]struct{}) bool {
	if !PublicDestination(destination) {
		return false
	}
	destination = destination.Unmap()
	var embedded netip.Addr
	if nat64WellKnownPrefix.Contains(destination) {
		bytes := destination.As16()
		embedded = netip.AddrFrom4([4]byte(bytes[12:]))
	}
	if containsEgressAddress(p.configured, destination, embedded) {
		return false
	}
	addresses := interfaceAddresses()
	return addresses != nil && !containsEgressAddress(addresses, destination, embedded)
}

func containsEgressAddress(addresses map[netip.Addr]struct{}, destination, embedded netip.Addr) bool {
	_, direct := addresses[destination]
	_, translated := addresses[embedded]
	return direct || embedded.IsValid() && translated
}

func (p *EgressPolicy) interfaceAddresses() map[netip.Addr]struct{} {
	if cached := p.local.Load(); cached != nil && p.now().Before(cached.until) {
		return cached.addresses
	}
	p.refresh.Lock()
	defer p.refresh.Unlock()
	cached := p.local.Load()
	if cached != nil && p.now().Before(cached.until) {
		return cached.addresses
	}
	addresses := p.loadInterfaceAddresses()
	if !p.local.CompareAndSwap(cached, &egressSnapshot{addresses: addresses, until: p.now().Add(egressRefreshInterval)}) {
		return nil
	}
	return addresses
}

func (p *EgressPolicy) loadInterfaceAddresses() map[netip.Addr]struct{} {
	addrs, err := p.interfaces()
	if err != nil {
		return nil
	}
	addresses := make(map[netip.Addr]struct{}, len(addrs))
	for _, addr := range addrs {
		var ip net.IP
		switch addr := addr.(type) {
		case *net.IPNet:
			ip = addr.IP
		case *net.IPAddr:
			ip = addr.IP
		}
		if host, ok := netip.AddrFromSlice(ip); ok {
			addresses[host.Unmap()] = struct{}{}
		}
	}
	return addresses
}

type egressPolicyKey struct{}

func WithEgressPolicy(ctx context.Context, policy *EgressPolicy) context.Context {
	return context.WithValue(ctx, egressPolicyKey{}, policy)
}

func egressPolicy(ctx context.Context) *EgressPolicy {
	policy, _ := ctx.Value(egressPolicyKey{}).(*EgressPolicy)
	return policy
}
