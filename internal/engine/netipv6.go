// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"net"
	"net/netip"
)

var (
	globalIPv6  = netip.MustParsePrefix("2000::/3")
	teredo      = netip.MustParsePrefix("2001::/32")
	sixToFour   = netip.MustParsePrefix("2002::/16")
	pipeTunIPv4 = netip.MustParsePrefix("172.19.0.0/30")
	pipeTunIPv6 = netip.MustParsePrefix("fdfe:dcba:9876::/126")
)

// NetworkIPv6 reports whether an interface outside Pipe's TUN has an IPv6
// default route and a global or unique local IPv6 address. It falls back to a
// public address check when the route table is unavailable. It sends nothing.
func NetworkIPv6() bool {
	routes, err := ipv6DefaultInterfaces()
	return networkIPv6(routes, err, net.Interfaces, (*net.Interface).Addrs)
}

func networkIPv6(routes map[int]struct{}, routeErr error, listInterfaces func() ([]net.Interface, error), listAddrs func(*net.Interface) ([]net.Addr, error)) bool {
	fallback := routeErr != nil
	if !fallback && len(routes) == 0 {
		return false
	}
	interfaces, err := listInterfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		_, routed := routes[iface.Index]
		if (!fallback && !routed) || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := listAddrs(&iface)
		if err == nil && interfaceHasIPv6(addresses, fallback) {
			return true
		}
	}
	return false
}

func interfaceHasIPv6(addresses []net.Addr, fallback bool) bool {
	usable := false
	for _, address := range addresses {
		prefix, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		ip, _ := netip.AddrFromSlice(prefix.IP)
		if fallback {
			if publicIPv6(ip) {
				return true
			}
			continue
		}
		if pipeTunIPv4.Contains(ip.Unmap()) || pipeTunIPv6.Contains(ip) {
			return false
		}
		usable = usable || unicastIPv6(ip) && (globalIPv6.Contains(ip) || ip.IsPrivate())
	}
	return usable
}

func publicIPv6(ip netip.Addr) bool {
	return unicastIPv6(ip) && !ip.IsPrivate()
}

func unicastIPv6(ip netip.Addr) bool {
	return ip.Is6() && !ip.Is4In6() && ip.IsGlobalUnicast() &&
		!teredo.Contains(ip) && !sixToFour.Contains(ip)
}
