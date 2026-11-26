// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !ios

package clientctl

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/sagernet/sing-tun"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Check for exact route conflicts because sing-tun otherwise replaces routes
// with the same prefix. Preserve existing routes and abort the rebuild.
func prepareTUNGuardRoutes(opts *tun.Options) error {
	ranges, err := opts.BuildAutoRouteRanges(false)
	if err != nil {
		return err
	}
	prefixes := make(map[netip.Prefix]bool, len(ranges))
	for _, prefix := range ranges {
		prefixes[prefix] = true
	}
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return err
	}
	for _, raw := range messages {
		entry, ok := raw.(*route.RouteMessage)
		if !ok || len(entry.Addrs) <= unix.RTAX_DST || entry.Flags&unix.RTF_IFSCOPE != 0 {
			continue
		}
		addr := routeAddress(entry.Addrs[unix.RTAX_DST])
		if !addr.IsValid() {
			continue
		}
		bits := addr.BitLen()
		if entry.Flags&unix.RTF_HOST == 0 {
			if len(entry.Addrs) <= unix.RTAX_NETMASK {
				continue
			}
			mask := routeAddress(entry.Addrs[unix.RTAX_NETMASK])
			var size int
			bits, size = net.IPMask(mask.AsSlice()).Size()
			if size != addr.BitLen() {
				continue
			}
		}
		prefix := netip.PrefixFrom(addr, bits).Masked()
		if prefixes[prefix] {
			return fmt.Errorf("a route already exists for %s", prefix)
		}
	}
	return nil
}

func routeAddress(addr route.Addr) netip.Addr {
	switch addr := addr.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(addr.IP)
	case *route.Inet6Addr:
		return netip.AddrFrom16(addr.IP)
	default:
		return netip.Addr{}
	}
}
