// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !ios

package engine

import (
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func ipv6DefaultInterfaces() (map[int]struct{}, error) {
	rib, err := route.FetchRIB(unix.AF_INET6, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	return darwinIPv6DefaultInterfaces(messages), nil
}

func darwinIPv6DefaultInterfaces(messages []route.Message) map[int]struct{} {
	interfaces := make(map[int]struct{})
	for _, message := range messages {
		r, ok := message.(*route.RouteMessage)
		if !ok || r.Err != nil || r.Index <= 0 || r.Flags&unix.RTF_UP == 0 ||
			r.Flags&(unix.RTF_HOST|unix.RTF_REJECT|unix.RTF_BLACKHOLE) != 0 || len(r.Addrs) <= unix.RTAX_DST {
			continue
		}
		destination, ok := r.Addrs[unix.RTAX_DST].(*route.Inet6Addr)
		if !ok || destination.IP != [16]byte{} {
			continue
		}
		if len(r.Addrs) > unix.RTAX_NETMASK && r.Addrs[unix.RTAX_NETMASK] != nil {
			mask, ok := r.Addrs[unix.RTAX_NETMASK].(*route.Inet6Addr)
			if !ok || mask.IP != [16]byte{} {
				continue
			}
		}
		interfaces[r.Index] = struct{}{}
	}
	return interfaces
}
