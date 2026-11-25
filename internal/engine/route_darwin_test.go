// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !ios

package engine

import (
	"maps"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestDarwinIPv6DefaultInterfaces(t *testing.T) {
	message := func(index, flags int, dst, mask route.Addr) route.Message {
		return &route.RouteMessage{
			Index: index, Flags: flags, Addrs: []route.Addr{unix.RTAX_DST: dst, unix.RTAX_NETMASK: mask},
		}
	}
	zero := &route.Inet6Addr{}
	up := unix.RTF_UP
	messages := []route.Message{
		message(2, up, zero, zero),
		message(3, up|unix.RTF_IFSCOPE, zero, nil),
		message(4, up, zero, &route.Inet6Addr{IP: [16]byte{0x80}}),
		message(5, up, &route.Inet4Addr{}, &route.Inet4Addr{}),
		message(6, up|unix.RTF_HOST, zero, nil),
		message(7, up|unix.RTF_REJECT, zero, zero),
		message(8, up|unix.RTF_BLACKHOLE, zero, zero),
		message(9, 0, zero, zero),
	}
	got := darwinIPv6DefaultInterfaces(messages)
	want := map[int]struct{}{2: {}, 3: {}}
	if !maps.Equal(got, want) {
		t.Fatalf("darwinIPv6DefaultInterfaces() = %v, want %v", got, want)
	}
}
