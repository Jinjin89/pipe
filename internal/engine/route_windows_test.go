// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"maps"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsIPv6DefaultInterfaces(t *testing.T) {
	prefix := windows.IpAddressPrefix{Prefix: windows.RawSockaddrInet{Family: windows.AF_INET6}}
	nonDefault := prefix
	nonDefault.PrefixLength = 1
	ipv4 := prefix
	ipv4.Prefix.Family = windows.AF_INET
	rows := []windows.MibIpForwardRow2{
		{InterfaceLuid: 1, InterfaceIndex: 2, DestinationPrefix: prefix},
		{InterfaceLuid: 2, InterfaceIndex: 3, DestinationPrefix: prefix},
		{InterfaceLuid: 3, InterfaceIndex: 4, DestinationPrefix: nonDefault},
		{InterfaceLuid: 4, InterfaceIndex: 5, DestinationPrefix: ipv4},
		{InterfaceLuid: 5, InterfaceIndex: 6, DestinationPrefix: prefix, Loopback: 1},
	}
	adapters := []windows.IpAdapterAddresses{
		{Luid: 1, IfIndex: 7, Ipv6IfIndex: 2},
		{Luid: 2, Ipv6IfIndex: 3},
		{Luid: 3, Ipv6IfIndex: 4},
		{Luid: 4, Ipv6IfIndex: 5},
		{Luid: 5, Ipv6IfIndex: 6},
	}
	for i := range len(adapters) - 1 {
		adapters[i].Next = &adapters[i+1]
	}
	got := windowsIPv6RouteIndexes(windowsIPv6DefaultLUIDs(rows), &adapters[0])
	want := map[int]struct{}{7: {}, 3: {}}
	if !maps.Equal(got, want) {
		t.Fatalf("Windows IPv6 default-route indexes = %v, want %v", got, want)
	}
}
