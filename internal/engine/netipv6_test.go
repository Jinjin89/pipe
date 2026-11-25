// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestPublicIPv6(t *testing.T) {
	for address, want := range map[string]bool{
		"2408:8000::1": true, "2001:4860::8888": true,
		"fdfe:dcba:9876::1": false, // Pipe's TUN and other private addresses
		"fe80::1":           false, "::1": false, "::": false, "ff02::1": false,
		"2001:0:4136::1": false, "2002:c000:204::1": false, // Teredo, 6to4
		"::ffff:192.0.2.1": false, "192.0.2.1": false,
	} {
		if got := publicIPv6(netip.MustParseAddr(address)); got != want {
			t.Errorf("publicIPv6(%s) = %t, want %t", address, got, want)
		}
	}
}

func TestNetworkIPv6(t *testing.T) {
	readFailure := errors.New("route table unavailable")
	for _, test := range []struct {
		name       string
		routes     []int
		addresses  [][]string
		routeErr   error
		firstFlags net.Flags
		want       bool
	}{
		{
			name: "ULA with default route", routes: []int{1},
			addresses: [][]string{{"fd12:3456::1"}}, want: true,
		},
		{
			name: "public address with default route", routes: []int{1},
			addresses: [][]string{{"2408:8000::1"}}, want: true,
		},
		{
			name:      "public address without default route",
			addresses: [][]string{{"2408:8000::1"}},
		},
		{
			name: "route and public address on different interfaces", routes: []int{2},
			addresses: [][]string{{"2408:8000::1"}, {"fe80::1"}},
		},
		{
			name: "Pipe TUN IPv6 prefix", routes: []int{1},
			addresses: [][]string{{"2408:8000::1", "fdfe:dcba:9876::2"}, {"fd12:3456::1"}},
		},
		{
			name: "Pipe TUN IPv4 prefix", routes: []int{1},
			addresses: [][]string{{"2408:8000::1", "::ffff:172.19.0.1"}},
		},
		{
			name: "non-Pipe default route alongside Pipe TUN", routes: []int{1, 2},
			addresses: [][]string{{"fdfe:dcba:9876::1"}, {"fd12:3456::1"}}, want: true,
		},
		{
			name: "legacy tunnels", routes: []int{1},
			addresses: [][]string{{"2001:0:4136::1", "2002:c000:204::1"}},
		},
		{
			name: "no global or unique local address", routes: []int{1},
			addresses: [][]string{{"::", "::1", "ff02::1", "fe80::1", "fec0::1", "::ffff:192.0.2.1", "192.0.2.1"}},
		},
		{
			name: "loopback interface", routes: []int{1}, firstFlags: net.FlagLoopback,
			addresses: [][]string{{"2408:8000::1"}},
		},
		{
			name: "read failure accepts public address", routeErr: readFailure,
			addresses: [][]string{{"2408:8000::1"}}, want: true,
		},
		{
			name: "read failure keeps ULA excluded", routeErr: readFailure,
			addresses: [][]string{{"fd12:3456::1"}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			routes := make(map[int]struct{}, len(test.routes))
			for _, index := range test.routes {
				routes[index] = struct{}{}
			}
			interfaces := make([]net.Interface, len(test.addresses))
			for i := range interfaces {
				interfaces[i] = net.Interface{Index: i + 1, Flags: net.FlagUp}
			}
			interfaces[0].Flags |= test.firstFlags
			listInterfaces := func() ([]net.Interface, error) { return interfaces, nil }
			listAddrs := func(iface *net.Interface) ([]net.Addr, error) {
				var addresses []net.Addr
				for _, address := range test.addresses[iface.Index-1] {
					ip := netip.MustParseAddr(address)
					addresses = append(addresses, &net.IPNet{IP: net.IP(ip.AsSlice())})
				}
				return addresses, nil
			}
			if got := networkIPv6(routes, test.routeErr, listInterfaces, listAddrs); got != test.want {
				t.Fatalf("networkIPv6() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestNetworkIPv6ReadsLocalState(t *testing.T) {
	NetworkIPv6()
}
