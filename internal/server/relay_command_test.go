// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestRelayCommand(t *testing.T) {
	shared := Settings{
		Mode: Shared, Domain: "origin.example.net", RealityDest: realitySelf,
		Ports: Ports{Stealth: 8443, Fast: 443}, FastHop: "25000-25003",
		HTTPSProxyListener: &httpsProxyListenerConfig{Port: 9443},
		RealityPrivateKey:  "secret", WSPath: "/ws/private-path",
	}
	for _, test := range []struct {
		name, domain, lookupNetwork string
		local, dns                  []string
		mode                        DeployMode
		fastPort                    uint16
		noStealth                   bool
		want, hint                  string
	}{
		{
			name: "interface preferred", local: []string{"10.1.2.3", "93.184.216.34", "2606:4700::1234"},
			want: "pipe relay add --to 93.184.216.34,2606:4700::1234 --tcp 8443 --udp 443,25000-25003",
			hint: "active server interfaces",
		},
		{
			name: "Fast base above hop range", local: []string{"93.184.216.34"}, lookupNetwork: "ip6", fastPort: 25004,
			want: "pipe relay add --to 93.184.216.34 --tcp 8443 --udp 25004,25000-25003",
			hint: "active server interfaces",
		},
		{
			name: "DNS fallback", lookupNetwork: "ip", local: []string{"127.0.0.1"}, dns: []string{"192.0.2.12", "2606:4700::1234"},
			want: "pipe relay add --to 2606:4700::1234 --tcp 8443 --udp 443,25000-25003",
			hint: "A and AAAA records",
		},
		{
			name: "missing IPv4 from DNS", lookupNetwork: "ip4", local: []string{"10.1.2.3", "2606:4700::1234"}, dns: []string{"93.184.216.34", "2606:4700::5678"},
			want: "pipe relay add --to 93.184.216.34,2606:4700::1234 --tcp 8443 --udp 443,25000-25003",
			hint: "active server interfaces and the server name's A records",
		},
		{
			name: "missing IPv6 from DNS", lookupNetwork: "ip6", local: []string{"93.184.216.34"}, dns: []string{"2606:4700::1234"},
			want: "pipe relay add --to 93.184.216.34,2606:4700::1234 --tcp 8443 --udp 443,25000-25003",
			hint: "active server interfaces and the server name's AAAA records",
		},
		{
			name: "missing IPv4 from literal", domain: "93.184.216.34", local: []string{"2606:4700::1234"},
			want: "pipe relay add --to 93.184.216.34,2606:4700::1234 --tcp 8443 --udp 443,25000-25003",
			hint: "active server interfaces and the configured server IP",
		},
		{
			name: "no public address", lookupNetwork: "ip", dns: []string{"169.254.169.254", "2001:db8::1"},
			hint: "No public server address",
		},
		{
			name: "standalone Stealth only", mode: Standalone, lookupNetwork: "ip6", local: []string{"93.184.216.34"},
			want: "pipe relay add --to 93.184.216.34 --tcp 8443",
			hint: "active server interfaces",
		},
		{
			name: "shared Fast only", noStealth: true, lookupNetwork: "ip6", local: []string{"93.184.216.34"},
			want: "pipe relay add --to 93.184.216.34 --udp 443,25000-25003",
			hint: "active server interfaces",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			parse := func(raw []string) []netip.Addr {
				var addresses []netip.Addr
				for _, ip := range raw {
					addresses = append(addresses, netip.MustParseAddr(ip))
				}
				return addresses
			}
			settings := shared
			if test.domain != "" {
				settings.Domain = test.domain
			}
			if test.mode != "" {
				settings.Mode = test.mode
			}
			if test.fastPort != 0 {
				settings.Ports.Fast = test.fastPort
			}
			if test.noStealth {
				settings.HTTPSProxyListener = nil
			}
			local := func() ([]netip.Addr, error) { return parse(test.local), nil }
			lookedUp := false
			lookup := func(_ context.Context, network, name string) ([]netip.Addr, error) {
				if lookedUp || test.lookupNetwork == "" || network != test.lookupNetwork || name != settings.Domain {
					t.Fatalf("unexpected DNS lookup %q %q", network, name)
				}
				lookedUp = true
				return parse(test.dns), nil
			}
			line, hint, err := relayCommand(t.Context(), settings, local, lookup)
			if err != nil || line != test.want || !strings.Contains(hint, test.hint) {
				t.Fatalf("relayCommand() = %q, %q, %v, want %q and hint containing %q", line, hint, err, test.want, test.hint)
			}
			if lookedUp != (test.lookupNetwork != "") {
				t.Fatalf("lookup called = %v, want %v", lookedUp, test.lookupNetwork != "")
			}
		})
	}
}
