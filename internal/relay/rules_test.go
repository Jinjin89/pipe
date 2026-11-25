// SPDX-License-Identifier: GPL-3.0-or-later

package relay

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

func TestRelayRulesScope(t *testing.T) {
	first := testRoute(t, "93.184.216.34,2606:4700::1234", "8443", "443,25000-25003", "relay.example")
	second := testRoute(t, "8.8.4.4", "8443", "443,25000-25003", "relay.example")
	second.RelayTCP, second.RelayUDP = 8444, portRange{25004, 25007}
	s := state{ingress{IPv4: []string{"eth0"}, IPv6: []string{"eth1"}}, []route{first, second}}
	rules := ruleText(s, map[string]string{ipv4Forward: "0", ipv6Forward: "0"})
	for _, want := range []string{
		`type filter hook forward priority filter; policy accept;`,
		`type ipv4_addr; flags dynamic,timeout; timeout 2m; size 65536;`,
		`type ipv6_addr; flags dynamic,timeout; timeout 2m; size 65536;`,
		`iifname { "eth0" } meta nfproto ipv4 fib daddr type local ct status & dnat == 0 tcp dport 8443 ct state new update @tcp4_sources { ip saddr limit rate 200/second burst 1000 packets } counter dnat ip to 93.184.216.34:8443`,
		`iifname { "eth1" } meta nfproto ipv6 fib daddr type local ct status & dnat == 0 udp dport 25000-25003 ct state new update @udp6_sources { ip6 saddr limit rate 400/second burst 2000 packets } counter dnat ip6 to [2606:4700::1234]:443`,
		`udp dport 25004-25007 ct state new update @udp4_sources { ip saddr limit rate 400/second burst 2000 packets } counter dnat ip to 8.8.4.4:443`,
		`tcp dport 8443 ct state new counter drop`,
		`ct direction original ct status dnat ip daddr 8.8.4.4 tcp dport 8443 ct original proto-dst 8444 tcp flags & syn == syn tcp option maxseg size set rt mtu`,
		`ct direction reply ct status dnat ct state established ip6 saddr 2606:4700::1234 udp sport 443 ct original proto-dst 25000-25003 counter name route_1_udp accept`,
		`postrouting ct direction original ct status dnat ip daddr 8.8.4.4 udp dport 443 ct original proto-dst 25004-25007 counter masquerade`,
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("rules missing %q", want)
		}
	}
	for _, once := range []string{"add set inet pipe_relay tcp4_sources ", "add set inet pipe_relay udp4_sources ",
		"add counter inet pipe_relay route_2_tcp\n", "add chain inet pipe_relay pmtud4\n",
		"forward meta nfproto ipv4 counter drop\n"} {
		if count := strings.Count(rules, once); count != 1 {
			t.Errorf("got %d occurrences of %q, want 1", count, once)
		}
	}
	if strings.Index(rules, "forward meta nfproto ipv4 counter drop") <= strings.LastIndex(rules, "counter name route_2_udp accept") {
		t.Fatal("IPv4 drop precedes second route")
	}
}

func TestRelayForwardingGuardFollowsBaseline(t *testing.T) {
	r := testRoute(t, "93.184.216.34,2606:4700::1234", "8443", "", "relay.example")
	s := state{ingress{IPv4: []string{"eth0"}, IPv6: []string{"eth1"}}, []route{r}}
	for _, test := range []struct {
		ipv4, ipv6 string
		drops      []string
	}{
		{"1", "1", nil},
		{"0", "1", []string{"ipv4"}},
		{"1", "0", []string{"ipv6"}},
		{"0", "0", []string{"ipv4", "ipv6"}},
	} {
		rules := ruleText(s, map[string]string{ipv4Forward: test.ipv4, ipv6Forward: test.ipv6})
		var drops []string
		for line := range strings.SplitSeq(rules, "\n") {
			if strings.HasPrefix(line, "add rule inet pipe_relay forward ") && strings.HasSuffix(line, " drop") {
				prefix := "add rule inet pipe_relay forward meta nfproto "
				if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, " counter drop") {
					t.Fatalf("forward guard depends on interface or connection state %q", line)
				}
				drops = append(drops, strings.TrimSuffix(strings.TrimPrefix(line, prefix), " counter drop"))
			}
		}
		if !slices.Equal(drops, test.drops) {
			t.Errorf("subsequent drops with prior IPv4=%s and IPv6=%s = %v, want %v", test.ipv4, test.ipv6, drops, test.drops)
		}
		if strings.Contains(rules, "icmp code frag-needed") != (test.ipv4 == "0") ||
			strings.Contains(rules, "icmpv6 type packet-too-big") != (test.ipv6 == "0") {
			t.Errorf("PMTUD exceptions do not match guards with prior IPv4=%s and IPv6=%s", test.ipv4, test.ipv6)
		}
	}
}

func TestRelayRelatedPMTUDPrecedesDrop(t *testing.T) {
	r := testRoute(t, "93.184.216.34,2606:4700::1234", "8443", "443,25000-25003", "relay.example")
	s := state{ingress{IPv4: []string{"eth0"}, IPv6: []string{"eth1"}}, []route{r}}
	rules := ruleText(s, map[string]string{ipv4Forward: "0", ipv6Forward: "0"})
	const forward = "add rule inet pipe_relay forward "
	for _, family := range []struct {
		proto, chain, ip, target, interfaces, icmp string
	}{
		{"ipv4", "pmtud4", "ip", "93.184.216.34", `{ "eth0" }`, "icmp type destination-unreachable icmp code frag-needed"},
		{"ipv6", "pmtud6", "ip6", "2606:4700::1234", `{ "eth1" }`, "icmpv6 type packet-too-big"},
	} {
		jump := forward + family.icmp + " ct state related ct status dnat jump " + family.chain + "\n"
		guard := forward + "meta nfproto " + family.proto + " counter drop\n"
		if !strings.Contains(rules, jump+guard) {
			t.Errorf("missing PMTUD jump before %s guard\n%s", family.proto, jump)
		}
		chainRule := "add rule inet pipe_relay " + family.chain + " "
		for _, flow := range []struct{ protocol, ports, server string }{
			{"tcp", "8443", "8443"}, {"udp", "25000-25003", "443"},
		} {
			related := "ct protocol " + flow.protocol + " ct original proto-dst " +
				flow.ports + " ct reply " + family.ip + " saddr " + family.target + " ct reply proto-src " + flow.server + " counter accept\n"
			for _, want := range []string{
				chainRule + "iifname " + family.interfaces + " ct direction original " + family.ip + " daddr " + family.target + " " + related,
				chainRule + "oifname " + family.interfaces + " ct direction reply " + related,
			} {
				if !strings.Contains(rules, want) {
					t.Errorf("missing PMTUD rule\n%s", want)
				}
			}
		}
		if count := strings.Count(rules, chainRule); count != 4 {
			t.Errorf("got %d rules in %s, want 4", count, family.chain)
		}
	}
	if count := strings.Count(rules, "ct state related"); count != 2 {
		t.Errorf("got %d related-flow jumps, want 2", count)
	}
}

func TestRelaySavedAcceptRA(t *testing.T) {
	r := testRoute(t, "2606:4700::1234", "8443", "", "relay.example")
	previous := map[string]string{ipv6Forward: "0", raSysctl("eth0.100"): "1", raSysctl("eth1"): "1"}
	rules := ruleText(state{ingress{IPv6: []string{"eth1", "eth0.100"}}, []route{r}}, previous)
	if !strings.Contains(rules, `add set inet pipe_relay saved_accept_ra { type ifname; flags constant; elements = { "eth0.100", "eth1" }; }`) {
		t.Fatalf("rules missing saved RA interfaces\n%s", rules)
	}
	names, err := readRelayRA(`{"nftables":[{"set":{"name":"saved_accept_ra","elem":["eth0.100","eth1"]}}]}`)
	if err != nil || !slices.Equal(names, []string{"eth0.100", "eth1"}) {
		t.Fatalf("readRelayRA() = %v, %v", names, err)
	}
}

func TestRelayRulesSingleFamily(t *testing.T) {
	r := testRoute(t, "2606:4700::1234", "8443", "", "relay.example")
	rules := ruleText(state{ingress{IPv6: []string{"eth0"}}, []route{r}}, nil)
	if strings.Contains(rules, "ipv4") || strings.Contains(rules, "udp") || !strings.Contains(rules, "dnat ip6 to [2606:4700::1234]:8443") {
		t.Fatalf("unexpected address family or protocol\n%s", rules)
	}
}

func TestRelayTableKeepsForwardingBaseline(t *testing.T) {
	previous := map[string]string{ipv4Forward: "0", ipv6Forward: "1"}
	output := "table inet pipe_relay {\n\tcomment \"Pipe relay " + ipv4Forward + "=0 " + ipv6Forward + "=1\"\n}\n"
	got, owned := relayTableForwarding(output)
	if !owned || !maps.Equal(got, previous) {
		t.Fatalf("relayTableForwarding() = %v, %v", got, owned)
	}
}

func TestRelayRouteDevices(t *testing.T) {
	names, err := routeDevices(`[{"dev":"eth0"},{"nexthops":[{"dev":"eth1"},{"dev":"eth0"}]},{"dev":"lo"},{"type":"local","dev":"eth2"}]`)
	if err != nil || !slices.Equal(names, []string{"eth0", "eth1"}) {
		t.Fatalf("routeDevices() = %v, %v", names, err)
	}
}
