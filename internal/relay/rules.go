// SPDX-License-Identifier: GPL-3.0-or-later

package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

const tableName = "pipe_relay"
const tableComment = "Pipe relay"
const tableSpec = "inet " + tableName
const ipv4Forward = "net.ipv4.ip_forward"
const ipv6Forward = "net.ipv6.conf.all.forwarding"
const raSetName = "saved_accept_ra"
const raSysctlPrefix = "net/ipv6/conf/"
const raSysctlSuffix = "/accept_ra"

func validIngressName(name string) bool {
	switch name {
	case "", ".", "..", "lo", "all", "default":
		return false
	}
	// The name also appears in nft and sysctl file syntax.
	return len(name) < 16 && !strings.ContainsAny(name, "/:=*?[]\\#;\" \t\r\n\v\f\x00")
}

func raSysctl(name string) string {
	return raSysctlPrefix + name + raSysctlSuffix
}

func raInterface(key string) (string, bool) {
	if prefix, ok := strings.CutPrefix(key, raSysctlPrefix); ok {
		name, ok := strings.CutSuffix(prefix, raSysctlSuffix)
		if ok && validIngressName(name) {
			return name, true
		}
	}
	return "", false
}

func savedRAInterfaces(previous map[string]string) []string {
	var names []string
	for key, value := range previous {
		if name, ok := raInterface(key); ok && value == "1" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

type nftTable struct {
	Family   string `json:"family"`
	Name     string `json:"name"`
	Handle   uint64 `json:"handle"`
	previous map[string]string
}

func readRelayTable(output string) (nftTable, error) {
	var ruleset struct {
		Entries []struct {
			Table nftTable `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(output), &ruleset); err != nil {
		return nftTable{}, fmt.Errorf("read nftables tables: %w", err)
	}
	for _, entry := range ruleset.Entries {
		if entry.Table.Family == "inet" && entry.Table.Name == tableName {
			return entry.Table, nil
		}
	}
	return nftTable{}, nil
}

func relayTableForwarding(output string) (map[string]string, bool) {
	body, ok := strings.CutPrefix(strings.TrimSpace(output), "table "+tableSpec+" {\n")
	if !ok {
		return nil, false
	}
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "flags ") {
			continue
		}
		quoted, ok := strings.CutPrefix(strings.TrimSuffix(line, ";"), "comment ")
		if !ok {
			break
		}
		comment, err := strconv.Unquote(quoted)
		if err != nil {
			break
		}
		if comment == tableComment {
			return nil, true
		}
		saved, ok := strings.CutPrefix(comment, tableComment+" ")
		if !ok {
			break
		}
		values := make(map[string]string)
		for _, field := range strings.Fields(saved) {
			key, value, found := strings.Cut(field, "=")
			if !found || !validForwarding(key, value) || values[key] != "" {
				return nil, false
			}
			values[key] = value
		}
		return values, len(values) > 0
	}
	return nil, false
}

func validForwarding(key, value string) bool {
	return (key == ipv4Forward || key == ipv6Forward) && (value == "0" || value == "1")
}

func validPreviousSysctl(key, value string) bool {
	_, ra := raInterface(key)
	return validForwarding(key, value) || (ra && value == "1")
}

func readRelayRA(output string) ([]string, error) {
	var ruleset struct {
		Entries []struct {
			Set struct {
				Name  string   `json:"name"`
				Elems []string `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(output), &ruleset); err != nil {
		return nil, fmt.Errorf("read relay accept_ra state: %w", err)
	}
	for _, entry := range ruleset.Entries {
		if entry.Set.Name == raSetName {
			for _, name := range entry.Set.Elems {
				if !validIngressName(name) {
					return nil, fmt.Errorf("invalid saved relay interface %q", name)
				}
			}
			return entry.Set.Elems, nil
		}
	}
	return nil, errors.New("missing relay accept_ra state")
}

func replaceTable(handle uint64, rules string) string {
	if handle != 0 {
		// A handle cannot identify a different table recreated under our name.
		return fmt.Sprintf("delete table inet handle %d\n", handle) + rules
	}
	return rules
}

func counterName(index int, protocol string) string {
	return fmt.Sprintf("route_%d_%s", index+1, protocol)
}

func ruleText(s state, previous map[string]string) string {
	var out strings.Builder
	comment := tableComment
	for _, key := range []string{ipv4Forward, ipv6Forward} {
		if value := previous[key]; validForwarding(key, value) {
			comment += " " + key + "=" + value
		}
	}
	fmt.Fprintf(&out, "create table %s { comment %q; }\n", tableSpec, comment)
	if names := savedRAInterfaces(previous); len(names) != 0 {
		// Preserve the baseline even when the relay runs without /etc files.
		for i, name := range names {
			names[i] = strconv.Quote(name)
		}
		fmt.Fprintf(&out, "add set %s %s { type ifname; flags constant; elements = { %s }; }\n",
			tableSpec, raSetName, strings.Join(names, ", "))
	}
	for _, chain := range []struct{ name, typ, priority string }{
		{"prerouting", "nat", "dstnat + 1"},
		{"forward", "filter", "filter"},
		{"postrouting", "nat", "srcnat"},
	} {
		fmt.Fprintf(&out, "add chain %s %s { type %s hook %s priority %s; policy accept; }\n",
			tableSpec, chain.name, chain.typ, chain.name, chain.priority)
	}
	for i, r := range s.routes {
		if r.RelayTCP != 0 {
			fmt.Fprintf(&out, "add counter %s %s\n", tableSpec, counterName(i, "tcp"))
		}
		if r.RelayUDP.valid() {
			fmt.Fprintf(&out, "add counter %s %s\n", tableSpec, counterName(i, "udp"))
		}
	}
	for _, family := range []struct {
		ip, number string
		forwarding string
		interfaces []string
		pmtud      string
	}{
		{"ip", "4", ipv4Forward, s.IPv4, "icmp type destination-unreachable icmp code frag-needed"},
		{"ip6", "6", ipv6Forward, s.IPv6, "icmpv6 type packet-too-big"},
	} {
		if len(family.interfaces) == 0 {
			continue
		}
		names := make([]string, 0, len(family.interfaces))
		for _, name := range family.interfaces {
			names = append(names, strconv.Quote(name))
		}
		ifaces := "{ " + strings.Join(names, ", ") + " }"
		pmtudChain := ""
		if previous[family.forwarding] == "0" {
			// nft evaluates the outer ICMP protocol separately from the tracked TCP or UDP protocol.
			pmtudChain = "pmtud" + family.number
			fmt.Fprintf(&out, "add chain %s %s\n", tableSpec, pmtudChain)
		}
		meters := make(map[string]bool)
		for i, r := range s.routes {
			address := r.IPv4
			if family.ip == "ip6" {
				address = r.IPv6
			}
			if !address.IsValid() {
				continue
			}
			for _, flow := range []struct {
				protocol string
				server   uint16
				relay    portRange
				rate     int
				burst    int
			}{
				{"tcp", r.ServerTCP, single(r.RelayTCP), 200, 1000},
				{"udp", r.ServerUDP, r.RelayUDP, 400, 2000},
			} {
				if !flow.relay.valid() {
					continue
				}
				sources := flow.protocol + family.number + "_sources"
				if !meters[sources] {
					fmt.Fprintf(&out, "add set %s %s { type ipv%s_addr; flags dynamic,timeout; timeout 2m; size 65536; }\n",
						tableSpec, sources, family.number)
					meters[sources] = true
				}
				ports := flow.relay.String()
				local := fmt.Sprintf("iifname %s meta nfproto ipv%s fib daddr type local ct status & dnat == 0 %s dport %s ct state new",
					ifaces, family.number, flow.protocol, ports)
				fmt.Fprintf(&out, "add rule %s prerouting %s update @%s { %s saddr limit rate %d/second burst %d packets } counter dnat %s to %s\n",
					tableSpec, local, sources, family.ip, flow.rate, flow.burst, family.ip,
					netip.AddrPortFrom(address, flow.server))
				fmt.Fprintf(&out, "add rule %s prerouting %s counter drop\n", tableSpec, local)

				translated := fmt.Sprintf("ct direction original ct status dnat %s daddr %s %s dport %d ct original proto-dst %s",
					family.ip, address, flow.protocol, flow.server, ports)
				original := "iifname " + ifaces + " " + translated
				reply := fmt.Sprintf("oifname %s ct direction reply ct status dnat ct state established %s saddr %s %s sport %d ct original proto-dst %s",
					ifaces, family.ip, address, flow.protocol, flow.server, ports)
				counter := counterName(i, flow.protocol)
				for _, direction := range []string{original, reply} {
					if flow.protocol == "tcp" {
						fmt.Fprintf(&out, "add rule %s forward %s tcp flags & syn == syn tcp option maxseg size set rt mtu\n",
							tableSpec, direction)
					}
					fmt.Fprintf(&out, "add rule %s forward %s counter name %s accept\n", tableSpec, direction, counter)
				}
				if pmtudChain != "" {
					// The outer error can come from a router. Match the server tuple in conntrack.
					related := fmt.Sprintf("ct protocol %s ct original proto-dst %s ct reply %s saddr %s ct reply proto-src %d",
						flow.protocol, ports, family.ip, address, flow.server)
					fmt.Fprintf(&out, "add rule %s %s iifname %s ct direction original %s daddr %s %s counter accept\n",
						tableSpec, pmtudChain, ifaces, family.ip, address, related)
					fmt.Fprintf(&out, "add rule %s %s oifname %s ct direction reply %s counter accept\n",
						tableSpec, pmtudChain, ifaces, related)
				}
				fmt.Fprintf(&out, "add rule %s postrouting %s counter masquerade\n", tableSpec, translated)
			}
		}
		if pmtudChain != "" {
			fmt.Fprintf(&out, "add rule %s forward %s ct state related ct status dnat jump %s\n",
				tableSpec, family.pmtud, pmtudChain)
			fmt.Fprintf(&out, "add rule %s forward meta nfproto ipv%s counter drop\n", tableSpec, family.number)
		}
	}
	return out.String()
}

func routeDevices(output string) ([]string, error) {
	var routes []struct {
		Device   string `json:"dev"`
		Type     string `json:"type"`
		Nexthops []struct {
			Device string `json:"dev"`
		} `json:"nexthops"`
	}
	if err := json.Unmarshal([]byte(output), &routes); err != nil {
		return nil, fmt.Errorf("read route interfaces: %w", err)
	}
	var names []string
	add := func(name string) {
		if name != "" && name != "lo" {
			names = append(names, name)
		}
	}
	for _, route := range routes {
		if route.Type == "local" {
			continue
		}
		add(route.Device)
		for _, hop := range route.Nexthops {
			add(hop.Device)
		}
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}
