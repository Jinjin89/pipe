// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"runtime"
	"slices"
	"strings"

	"pipe/internal/engine"
	"pipe/internal/failover"
	"pipe/internal/link"
)

const (
	DefaultListen      = "127.0.0.1:7890"
	privateLocalDNS    = "private-local"
	domesticDoH        = "domestic-doh"
	domesticDoHIPv6    = "domestic-doh-v6"
	proxyBootstrapDoH  = "proxy-bootstrap-doh"
	bootstrapBackupDoH = "bootstrap-backup-doh"
	bootstrapBackupV6  = "bootstrap-backup-doh-v6"
	// The pinned uTLS Chrome profile uses Chrome 133.
	chromeDesktopUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
)

type ClientOptions struct {
	Preferences
	Profile     *link.Profile
	Relay       string // optional relay code
	Listen      string
	SystemProxy bool
	Tier        failover.Tier
	Mobile      bool
	// TUNListen adds the loopback mixed inbound on Listen next to the TUN
	// inbound (APP_DESIGN §8.4). It has no effect without TUN or with Mobile.
	TUNListen bool
	// TUNIPv6 gives the TUN an IPv6 address and routes. Set it when the
	// network has IPv6, so no IPv6 traffic can go around Pipe. Leave it off
	// on IPv4-only networks: a TUN accepts every TCP handshake itself, so an
	// IPv6 route it can't serve leaves apps "connected, then reset" instead
	// of falling back to IPv4.
	TUNIPv6       bool
	LogLevel      string // warn (default), info or debug
	TestAddress   netip.Addr
	TestCAFile    string
	TestHosts     map[string]netip.Addr
	LANDNSServers func() []netip.AddrPort
}

func BuildClient(options ClientOptions) (engine.Options, error) {
	var result engine.Options
	if !ValidMode(options.Mode) {
		return result, errors.New("mode must be smart, global or direct")
	}
	if options.TUN && options.SystemProxy {
		return result, errors.New("--tun and --system-proxy are mutually exclusive")
	}
	var inbound engine.Object
	var extra []engine.Object
	if options.TUN {
		stack := "mixed"
		if options.Mobile || runtime.GOOS == "android" {
			stack = "gvisor"
		}
		address := []string{"172.19.0.1/30"}
		if options.TUNIPv6 {
			address = append(address, "fdfe:dcba:9876::1/126")
		}
		inbound = engine.Object{
			"type": "tun", "tag": "tun-in", "address": address,
			"auto_route": true, "strict_route": true, "stack": stack, "dns_mode": "hijack",
		}
		if options.Mobile {
			inbound["mtu"] = 9000
		}
	}
	if !options.TUN || (options.TUNListen && !options.Mobile) {
		if options.Listen == "" {
			options.Listen = DefaultListen
		}
		listen, err := netip.ParseAddrPort(options.Listen)
		if err != nil || !listen.Addr().IsLoopback() || listen.Port() == 0 {
			return result, errors.New("--listen requires a loopback IP address and a nonzero port")
		}
		mixed := engine.Object{
			"type": "mixed", "tag": "mixed-in", "listen": listen.Addr().String(), "listen_port": listen.Port(),
			"set_system_proxy": options.SystemProxy,
		}
		if options.TUN {
			extra = append(extra, mixed)
		} else {
			inbound = mixed
		}
	}
	if options.Profile == nil && (options.Mode != Direct || needsProxy(options.Rules)) {
		return result, errors.New("a server profile is required for proxy routing")
	}
	if options.TestAddress.IsValid() && (options.TestCAFile == "" ||
		(!options.TestAddress.IsLoopback() && !options.TestAddress.IsPrivate())) {
		return result, errors.New("--test-address requires --test-ca and a loopback or private IP address")
	}
	if len(options.TestHosts) != 0 && options.TestCAFile == "" {
		return result, errors.New("--test-hosts requires --test-ca")
	}
	if options.Tier == "" {
		options.Tier = failover.Auto
	}
	if options.Tier != failover.Auto && (options.Profile == nil || !slices.Contains(failover.Available(options.Profile.CDN != ""), options.Tier)) {
		return result, fmt.Errorf("tier %q is unavailable", options.Tier)
	}
	if options.Relay != "" && options.Profile == nil {
		return result, errors.New("a server profile is required for a relay")
	}
	outbounds := []engine.Object{
		{"type": "direct", "tag": "direct", "domain_resolver": resolver(domesticDoH, options.IPv6)},
		{"type": "direct", "tag": "lan", "domain_resolver": resolver(privateLocalDNS, options.IPv6)},
		{"type": "block", "tag": "block"},
	}
	var relay engine.Relay
	if options.Profile != nil {
		tiers, compiledRelay, err := tierOutbounds(options)
		if err != nil {
			return result, err
		}
		outbounds = append(outbounds, tiers...)
		outbounds = append(outbounds, proxySelector(tiers, options.Tier))
		relay = compiledRelay
	}
	logLevel := options.LogLevel
	switch logLevel {
	case "":
		logLevel = "warn"
	case "warn", "info", "debug":
	default:
		return result, errors.New("log level must be warn, info or debug")
	}
	result.Config = engine.Object{
		"log":       engine.Object{"level": logLevel, "output": "stderr"},
		"inbounds":  append([]engine.Object{inbound}, extra...),
		"outbounds": outbounds,
		"dns":       clientDNS(options, relay),
		"route":     clientRoute(options),
	}
	result.LANDNSServers = options.LANDNSServers
	result.Relay = relay
	result.RuleSets = []string{"geosite-private", "geosite-cn"}
	if options.Mode == Smart {
		result.RuleSets = append(result.RuleSets, "geosite-geolocation-!cn", "geoip-cn")
	}
	return result, nil
}

func needsProxy(rules []Rule) bool {
	return slices.ContainsFunc(rules, func(r Rule) bool { return r.Action == "proxy" })
}

func tierOutbounds(options ClientOptions) ([]engine.Object, engine.Relay, error) {
	p := *options.Profile
	var code Relay
	if options.Relay != "" {
		parsed, err := ParseRelay(options.Relay, p.Host)
		if err != nil {
			return nil, engine.Relay{}, err
		}
		code = parsed
	}
	relay, err := relayForProfile(code, p)
	if err != nil {
		return nil, engine.Relay{}, err
	}
	keys := link.Derive(p.Seed)
	origin, cdn, cdnPort := p.Host, p.CDN, uint16(link.DefaultPort)
	if options.TestAddress.IsValid() {
		origin, cdn, cdnPort = options.TestAddress.String(), options.TestAddress.String(), p.ServerPort()
	}
	// Hysteria2 requires the native QUIC TLS config, which uTLS cannot export.
	fastTLS := clientTLS(p.FastServerName(), options.TestCAFile)
	if p.FastPin != "" {
		// Parse has already checked the strict base64url form. JSON encodes
		// byte slices as standard base64, as required by sing-box.
		pin, _ := link.DecodeKey(p.FastPin)
		fastTLS["certificate_public_key_sha256"] = [][]byte{pin[:]}
		delete(fastTLS, "certificate_path")
	}
	stealthTLS := chromeTLS(p.StealthServerName(), options.TestCAFile)
	stealthTLS["reality"] = engine.Object{"enabled": true, "public_key": link.EncodeKey(p.PublicKey), "short_id": keys.RealitySID}
	fast := engine.Object{
		"type": "hysteria2", "tag": "fast", "server": origin, "server_port": p.FastEndpointPort(),
		"password": keys.HY2Password, "bbr_profile": "standard", "tls": fastTLS,
	}
	if p.FastHop != "" {
		fast["server_ports"] = []string{strings.Replace(p.FastHop, "-", ":", 1)}
		fast["hop_interval"] = "30s"
	}
	outbounds := []engine.Object{
		fast,
		{
			"type": "vless", "tag": "stealth", "server": origin, "server_port": p.StealthEndpointPort(),
			"uuid": keys.VLESSUUID, "flow": "xtls-rprx-vision", "tls": stealthTLS,
		},
	}
	if p.CDN != "" {
		path := p.WSPath
		if path == "" {
			path = "/"
		}
		outbounds = append(outbounds, engine.Object{
			"type": "vmess", "tag": "rescue", "server": cdn, "server_port": cdnPort,
			"uuid": keys.VMessUUID, "security": "chacha20-poly1305", "alter_id": 0, "tls": chromeTLS(p.CDN, options.TestCAFile),
			"transport": engine.Object{
				"type": "ws", "path": path, "headers": engine.Object{"Host": p.CDN, "User-Agent": chromeDesktopUA},
				"max_early_data": engine.WebSocketEarlyDataLimit, "early_data_header_name": engine.WebSocketEarlyDataHeader,
			},
		})
	}
	hasRelayName := link.ValidDNSName(relay.Host)
	for _, outbound := range outbounds {
		_, err := netip.ParseAddr(outbound["server"].(string))
		if err != nil || (hasRelayName && slices.Contains(relay.Tags, outbound["tag"].(string))) {
			bootstrap := resolver(proxyBootstrapDoH, options.IPv6)
			// The bootstrap transport owns its positive and last-good cache.
			bootstrap["disable_cache"] = true
			outbound["domain_resolver"] = bootstrap
		}
	}
	return outbounds, relay, nil
}

func proxySelector(tiers []engine.Object, tier failover.Tier) engine.Object {
	available := make([]string, 0, len(tiers))
	for _, outbound := range tiers {
		available = append(available, outbound["tag"].(string))
	}
	if tier == failover.Auto {
		tier = failover.Fast
	}
	return engine.Object{
		"type": "selector", "tag": "proxy", "outbounds": available, "default": tier, "interrupt_exist_connections": false,
	}
}

func relayForProfile(code Relay, profile link.Profile) (engine.Relay, error) {
	relay := engine.Relay{Host: code.Host}
	if code.Host == "" {
		return relay, nil
	}
	if code.bare() {
		code.StealthPort = profile.StealthEndpointPort()
		code.FastPort, code.FastHop = profile.FastEndpointPort(), profile.FastHop
	}
	if code.StealthPort != 0 {
		relay.StealthPort = code.StealthPort
		relay.Tags = append(relay.Tags, "stealth")
	}
	if profile.FastPin == "" {
		return relay, nil
	}
	relay.FastPort = code.FastPort
	if code.FastHop != "" {
		first, _, err := link.ParseHop(code.FastHop)
		if err != nil {
			return engine.Relay{}, err
		}
		relay.FastPort = first
		relay.FastPorts = strings.Replace(code.FastHop, "-", ":", 1)
	}
	if relay.FastPort != 0 {
		relay.Tags = append(relay.Tags, "fast")
	}
	return relay, nil
}

func chromeTLS(name, caFile string) engine.Object {
	options := clientTLS(name, caFile)
	options["utls"] = engine.Object{"enabled": true, "fingerprint": "chrome"}
	return options
}

func clientTLS(name, caFile string) engine.Object {
	options := engine.Object{"enabled": true, "server_name": name}
	if caFile != "" {
		options["certificate_path"] = caFile
	}
	return options
}

func resolver(server string, ipv6 bool) engine.Object {
	options := engine.Object{"server": server}
	if !ipv6 {
		options["strategy"] = "ipv4_only"
	}
	return options
}

func privateDomains() engine.Object {
	return engine.Object{"type": "logical", "mode": "or", "rules": []engine.Object{
		{"rule_set": "geosite-private"}, {"domain_suffix": []string{"local", "lan", "home.arpa"}},
	}}
}

func clientRoute(options ClientOptions) engine.Object {
	return clientRouteForOS(options, runtime.GOOS)
}

func clientRouteForOS(options ClientOptions, goos string) engine.Object {
	rules := []engine.Object{{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}, {"port": 53, "action": "hijack-dns"}}
	if len(options.TestHosts) != 0 {
		resolve := resolver(engine.TestHostsTag, options.IPv6)
		resolve["domain"] = slices.Sorted(maps.Keys(options.TestHosts))
		resolve["action"] = "resolve"
		rules = append(rules, resolve)
	}
	if options.LANDNSServers != nil && goos == "darwin" {
		rules = append(rules, engine.Object{"domain_suffix": "local", "server": "local-mdns", "action": "resolve"})
	}
	// LAN is always direct, ahead of user rules.
	private := privateDomains()
	private["outbound"] = "lan"
	rules = append(rules, private, engine.Object{"ip_is_private": true, "outbound": "lan"})
	firstIP := slices.IndexFunc(options.Rules, func(r Rule) bool { return r.Field == "ip_cidr" })
	for i, r := range options.Rules {
		if i == firstIP && options.TUN && options.Profile != nil {
			rules = append(rules, resolveForIPRules(options)...)
		}
		rules = append(rules, engine.Object{r.Field: r.Match, "outbound": r.Action})
	}
	if options.Mode == Smart {
		rules = append(rules,
			engine.Object{"rule_set": "geosite-cn", "outbound": "direct"},
			engine.Object{"rule_set": "geosite-geolocation-!cn", "outbound": "proxy"},
			engine.Object{"type": "logical", "mode": "and", "outbound": "direct", "rules": []engine.Object{
				{"ip_cidr": []string{"0.0.0.0/0", "::/0"}}, {"rule_set": "geoip-cn"},
			}},
		)
	}
	final := "proxy"
	if options.Mode == Direct {
		final = "direct"
	}
	return engine.Object{
		"rules": rules, "final": final, "auto_detect_interface": options.TUN || !options.TestAddress.IsValid(),
		"default_domain_resolver": resolver(domesticDoH, options.IPv6),
	}
}

// resolveForIPRules lets user IP rules see real addresses in TUN mode, where
// names arrive as fake IPs. It runs just before the first IP rule, so earlier
// rules never cause a lookup. Names Pipe sends direct use the domestic DNS,
// as their DNS answers always did; every other name is looked up through the
// tunnel and is never sent to a domestic resolver.
func resolveForIPRules(options ClientOptions) []engine.Object {
	var domestic []engine.Object
	if options.Mode == Smart {
		domestic = append(domestic, engine.Object{"rule_set": "geosite-cn"})
	}
	for _, r := range options.Rules {
		if r.Action == "direct" && r.Field != "ip_cidr" {
			domestic = append(domestic, engine.Object{r.Field: r.Match})
		}
	}
	// Both address families, even under the IPv4-only DNS default: the proxy
	// dials the name itself, so an IPv6-only name must not come back empty here.
	other := engine.Object{"server": "proxy-doh", "action": "resolve", "strategy": "prefer_ipv4"}
	if len(domestic) == 0 {
		return []engine.Object{other}
	}
	local := resolver(domesticDoH, options.IPv6)
	local["type"], local["mode"], local["rules"], local["action"] = "logical", "or", domestic, "resolve"
	other["type"], other["mode"], other["rules"], other["invert"] = "logical", "or", domestic, true
	return []engine.Object{local, other}
}

func clientDNS(options ClientOptions, relay engine.Relay) engine.Object {
	privateType := "local"
	if options.LANDNSServers != nil {
		privateType = engine.LANDNSType
	}
	servers := []engine.Object{
		{"type": privateType, "tag": privateLocalDNS},
		domesticDNS(false),
	}
	if options.LANDNSServers != nil && runtime.GOOS == "darwin" {
		servers = append(servers, engine.Object{"type": "local", "tag": "local-mdns"})
	}
	if options.IPv6 {
		servers = append(servers, domesticDNS(true))
	}
	if len(options.TestHosts) != 0 {
		servers = append(servers, engine.Object{"type": "hosts", "tag": engine.TestHostsTag, "predefined": options.TestHosts})
	}
	if options.Profile != nil {
		servers = append(servers, engine.Object{
			"type": "https", "tag": "proxy-doh", "server": "1.1.1.1", "detour": "proxy", "tls": clientTLS("cloudflare-dns.com", ""),
		})
	}
	servers = append(servers, proxyBootstrapServers(options, relay)...)
	final := "proxy-doh"
	if options.Mode == Direct {
		final = domesticDoH
	}
	var rules []engine.Object
	if !options.IPv6 {
		rules = append(rules, engine.Object{"query_type": "AAAA", "action": "predefined", "rcode": "NOERROR"})
	}
	if options.LANDNSServers != nil && runtime.GOOS == "darwin" {
		// mDNSResponder must handle .local multicast while private unicast names
		// use the physical network's DNS servers.
		rules = append(rules, engine.Object{"domain_suffix": "local", "server": "local-mdns"})
	}
	private := privateDomains()
	private["server"] = privateLocalDNS
	rules = append(rules, private)
	useFake := options.TUN && options.Profile != nil
	if useFake {
		servers = append(servers, engine.Object{
			"type": "fakeip", "tag": "fake-ip", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18",
		})
	}
	for _, rule := range options.Rules {
		if rule.Field == "ip_cidr" {
			continue
		}
		match := engine.Object{rule.Field: rule.Match}
		switch rule.Action {
		case "block":
			match["action"], match["rcode"] = "predefined", "NXDOMAIN"
		case "direct":
			if useFake {
				rules = append(rules, fakeIPRule(match), fakeIPHintRule(match))
			}
			match = engine.Object{rule.Field: rule.Match, "server": domesticDoH}
		case "proxy":
			if useFake {
				rules = append(rules, fakeIPRule(match), fakeIPHintRule(match))
			}
			// Keep the nested match in the preceding rule action-free.
			match = engine.Object{rule.Field: rule.Match, "server": "proxy-doh"}
		}
		rules = append(rules, match)
	}
	// In TUN mode every A/AAAA answer is a fake IP, domestic names included, so
	// apps never hold a real address: the engine picks the address family per
	// connection and falls back itself. Other query types follow the rules below.
	if useFake {
		rules = append(rules, fakeIPRule(nil), fakeIPHintRule(nil))
	}
	if options.Mode == Smart {
		rules = append(rules, engine.Object{"rule_set": "geosite-cn", "server": domesticDoH})
	}
	dns := engine.Object{"servers": servers, "rules": rules, "final": final, "reverse_mapping": true}
	if !options.IPv6 {
		dns["strategy"] = "ipv4_only"
	}
	return dns
}

func domesticDNS(ipv6 bool) engine.Object {
	tag, address := domesticDoH, "223.5.5.5"
	if ipv6 {
		tag, address = domesticDoHIPv6, "2400:3200::1"
	}
	return engine.Object{"type": "https", "tag": tag, "server": address, "tls": clientTLS("dns.alidns.com", "")}
}

func proxyBootstrapServers(options ClientOptions, relay engine.Relay) []engine.Object {
	hosts := proxyEndpointNames(options, relay)
	if len(hosts) == 0 {
		return nil
	}
	servers := []engine.Object{
		{"type": "https", "tag": bootstrapBackupDoH, "server": "1.1.1.1", "tls": clientTLS("cloudflare-dns.com", "")},
	}
	upstreams := []string{domesticDoH, bootstrapBackupDoH}
	if options.IPv6 {
		servers = append(servers, engine.Object{
			"type": "https", "tag": bootstrapBackupV6, "server": "2606:4700:4700::1111", "tls": clientTLS("cloudflare-dns.com", ""),
		})
		upstreams = append(upstreams, domesticDoHIPv6, bootstrapBackupV6)
	}
	return append(servers, engine.Object{"type": engine.BootstrapDNSType, "tag": proxyBootstrapDoH, "hosts": hosts, "upstreams": upstreams})
}

func proxyEndpointNames(options ClientOptions, relay engine.Relay) []string {
	var hosts []string
	if options.Profile != nil && !options.TestAddress.IsValid() {
		for _, host := range []string{options.Profile.Host, options.Profile.CDN} {
			if _, err := netip.ParseAddr(host); host != "" && err != nil {
				hosts = append(hosts, host)
			}
		}
	}
	if len(relay.Tags) != 0 && link.ValidDNSName(relay.Host) && !slices.ContainsFunc(hosts, func(host string) bool {
		return strings.EqualFold(host, relay.Host)
	}) {
		hosts = append(hosts, relay.Host)
	}
	return hosts
}

func fakeIPRule(match engine.Object) engine.Object {
	// A 1 s TTL keeps apps from holding fake IPs that a restarted or stopped
	// engine no longer knows (the default is 600 s).
	return engine.Object{
		"type": "logical", "mode": "and", "rules": fakeIPConditions([]string{"A", "AAAA"}, match),
		"server": "fake-ip", "rewrite_ttl": 1,
	}
}

func fakeIPHintRule(match engine.Object) engine.Object {
	// HTTPS and SVCB can carry real address hints that bypass the fake-IP table.
	return engine.Object{
		"type": "logical", "mode": "and", "rules": fakeIPConditions([]string{"HTTPS", "SVCB"}, match),
		"action": "predefined", "rcode": "NOERROR",
	}
}

func fakeIPConditions(queryTypes []string, match engine.Object) []engine.Object {
	exempt := engine.Object{
		"type": "logical", "mode": "or", "invert": true,
		"rules": []engine.Object{
			{"domain_suffix": []string{
				"in-addr.arpa", "ip6.arpa", "pool.ntp.org", "time.apple.com", "time.windows.com", "time.google.com",
				"connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients3.google.com", "captive.apple.com",
				"msftconnecttest.com", "msftncsi.com", "detectportal.firefox.com", "nmcheck.gnome.org", "connectivity-check.ubuntu.com",
			}},
			{"domain_regex": `(?i)(^|\.)(ntp|stun|turn)[0-9-]*(\.|$)`},
		},
	}
	conditions := []engine.Object{{"query_type": queryTypes}, exempt}
	if match != nil {
		conditions = append(conditions, match)
	}
	return conditions
}
