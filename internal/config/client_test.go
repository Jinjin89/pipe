// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"pipe/internal/engine"
	"pipe/internal/link"
)

func TestClientRelayEndpoints(t *testing.T) {
	const host = "relay.example"
	const hop = "20000-20005"
	pin := link.EncodeKey([32]byte{1})
	profile := link.Profile{Host: "origin.example", CDN: "cdn.example", FastPort: 3000, StealthPort: 4000}
	options := ClientOptions{Preferences: Defaults(), Profile: &profile}
	for _, tc := range []struct {
		name, code, pin, directHop string
		want                       engine.Relay
	}{
		{"disabled", "", pin, hop, engine.Relay{}},
		{"bare unpinned", host, "", hop, engine.Relay{Host: host, Tags: []string{"stealth"}, StealthPort: 4000}},
		{"bare pinned", host, pin, "", engine.Relay{Host: host, Tags: []string{"stealth", "fast"}, StealthPort: 4000, FastPort: 3000}},
		{"bare hopping", host, pin, hop, engine.Relay{Host: host, Tags: []string{"stealth", "fast"}, StealthPort: 4000, FastPort: 20000, FastPorts: "20000:20005"}},
		{"TCP only", host + ":8444", pin, hop, engine.Relay{Host: host, Tags: []string{"stealth"}, StealthPort: 8444}},
		{"UDP only", host + "/444", pin, hop, engine.Relay{Host: host, Tags: []string{"fast"}, FastPort: 444}},
		{"hop only", host + "/30000-30005", pin, "", engine.Relay{Host: host, Tags: []string{"fast"}, FastPort: 30000, FastPorts: "30000:30005"}},
		{"TCP and hop", host + ":8444/30000-30005", pin, hop, engine.Relay{Host: host, Tags: []string{"stealth", "fast"}, StealthPort: 8444, FastPort: 30000, FastPorts: "30000:30005"}},
		{"UDP only unpinned", host + "/444", "", hop, engine.Relay{Host: host}},
		{"TCP and hop unpinned", host + ":8444/30000-30005", "", "", engine.Relay{Host: host, Tags: []string{"stealth"}, StealthPort: 8444}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile.FastPin, profile.FastHop, options.Relay = tc.pin, tc.directHop, tc.code
			compiled, err := BuildClient(options)
			if err != nil {
				t.Fatal(err)
			}
			if got := compiled.Relay; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("relay %+v, want %+v", got, tc.want)
			}
			options.Relay = ""
			direct, err := BuildClient(options)
			if err != nil || !reflect.DeepEqual(compiled.Config["outbounds"], direct.Config["outbounds"]) {
				t.Fatalf("relay changed the origin ports or authentication: %v", err)
			}
		})
	}
	options.Relay = profile.Host + ":8444/444"
	if _, err := BuildClient(options); err == nil {
		t.Fatal("accepted the origin as its own relay")
	}
	options.Mode, options.Profile = Direct, nil
	if _, err := BuildClient(options); err == nil {
		t.Fatal("accepted a relay without a profile")
	}
}

func TestRelayBootstrapUsesProxyEndpointResolver(t *testing.T) {
	profile := link.Profile{
		Host: "origin.example", CDN: "cdn.example", FastPin: link.EncodeKey([32]byte{1}),
	}
	options := ClientOptions{Preferences: Defaults(), Profile: &profile, Relay: "relay.example:8444/30000-30005"}
	compiled, err := BuildClient(options)
	if err != nil {
		t.Fatal(err)
	}
	if hosts := clientDNSByTag(compiled)[proxyBootstrapDoH]["hosts"]; !reflect.DeepEqual(hosts, []string{"origin.example", "cdn.example", "relay.example"}) {
		t.Fatalf("bootstrap hosts %v", hosts)
	}

	options.TestAddress, options.TestCAFile = netip.MustParseAddr("127.0.0.1"), "ca.pem"
	options.IPv6 = false
	compiled, err = BuildClient(options)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := clientDNSByTag(compiled)[proxyBootstrapDoH]
	if !reflect.DeepEqual(bootstrap["hosts"], []string{"relay.example"}) ||
		!reflect.DeepEqual(bootstrap["upstreams"], []string{domesticDoH, bootstrapBackupDoH}) {
		t.Fatalf("bootstrap with an IPv4-only literal origin: %v", bootstrap)
	}
	outbounds := clientOutboundsByTag(compiled)
	for _, tier := range []string{"fast", "stealth"} {
		want := engine.Object{"server": proxyBootstrapDoH, "strategy": "ipv4_only", "disable_cache": true}
		if got := outbounds[tier]["domain_resolver"]; !reflect.DeepEqual(got, want) {
			t.Fatalf("%s bootstrap resolver %v, want %v", tier, got, want)
		}
	}
	if outbounds["rescue"]["domain_resolver"] != nil {
		t.Fatal("Rescue must not look up the relay")
	}

	options.Relay = "127.0.0.2:8444/444"
	compiled, err = BuildClient(options)
	if err != nil {
		t.Fatal(err)
	}
	if clientDNSByTag(compiled)[proxyBootstrapDoH] != nil {
		t.Fatal("literal relay must not need bootstrap DNS")
	}
}

func TestUnusedRelayDoesNotAddBootstrap(t *testing.T) {
	options := ClientOptions{
		Preferences: Defaults(), Profile: &link.Profile{Host: "origin.example"}, Relay: "relay.example/444",
	}
	compiled, err := BuildClient(options)
	if err != nil {
		t.Fatal(err)
	}
	if hosts := clientDNSByTag(compiled)[proxyBootstrapDoH]["hosts"]; !reflect.DeepEqual(hosts, []string{"origin.example"}) {
		t.Fatalf("bootstrap hosts %v", hosts)
	}

	options.TestAddress, options.TestCAFile = netip.MustParseAddr("127.0.0.1"), "ca.pem"
	compiled, err = BuildClient(options)
	if err != nil {
		t.Fatal(err)
	}
	if clientDNSByTag(compiled)[proxyBootstrapDoH] != nil {
		t.Fatal("an unused relay name created a bootstrap resolver")
	}
}

func TestRescueUsesExplicitPayloadEncryption(t *testing.T) {
	options, err := BuildClient(ClientOptions{
		Preferences: Defaults(), Profile: &link.Profile{Host: "origin.example", CDN: "cdn.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, outbound := range options.Config["outbounds"].([]engine.Object) {
		if outbound["tag"] == "rescue" {
			if outbound["security"] != "chacha20-poly1305" || outbound["alter_id"] != 0 {
				t.Fatalf("rescue must explicitly encrypt its VMess-AEAD payload, got %v", outbound["security"])
			}
			return
		}
	}
	t.Fatal("missing rescue outbound")
}

func TestSmartRouteKeepsProxyDestinationsUnresolved(t *testing.T) {
	options, err := BuildClient(ClientOptions{Preferences: Defaults(), Profile: &link.Profile{Host: "origin.example"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"geosite-cn", "geosite-geolocation-!cn", "geoip-cn"} {
		if !slices.Contains(options.RuleSets, name) {
			t.Errorf("missing rule set %q", name)
		}
	}
	route := options.Config["route"].(engine.Object)
	rules := route["rules"].([]engine.Object)
	for _, rule := range rules {
		if rule["action"] == "resolve" {
			t.Fatal("client routing may not resolve a proxy destination before transit")
		}
	}
	want := []engine.Object{
		{"rule_set": "geosite-cn", "outbound": "direct"},
		{"rule_set": "geosite-geolocation-!cn", "outbound": "proxy"},
		{"type": "logical", "mode": "and", "outbound": "direct", "rules": []engine.Object{
			{"ip_cidr": []string{"0.0.0.0/0", "::/0"}}, {"rule_set": "geoip-cn"},
		}},
	}
	if route["final"] != "proxy" || len(rules) < len(want) || !reflect.DeepEqual(rules[len(rules)-len(want):], want) {
		t.Fatal("expected CN and non-CN site rules, IP-only GeoIP, and proxy fallback")
	}
}

func TestClientTestHostsResolveOnlyMappedNames(t *testing.T) {
	const host = "cn.split.test"
	options := ClientOptions{
		Preferences: Defaults(),
		Profile:     &link.Profile{Host: "origin.example"},
		TestHosts:   map[string]netip.Addr{host: netip.MustParseAddr("11.0.0.80")},
	}
	if _, err := BuildClient(options); err == nil || err.Error() != "--test-hosts requires --test-ca" {
		t.Fatalf("BuildClient without test CA returned %v", err)
	}
	options.TestCAFile = "test-ca.pem"
	options.Rules = []Rule{{"domain", host, "direct"}}
	compiled, err := BuildClient(options)
	if err != nil {
		t.Fatal(err)
	}
	resolver := clientDNSByTag(compiled)[engine.TestHostsTag]
	if resolver["type"] != "hosts" || !reflect.DeepEqual(resolver["predefined"], options.TestHosts) {
		t.Fatalf("expected predefined test hosts, got %v", resolver)
	}
	rules := compiled.Config["route"].(engine.Object)["rules"].([]engine.Object)
	for i, rule := range rules {
		if rule["action"] == "resolve" {
			if rule["server"] != engine.TestHostsTag || !reflect.DeepEqual(rule["domain"], []string{host}) ||
				!slices.ContainsFunc(rules[i+1:], func(r engine.Object) bool {
					return reflect.DeepEqual(r, engine.Object{"domain": host, "outbound": "direct"})
				}) {
				t.Fatalf("expected the test mapping before its direct rule, got %v", rules)
			}
			return
		}
	}
	t.Fatal("missing test hosts resolve rule")
}

func TestProxyHostBootstrapUsesDirectDoH(t *testing.T) {
	preferences := Defaults()
	preferences.TUN = true
	options, err := BuildClient(ClientOptions{
		Preferences: preferences, Profile: &link.Profile{Host: "origin.example", CDN: "cdn.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	servers, outbounds := clientDNSByTag(options), clientOutboundsByTag(options)
	bootstrap := servers[proxyBootstrapDoH]
	if bootstrap["type"] != engine.BootstrapDNSType ||
		!reflect.DeepEqual(bootstrap["hosts"], []string{"origin.example", "cdn.example"}) ||
		!reflect.DeepEqual(bootstrap["upstreams"], []string{domesticDoH, bootstrapBackupDoH, domesticDoHIPv6, bootstrapBackupV6}) {
		t.Fatalf("unexpected bootstrap transport: %v", bootstrap)
	}
	for tag, want := range map[string]string{
		domesticDoH: "223.5.5.5", bootstrapBackupDoH: "1.1.1.1",
		domesticDoHIPv6: "2400:3200::1", bootstrapBackupV6: "2606:4700:4700::1111",
	} {
		server := servers[tag]
		if server["type"] != "https" || server["server"] != want || server["detour"] != nil || server["tls"].(engine.Object)["enabled"] != true {
			t.Fatalf("%s must dial %s directly with TLS: %v", tag, want, server)
		}
	}
	for tag, want := range map[string]string{domesticDoHIPv6: "dns.alidns.com", bootstrapBackupV6: "cloudflare-dns.com"} {
		if servers[tag]["tls"].(engine.Object)["server_name"] != want {
			t.Errorf("%s has the wrong TLS name: %v", tag, servers[tag]["tls"])
		}
	}
	for _, tier := range []string{"fast", "stealth", "rescue"} {
		resolver := outbounds[tier]["domain_resolver"].(engine.Object)
		if resolver["server"] != proxyBootstrapDoH || resolver["disable_cache"] != true {
			t.Errorf("%s must use the dedicated bootstrap cache: %v", tier, resolver)
		}
	}
	route := options.Config["route"].(engine.Object)
	if route["auto_detect_interface"] != true || route["default_domain_resolver"].(engine.Object)["server"] != domesticDoH {
		t.Fatal("outbound bootstrap must use the detected physical interface and an encrypted default resolver")
	}
	if servers[privateLocalDNS]["type"] != "local" || outbounds["lan"]["domain_resolver"].(engine.Object)["server"] != privateLocalDNS {
		t.Fatal("private LAN hostnames should still use the local resolver")
	}
	for _, r := range options.Config["dns"].(engine.Object)["rules"].([]engine.Object) {
		if r["server"] == privateLocalDNS {
			want := privateDomains()
			want["server"] = privateLocalDNS
			if !reflect.DeepEqual(r, want) {
				t.Fatalf("local DNS selected for a nonprivate rule: %v", r)
			}
		}
	}
}

func TestLANProviderRoutesPrivateNamesAndUsesPlatformMDNS(t *testing.T) {
	provider := func() []netip.AddrPort { return []netip.AddrPort{netip.MustParseAddrPort("192.168.1.1:53")} }
	preferences := Defaults()
	preferences.TUN = true
	compiled, err := BuildClient(ClientOptions{
		Preferences: preferences, Profile: &link.Profile{Host: "origin.example"},
		TUNIPv6: true, LANDNSServers: provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	if compiled.LANDNSServers == nil {
		t.Fatal("engine options dropped the LAN DNS provider")
	}
	servers := clientDNSByTag(compiled)
	if servers[privateLocalDNS]["type"] != engine.LANDNSType {
		t.Fatalf("private DNS transports: %v", servers)
	}
	rules := compiled.Config["dns"].(engine.Object)["rules"].([]engine.Object)
	private := privateDomains()
	private["server"] = privateLocalDNS
	if runtime.GOOS == "darwin" {
		if servers["local-mdns"]["type"] != "local" {
			t.Fatalf("macOS .local queries must use mDNSResponder: %v", servers)
		}
		want := []engine.Object{{"domain_suffix": "local", "server": "local-mdns"}, private}
		found := false
		for i := 0; i+1 < len(rules); i++ {
			if reflect.DeepEqual(rules[i:i+2], want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected .local mDNS before private LAN DNS rule: %v", rules)
		}
	} else {
		if servers["local-mdns"] != nil {
			t.Fatalf("platform without macOS mDNS must not use local DNS: %v", servers["local-mdns"])
		}
		if !slices.ContainsFunc(rules, func(rule engine.Object) bool { return reflect.DeepEqual(rule, private) }) {
			t.Fatalf("private names were not routed to LAN DNS: %v", rules)
		}
	}
}

func TestMacTUNMixedLocalNamesResolveThroughMDNS(t *testing.T) {
	config := clientRouteForOS(ClientOptions{
		LANDNSServers: func() []netip.AddrPort { return []netip.AddrPort{netip.MustParseAddrPort("192.168.1.1:53")} },
	}, "darwin")
	rules := config["rules"].([]engine.Object)
	resolve := engine.Object{"domain_suffix": "local", "server": "local-mdns", "action": "resolve"}
	private := privateDomains()
	private["outbound"] = "lan"
	resolveAt, privateAt := -1, -1
	for i, rule := range rules {
		if reflect.DeepEqual(rule, resolve) {
			resolveAt = i
		}
		if reflect.DeepEqual(rule, private) {
			privateAt = i
		}
	}
	if resolveAt < 0 || privateAt < 0 || resolveAt >= privateAt {
		t.Fatalf(".local must resolve through mDNS before LAN routing: %v", rules)
	}
}

func TestProxyBootstrapBypassesLiteralAddresses(t *testing.T) {
	for _, test := range []struct {
		name, host, cdn, originIP, cdnIP string
		address                          netip.Addr
	}{
		{"literal", "203.0.113.1", "2001:db8::1", "203.0.113.1", "2001:db8::1", netip.Addr{}},
		{"test address", "origin.example", "cdn.example", "127.0.0.1", "127.0.0.1", netip.MustParseAddr("127.0.0.1")},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, err := BuildClient(ClientOptions{
				Preferences: Defaults(), Profile: &link.Profile{Host: test.host, CDN: test.cdn, Port: 18443},
				TestAddress: test.address, TestCAFile: "test-ca.pem",
			})
			if err != nil {
				t.Fatal(err)
			}
			servers, outbounds := clientDNSByTag(options), clientOutboundsByTag(options)
			if servers[proxyBootstrapDoH] != nil || servers[bootstrapBackupDoH] != nil {
				t.Fatal("literal endpoints should not need bootstrap DNS transports")
			}
			for tag, ip := range map[string]string{"fast": test.originIP, "stealth": test.originIP, "rescue": test.cdnIP} {
				outbound := outbounds[tag]
				if outbound["server"] != ip || outbound["domain_resolver"] != nil {
					t.Errorf("%s did not dial the literal endpoint without a resolver", tag)
				}
			}
			rescue := outbounds["rescue"]
			if test.address.IsValid() && rescue["server_port"] != uint16(18443) {
				t.Fatal("Rescue should still use the configured test port")
			}
			if rescue["tls"].(engine.Object)["server_name"] != test.cdn {
				t.Fatal("address override changed the CDN TLS name")
			}
		})
	}
}

func TestProxyTLSFingerprintsAndRescueUserAgent(t *testing.T) {
	options, err := BuildClient(ClientOptions{
		Preferences: Defaults(), Profile: &link.Profile{Host: "origin.example", CDN: "cdn.example"}, TestCAFile: "test-ca.pem",
	})
	if err != nil {
		t.Fatal(err)
	}
	outbounds := clientOutboundsByTag(options)
	for _, tier := range []string{"fast", "stealth", "rescue"} {
		tlsOptions := outbounds[tier]["tls"].(engine.Object)
		if tlsOptions["certificate_path"] != "test-ca.pem" {
			t.Errorf("%s dropped the test CA", tier)
		}
		if tier == "fast" {
			if tlsOptions["utls"] != nil {
				t.Fatal("uTLS would break the native QUIC transport")
			}
			continue
		}
		if !reflect.DeepEqual(tlsOptions["utls"], engine.Object{"enabled": true, "fingerprint": "chrome"}) {
			t.Errorf("%s must use the Chrome uTLS profile", tier)
		}
	}
	headers := outbounds["rescue"]["transport"].(engine.Object)["headers"].(engine.Object)
	userAgent, _ := headers["User-Agent"].(string)
	if !strings.Contains(userAgent, "Chrome/133.0.0.0") || strings.Contains(userAgent, "Go-http-client") || headers["Host"] != "cdn.example" {
		t.Fatalf("invalid Rescue WebSocket headers: %v", headers)
	}
}

func TestSharedClientEndpointsUseIndependentPortsAndNames(t *testing.T) {
	pin := [32]byte{45, 67}
	profile := &link.Profile{
		Host: "origin.example", CDN: "static.website.example", CDNPort: 2053, FastPort: 14443, StealthPort: 8443,
		FastSNI: "fast.example", RealitySNI: "cover.example", FastPin: link.EncodeKey(pin), FastHop: "20000-40000",
	}
	options, err := BuildClient(ClientOptions{
		Preferences: Defaults(), Profile: profile, TestCAFile: "fixture-ca.pem",
		TestAddress: netip.MustParseAddr("10.83.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	out := clientOutboundsByTag(options)
	for tag, want := range map[string]struct {
		port uint16
		name string
	}{
		"fast": {14443, "fast.example"}, "stealth": {8443, "cover.example"}, "rescue": {2053, "static.website.example"},
	} {
		if out[tag]["server_port"] != want.port || out[tag]["tls"].(engine.Object)["server_name"] != want.name {
			t.Errorf("wrong %s endpoint", tag)
		}
	}
	rescue := out["rescue"]
	if rescue["server"] != "10.83.0.1" || rescue["transport"].(engine.Object)["headers"].(engine.Object)["Host"] != profile.CDN {
		t.Fatal("Rescue must dial the test address with the CDN hostname in the WebSocket Host header")
	}
	fast, fastTLS := out["fast"], out["fast"]["tls"].(engine.Object)
	if fastTLS["certificate_path"] != nil || !reflect.DeepEqual(fastTLS["certificate_public_key_sha256"], [][]byte{pin[:]}) {
		t.Fatal("Fast pin must replace the CA and use the standard binary JSON representation")
	}
	if !reflect.DeepEqual(fast["server_ports"], []string{"20000:40000"}) || fast["hop_interval"] != "30s" {
		t.Fatal("incorrect Fast port hopping configuration")
	}
}

func TestLiteralOriginUsesFastSNIForStealthByDefault(t *testing.T) {
	profile := &link.Profile{Host: "2001:db8::1", FastSNI: "origin.example"}
	options, err := BuildClient(ClientOptions{Preferences: Defaults(), Profile: profile})
	if err != nil {
		t.Fatal(err)
	}
	out := clientOutboundsByTag(options)
	stealth := out["stealth"]
	if stealth["server"] != profile.Host || stealth["tls"].(engine.Object)["server_name"] != profile.FastSNI {
		t.Fatal("Stealth did not use the DNS name configured for the literal origin")
	}
}

func clientDNSByTag(options engine.Options) map[string]engine.Object {
	return optionsByTag(options.Config["dns"].(engine.Object)["servers"].([]engine.Object))
}

func clientOutboundsByTag(options engine.Options) map[string]engine.Object {
	return optionsByTag(options.Config["outbounds"].([]engine.Object))
}

func optionsByTag(objects []engine.Object) map[string]engine.Object {
	result := make(map[string]engine.Object, len(objects))
	for _, object := range objects {
		result[object["tag"].(string)] = object
	}
	return result
}

func TestRuleRoundTrip(t *testing.T) {
	for _, text := range []string{
		"example.com -> proxy",
		"suffix:example.com -> direct",
		"keyword:ads -> block",
		"192.0.2.0/24 -> direct",
		"192.0.2.7 -> proxy",
		"2001:db8::/32 -> block",
		"app:com.example.app -> proxy",
		"process:curl -> direct",
		"process:/usr/bin/curl -> proxy",
	} {
		rule, err := ParseRule(text)
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		again, err := ParseRule(FormatRule(rule))
		if err != nil || again != rule {
			t.Errorf("%s: %q -> %+v, %v (want %+v)", text, FormatRule(rule), again, err, rule)
		}
	}
	if _, err := ParseRule("example.com -> maybe"); err == nil {
		t.Error("accepted a bad action")
	}
}

func TestClientLogLevel(t *testing.T) {
	for level, want := range map[string]string{"": "warn", "warn": "warn", "info": "info", "debug": "debug"} {
		options, err := BuildClient(ClientOptions{Preferences: Preferences{Mode: Direct}, LogLevel: level})
		if err != nil {
			t.Fatal(err)
		}
		if got := options.Config["log"].(engine.Object)["level"]; got != want {
			t.Errorf("level %q -> %v, want %v", level, got, want)
		}
	}
	if _, err := BuildClient(ClientOptions{Preferences: Preferences{Mode: Direct}, LogLevel: "trace"}); err == nil {
		t.Error("accepted trace")
	}
}

func TestLANRulesPrecedeUserRules(t *testing.T) {
	compiled, err := BuildClient(ClientOptions{
		Preferences: Preferences{Mode: Global, Rules: []Rule{{"domain", "example.com", "proxy"}}},
		Profile:     &link.Profile{Host: "origin.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rules := compiled.Config["route"].(engine.Object)["rules"].([]engine.Object)
	private, user := -1, -1
	for i, r := range rules {
		if r["ip_is_private"] == true {
			private = i
		}
		if r["domain"] == "example.com" {
			user = i
		}
	}
	if private < 0 || user < 0 || private > user {
		t.Fatalf("LAN rule at %d, user rule at %d", private, user)
	}
}

func TestTUNListenAddsLoopbackMixedInbound(t *testing.T) {
	build := func(o ClientOptions) map[string]engine.Object {
		o.Preferences = Defaults()
		o.TUN = true
		o.Profile = &link.Profile{Host: "origin.example"}
		options, err := BuildClient(o)
		if err != nil {
			t.Fatal(err)
		}
		return optionsByTag(options.Config["inbounds"].([]engine.Object))
	}
	both := build(ClientOptions{TUNListen: true, Listen: "127.0.0.1:7999"})
	tun, mixed := both["tun-in"], both["mixed-in"]
	if tun == nil || mixed == nil {
		t.Fatalf("want both inbounds, got %v", both)
	}
	if tun["dns_mode"] != "hijack" || mixed["dns_mode"] != nil {
		t.Fatalf("DNS hijack must stay on the TUN inbound only: %v %v", tun, mixed)
	}
	if mixed["listen"] != "127.0.0.1" || mixed["listen_port"] != uint16(7999) || mixed["set_system_proxy"] != false {
		t.Fatalf("unexpected mixed inbound: %v", mixed)
	}
	if one := build(ClientOptions{}); one["mixed-in"] != nil || one["tun-in"] == nil {
		t.Fatalf("plain TUN must stay TUN only: %v", one)
	}
	if one := build(ClientOptions{TUNListen: true, Mobile: true}); one["mixed-in"] != nil {
		t.Fatalf("Mobile must not get the mixed inbound: %v", one)
	}
	preferences := Defaults()
	preferences.TUN = true
	_, err := BuildClient(ClientOptions{Preferences: preferences, TUNListen: true, Listen: "0.0.0.0:7890",
		Profile: &link.Profile{Host: "origin.example"}})
	if err == nil {
		t.Fatal("TUNListen must validate the listen address as loopback")
	}
}

func TestTUNAddressFollowsTUNIPv6(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		for _, ipv6 := range []bool{false, true} {
			prefs := Defaults()
			prefs.TUN = true
			prefs.IPv6 = !ipv6 // the preference alone doesn't decide
			compiled, err := BuildClient(ClientOptions{
				Preferences: prefs, Mobile: mobile, TUNIPv6: ipv6, Profile: &link.Profile{Host: "origin.example"},
			})
			if err != nil {
				t.Fatalf("mobile=%t ipv6=%t: %v", mobile, ipv6, err)
			}
			tun := optionsByTag(compiled.Config["inbounds"].([]engine.Object))["tun-in"]
			addrs := tun["address"].([]string)
			want := []string{"172.19.0.1/30"}
			if ipv6 {
				want = append(want, "fdfe:dcba:9876::1/126")
			}
			if !slices.Equal(addrs, want) {
				t.Errorf("mobile=%t ipv6=%t: TUN addresses = %v, want %v", mobile, ipv6, addrs, want)
			}
		}
	}
}

func TestTUNFakeIPDNSRules(t *testing.T) {
	prefs := Defaults()
	prefs.Mode = Smart
	prefs.TUN = true
	prefs.Rules = []Rule{{Field: "domain_suffix", Match: "direct.example", Action: "direct"}}
	compiled, err := BuildClient(ClientOptions{
		Preferences: prefs, Profile: &link.Profile{Host: "origin.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rules := compiled.Config["dns"].(engine.Object)["rules"].([]engine.Object)
	wantDirectFake := fakeIPRule(engine.Object{"domain_suffix": "direct.example"})
	wantDirectHints := fakeIPHintRule(engine.Object{"domain_suffix": "direct.example"})
	wantDirectDNS := engine.Object{"domain_suffix": "direct.example", "server": domesticDoH}
	wantAllFake := fakeIPRule(nil)
	wantAllHints := fakeIPHintRule(nil)
	wantCN := engine.Object{"rule_set": "geosite-cn", "server": domesticDoH}

	directFakeIdx, directHintsIdx, directDNSIdx := -1, -1, -1
	allFakeIdx, allHintsIdx, cnIdx := -1, -1, -1
	for i, r := range rules {
		switch {
		case reflect.DeepEqual(r, wantDirectFake):
			directFakeIdx = i
		case reflect.DeepEqual(r, wantDirectHints):
			directHintsIdx = i
		case reflect.DeepEqual(r, wantDirectDNS):
			directDNSIdx = i
		case reflect.DeepEqual(r, wantAllFake):
			allFakeIdx = i
		case reflect.DeepEqual(r, wantAllHints):
			allHintsIdx = i
		case reflect.DeepEqual(r, wantCN):
			cnIdx = i
		}
	}
	if directFakeIdx < 0 || directHintsIdx != directFakeIdx+1 || directDNSIdx <= directHintsIdx {
		t.Fatalf("direct user rules must fake A/AAAA, empty HTTPS/SVCB, then use domestic DoH (fake=%d, hints=%d, doh=%d)", directFakeIdx, directHintsIdx, directDNSIdx)
	}
	if allFakeIdx < 0 || allHintsIdx != allFakeIdx+1 || cnIdx <= allHintsIdx {
		t.Fatalf("catch-all fake-IP rules must precede geosite-cn (fake=%d, hints=%d, cn=%d)", allFakeIdx, allHintsIdx, cnIdx)
	}
}

func TestIPv4OnlyDNSStripsIPv6HintsAndOmitsIPv6Bootstrap(t *testing.T) {
	prefs := Defaults()
	prefs.IPv6 = false
	compiled, err := BuildClient(ClientOptions{Preferences: prefs, Profile: &link.Profile{Host: "origin.example"}})
	if err != nil {
		t.Fatal(err)
	}
	dns := compiled.Config["dns"].(engine.Object)
	servers := clientDNSByTag(compiled)
	bootstrap := servers[proxyBootstrapDoH]
	if dns["strategy"] != "ipv4_only" {
		t.Fatalf("IPv4-only DNS must strip IPv6 hints, got %v", dns["strategy"])
	}
	if servers[domesticDoHIPv6] != nil || servers[bootstrapBackupV6] != nil ||
		!reflect.DeepEqual(bootstrap["upstreams"], []string{domesticDoH, bootstrapBackupDoH}) {
		t.Fatalf("IPv4-only config included IPv6 bootstrap upstreams: %v", servers)
	}
}

// In TUN mode user IP rules see real addresses: domestic and direct names
// via domestic DNS, others through the tunnel, looked up only from the first
// IP rule on.
func TestTUNResolvesNamesForIPRules(t *testing.T) {
	for _, ipRule := range []bool{false, true} {
		prefs := Defaults()
		prefs.TUN = true
		prefs.Rules = []Rule{
			{Field: "domain_suffix", Match: "first.example", Action: "proxy"},
			{Field: "domain_suffix", Match: "home.example", Action: "direct"},
		}
		if ipRule {
			prefs.Rules = append(prefs.Rules, Rule{Field: "ip_cidr", Match: "192.0.2.0/24", Action: "block"})
		}
		compiled, err := BuildClient(ClientOptions{Preferences: prefs, Profile: &link.Profile{Host: "origin.example"}})
		if err != nil {
			t.Fatal(err)
		}
		route := compiled.Config["route"].(engine.Object)["rules"].([]engine.Object)
		var resolves []engine.Object
		firstAt, resolveAt := -1, -1
		for i, r := range route {
			if r["action"] == "resolve" && r["domain"] == nil { // test hosts have their own
				resolves = append(resolves, r)
				resolveAt = i
			}
			if r["domain_suffix"] == "first.example" {
				firstAt = i
			}
		}
		if !ipRule {
			if len(resolves) != 0 {
				t.Fatalf("lookups without IP rules: %v", resolves)
			}
			continue
		}
		if len(resolves) != 2 || resolveAt < firstAt {
			t.Fatalf("resolve rules %v at %d, first user rule at %d", resolves, resolveAt, firstAt)
		}
		domestic := []engine.Object{{"rule_set": "geosite-cn"}, {"domain_suffix": "home.example"}}
		if resolves[0]["server"] != domesticDoH || !reflect.DeepEqual(resolves[0]["rules"], domestic) || resolves[0]["invert"] != nil ||
			resolves[1]["server"] != "proxy-doh" || !reflect.DeepEqual(resolves[1]["rules"], domestic) || resolves[1]["invert"] != true ||
			resolves[1]["strategy"] != "prefer_ipv4" {
			t.Fatalf("resolve rules %v", resolves)
		}
	}
}
