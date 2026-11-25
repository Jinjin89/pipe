// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"reflect"
	"slices"
	"testing"

	"pipe/internal/engine"
	"pipe/internal/link"
)

func TestBuildProbeNamedEndpoints(t *testing.T) {
	profile := link.Profile{Host: "origin.example", CDN: "cdn.example", FastPin: link.EncodeKey([32]byte{1})}
	options := ProbeOptions{Profile: profile, Relay: "relay.example:8444/444", IPv6: true, Interface: "uplink0"}
	compiled, err := BuildProbe(options)
	if err != nil {
		t.Fatal(err)
	}
	if got := compiled.Config["inbounds"].([]engine.Object); len(got) != 0 || len(compiled.RuleSets) != 0 {
		t.Fatal("probe includes inbounds or rule sets")
	}
	if got := compiled.Config["route"]; !reflect.DeepEqual(got, engine.Object{"default_interface": "uplink0"}) {
		t.Fatalf("unexpected probe route options %v", got)
	}
	if got := compiled.Config["log"]; !reflect.DeepEqual(got, engine.Object{"disabled": true}) {
		t.Fatalf("unexpected probe log options %v", got)
	}
	live, err := BuildClient(ClientOptions{Profile: &profile, Relay: options.Relay, Preferences: Preferences{Mode: Smart, IPv6: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(compiled.Relay, live.Relay) {
		t.Fatalf("probe relay %+v differs from client relay %+v", compiled.Relay, live.Relay)
	}
	outbounds, clientTiers := clientOutboundsByTag(compiled), clientOutboundsByTag(live)
	if len(outbounds) != 3 {
		t.Fatalf("probe has %d outbounds, want three tiers", len(outbounds))
	}
	for _, tier := range []string{"fast", "stealth", "rescue"} {
		outbound := outbounds[tier]
		if !reflect.DeepEqual(outbound, clientTiers[tier]) || outbound["domain_resolver"].(engine.Object)["server"] != proxyBootstrapDoH {
			t.Fatalf("probe's %s outbound differs from the client tier", tier)
		}
	}
	dns := compiled.Config["dns"].(engine.Object)
	if len(dns) != 2 || dns["final"] != domesticDoH {
		t.Fatalf("unexpected probe DNS options %v", dns)
	}
	servers := clientDNSByTag(compiled)
	for _, tag := range []string{domesticDoH, domesticDoHIPv6, bootstrapBackupDoH, bootstrapBackupV6} {
		if server := servers[tag]; server["type"] != "https" || server["detour"] != nil {
			t.Fatalf("probe DNS upstream %q must use direct DoH", tag)
		}
	}
	bootstrap := servers[proxyBootstrapDoH]
	if len(servers) != 5 || bootstrap["type"] != engine.BootstrapDNSType ||
		!slices.Equal(bootstrap["hosts"].([]string), []string{profile.Host, profile.CDN, "relay.example"}) {
		t.Fatalf("unexpected bootstrap DNS options %v", bootstrap)
	}
}

func TestBuildProbeLiteralOrigin(t *testing.T) {
	options := ProbeOptions{Profile: link.Profile{Host: "192.0.2.1"}, Relay: "relay.example:8444"}
	compiled, err := BuildProbe(options)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Config["route"] != nil {
		t.Fatal("unbound probe has route options")
	}
	outbounds := clientOutboundsByTag(compiled)
	if len(outbounds) != 2 || outbounds["fast"]["domain_resolver"] != nil {
		t.Fatal("probe included Rescue or assigned a resolver to the literal-only Fast tier")
	}
	want := engine.Object{"server": proxyBootstrapDoH, "strategy": "ipv4_only", "disable_cache": true}
	if got := outbounds["stealth"]["domain_resolver"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("Stealth relay resolver %v, want %v", got, want)
	}
	if servers := clientDNSByTag(compiled); len(servers) != 3 ||
		!slices.Equal(servers[proxyBootstrapDoH]["hosts"].([]string), []string{"relay.example"}) {
		t.Fatalf("literal origin probe DNS servers %v", servers)
	}
}
