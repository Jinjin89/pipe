// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"errors"

	"pipe/internal/engine"
	"pipe/internal/link"
)

// ProbeOptions describes the profile and network for a latency probe.
type ProbeOptions struct {
	Profile   link.Profile
	Relay     string // optional relay code
	IPv6      bool
	Interface string // physical uplink when a TUN session is active
}

// BuildProbe configures an engine that dials proxy tiers and resolves their
// endpoints without opening any inbounds or installing routing rules.
func BuildProbe(options ProbeOptions) (engine.Options, error) {
	if options.Profile.Host == "" {
		return engine.Options{}, errors.New("a server profile is required for a probe")
	}
	client := ClientOptions{
		Preferences: Preferences{IPv6: options.IPv6},
		Profile:     &options.Profile,
		Relay:       options.Relay,
	}
	outbounds, relay, err := tierOutbounds(client)
	if err != nil {
		return engine.Options{}, err
	}
	// Keep a DoH default even for literal endpoints so sing-box does not
	// install its fallback system DNS transport.
	dns := engine.Object{"final": domesticDoH}
	servers := []engine.Object{domesticDNS(false)}
	if options.IPv6 {
		servers = append(servers, domesticDNS(true))
	} else {
		dns["strategy"] = "ipv4_only"
	}
	dns["servers"] = append(servers, proxyBootstrapServers(client, relay)...)
	result := engine.Options{
		Config: engine.Object{
			"log":       engine.Object{"disabled": true},
			"inbounds":  []engine.Object{},
			"outbounds": outbounds,
			"dns":       dns,
		},
		Relay: relay,
	}
	if options.Interface != "" {
		result.Config["route"] = engine.Object{"default_interface": options.Interface}
	}
	result.DisableRelayCooldown = true
	return result, nil
}
