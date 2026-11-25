// SPDX-License-Identifier: GPL-3.0-or-later

package mobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"pipe/internal/config"
	"pipe/internal/failover"
	"pipe/internal/link"
)

type appSelection struct {
	Mode     string   `json:"mode"`
	Packages []string `json:"packages"`
}

type preferences struct {
	Mode   string          `json:"mode"`
	Tier   string          `json:"tier"`
	Relay  string          `json:"relay"`
	IPv6   bool            `json:"ipv6"`
	PerApp appSelection    `json:"perApp"`
	Test   json.RawMessage `json:"test"`
	Rules  []ruleObject    `json:"rules"`
	// LogLevel is "warn" (default) or "info".
	LogLevel string `json:"logLevel"`
}

// ruleObject is the rule shape shared with the desktop API.
type ruleObject struct {
	Type   string `json:"type"` // domain|suffix|keyword|ip (no app rules on Android)
	Value  string `json:"value"`
	Action string `json:"action"` // proxy|direct|block
}

const maxRules = 500

// MaxRules is the most routing rules the app accepts.
func MaxRules() int64 { return maxRules }

// ValidateRelay returns "" when the relay code is valid for the profile, or a short message.
func ValidateRelay(rawProfile, code string) string {
	profile, err := link.Parse(strings.TrimSpace(rawProfile))
	if err != nil {
		return "invalid profile"
	}
	if _, err := config.ParseRelay(code, profile.Host); err != nil {
		return err.Error()
	}
	return ""
}

// ValidateRule returns "" when the rule is acceptable, or a short message.
func ValidateRule(ruleType, value, action string) string {
	if _, err := parseRule(ruleObject{Type: ruleType, Value: value, Action: action}); err != nil {
		return err.Error()
	}
	return ""
}

func parseRule(object ruleObject) (config.Rule, error) {
	value := strings.TrimSpace(object.Value)
	field := map[string]string{
		"domain": "domain", "ip": "ip_cidr", "suffix": "domain_suffix", "keyword": "domain_keyword",
	}[object.Type]
	if field == "" {
		return config.Rule{}, errors.New("unknown rule type")
	}
	if strings.Contains(value, "->") || (object.Type != "ip" && strings.Contains(value, ":")) {
		return config.Rule{}, errors.New("invalid value")
	}
	text := value
	if object.Type == "suffix" || object.Type == "keyword" {
		text = object.Type + ":" + value
	}
	rule, err := config.ParseRule(text + " -> " + object.Action)
	if err != nil {
		return config.Rule{}, errors.New("enter a valid value and choose proxy, direct or block")
	}
	if rule.Field != field {
		return config.Rule{}, errors.New("value does not match type")
	}
	return rule, nil
}

func parseRules(objects []ruleObject) ([]config.Rule, error) {
	if len(objects) > maxRules {
		return nil, errors.New("too many rules")
	}
	rules := make([]config.Rule, 0, len(objects))
	for i, object := range objects {
		rule, err := parseRule(object)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

type settings struct {
	client    config.ClientOptions
	apps      appSelection
	relayHost string
}

func prepare(rawProfile, prefsJSON string) (settings, error) {
	profile, err := link.Parse(strings.TrimSpace(rawProfile))
	if err != nil {
		return settings{}, err
	}
	return prepareProfile(&profile, prefsJSON)
}

func prepareProfile(profile *link.Profile, prefsJSON string) (settings, error) {
	prefs := preferences{Mode: config.Smart, Tier: string(failover.Auto), IPv6: true, PerApp: appSelection{Mode: "all"}}
	if prefsJSON != "" {
		if len(prefsJSON) > 1024*1024 || json.Unmarshal([]byte(prefsJSON), &prefs) != nil {
			return settings{}, errors.New("invalid VPN preferences")
		}
	}
	if !config.ValidMode(prefs.Mode) {
		return settings{}, errors.New("mode must be smart, global or direct")
	}
	tier := failover.Tier(prefs.Tier)
	if tier == failover.Rescue && profile.CDN == "" {
		tier = failover.Auto
	}
	if !validTier(tier, profile.CDN != "") {
		return settings{}, errors.New("tier is unavailable for this profile")
	}
	switch prefs.PerApp.Mode {
	case "all", "bypass":
	case "only":
		if len(prefs.PerApp.Packages) == 0 {
			return settings{}, errors.New("select at least one app")
		}
	default:
		return settings{}, errors.New("invalid per-app mode")
	}
	for _, name := range prefs.PerApp.Packages {
		if name == "" || strings.ContainsAny(name, " \t\r\n/") {
			return settings{}, errors.New("invalid Android package name")
		}
	}
	rules, err := parseRules(prefs.Rules)
	if err != nil {
		return settings{}, err
	}
	if prefs.LogLevel != "" && prefs.LogLevel != "warn" && prefs.LogLevel != "info" {
		return settings{}, errors.New("log level must be warn or info")
	}
	relay, err := config.ParseRelay(prefs.Relay, profile.Host)
	if err != nil {
		return settings{}, err
	}
	options := config.ClientOptions{
		Preferences: config.Preferences{Mode: prefs.Mode, IPv6: prefs.IPv6, TUN: true, Rules: rules},
		LogLevel:    prefs.LogLevel,
		Profile:     profile,
		Tier:        tier,
		Relay:       prefs.Relay,
		Mobile:      true,
	}
	if enableTestHooks && len(prefs.Test) != 0 {
		if err := applyTestOptions(prefs.Test, &options); err != nil {
			return settings{}, err
		}
	}
	return settings{client: options, apps: prefs.PerApp, relayHost: relay.Host}, nil
}

// networkClientOptions keeps the TUN in step with the active network while
// honoring the user's IPv6 preference for Pipe's own dials and DNS.
func networkClientOptions(options config.ClientOptions, netIPv6 bool) config.ClientOptions {
	options.IPv6 = options.IPv6 && netIPv6
	options.TUNIPv6 = netIPv6
	return options
}

func validTier(tier failover.Tier, cdn bool) bool {
	return tier == failover.Auto || slices.Contains(failover.Available(cdn), tier)
}

func applyTestOptions(raw json.RawMessage, options *config.ClientOptions) error {
	var test struct {
		CAFile  string `json:"caFile"`
		Address string `json:"address"`
	}
	if json.Unmarshal(raw, &test) != nil {
		return errors.New("invalid VPN test preferences")
	}
	if test.Address != "" {
		address, err := netip.ParseAddr(test.Address)
		if err != nil || (!address.IsPrivate() && !address.IsLoopback()) || test.CAFile == "" {
			return errors.New("test address requires a test CA and a private or loopback address")
		}
		options.TestAddress = address
	}
	options.TestCAFile = test.CAFile
	return nil
}
