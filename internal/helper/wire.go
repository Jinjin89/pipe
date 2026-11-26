// SPDX-License-Identifier: GPL-3.0-or-later

package helper

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"unicode/utf8"

	"pipe/internal/clientctl"
	"pipe/internal/config"
	"pipe/internal/failover"
	"pipe/internal/link"
)

// Limits from APP_DESIGN §8.2.
const (
	MaxRules    = 500
	MaxRuleSize = 1024
)

func validTier(tier string) bool {
	switch failover.Tier(tier) {
	case failover.Auto, failover.Fast, failover.Stealth, failover.Rescue:
		return true
	}
	return false
}

// EncodeOptions turns engine options into their wire form.
func EncodeOptions(o clientctl.Options) (SessionOptions, error) {
	text, err := o.Profile.Encode()
	if err != nil {
		return SessionOptions{}, err
	}
	s := SessionOptions{
		Link:     text,
		Relay:    o.Relay,
		Mode:     o.Mode,
		Tier:     string(o.Tier),
		IPv6:     o.IPv6,
		Rules:    make([]string, 0, len(o.Rules)),
		Listen:   o.Listen,
		LogLevel: o.LogLevel,
	}
	if s.Mode == "" {
		s.Mode = config.Smart
	}
	if s.Tier == "" {
		s.Tier = string(failover.Auto)
	}
	if s.Listen == "" {
		s.Listen = config.DefaultListen
	}
	if s.LogLevel == "" {
		s.LogLevel = "warn"
	}
	for _, r := range o.Rules {
		s.Rules = append(s.Rules, config.FormatRule(r))
	}
	return s, nil
}

// DecodeOptions validates a request from the app and returns the engine
// options. TUN mode exposes no anonymous mixed proxy.
func DecodeOptions(s SessionOptions) (clientctl.Options, error) {
	profile, err := link.Parse(s.Link)
	if err != nil {
		return clientctl.Options{}, errors.New("That link isn't a valid Pipe link.")
	}
	relay, err := config.ParseRelay(s.Relay, profile.Host)
	if err != nil {
		return clientctl.Options{}, err
	}
	mode := s.Mode
	if mode == "" {
		mode = config.Smart
	}
	if !config.ValidMode(mode) {
		return clientctl.Options{}, errors.New("Routing mode must be Smart, Global or Direct.")
	}
	tier := s.Tier
	if tier == "" {
		tier = string(failover.Auto)
	}
	if !validTier(tier) {
		return clientctl.Options{}, errors.New("That route isn't available.")
	}
	if len(s.Rules) > MaxRules {
		return clientctl.Options{}, fmt.Errorf("Too many rules (%d at most).", MaxRules)
	}
	rules := make([]config.Rule, 0, len(s.Rules))
	for i, text := range s.Rules {
		if len(text) > MaxRuleSize || !utf8.ValidString(text) {
			return clientctl.Options{}, fmt.Errorf("Rule %d is too long.", i+1)
		}
		r, err := config.ParseRule(text)
		if err != nil {
			return clientctl.Options{}, fmt.Errorf("Rule %d is not valid: %v.", i+1, err)
		}
		rules = append(rules, r)
	}
	listen := s.Listen
	if listen == "" {
		listen = config.DefaultListen
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil || host != "127.0.0.1" {
		return clientctl.Options{}, errors.New("The listen address must be 127.0.0.1 with a port.")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1024 || p > 65535 || strconv.Itoa(p) != port {
		return clientctl.Options{}, errors.New("The listen port must be between 1024 and 65535.")
	}
	level := s.LogLevel
	if level == "" {
		level = "warn"
	}
	if level != "warn" && level != "info" && level != "debug" {
		return clientctl.Options{}, errors.New("The log level must be warn, info or debug.")
	}
	return clientctl.Options{
		Profile:  profile,
		Relay:    relay.String(),
		Mode:     mode,
		Tier:     failover.Tier(tier),
		IPv6:     s.IPv6,
		Rules:    rules,
		Listen:   listen,
		LogLevel: level,
		TUN:      true,
		TUNOnly:  true,
	}, nil
}
