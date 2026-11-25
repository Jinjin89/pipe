// SPDX-License-Identifier: GPL-3.0-or-later

// Package config parses user preferences and compiles client options.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode"

	"pipe/internal/link"
	"pipe/internal/localfile"

	"gopkg.in/yaml.v3"
)

const (
	Smart  = "smart"
	Global = "global"
	Direct = "direct"
)

type Preferences struct {
	Server string
	Mode   string
	TUN    bool
	IPv6   bool
	Rules  []Rule
}

func Defaults() Preferences { return Preferences{Mode: Smart, IPv6: true} }

type YAML struct {
	Preferences
	Node yaml.Node
}

type Rule struct {
	Field  string
	Match  string
	Action string
}

func ReadYAML(path string) (*YAML, error) {
	data, err := localfile.Read(path, localfile.MaxConfigBytes, false)
	if err != nil {
		return nil, err
	}
	return ParseYAML(data)
}

func ParseYAML(data []byte) (*YAML, error) {
	file := &YAML{Preferences: Defaults()}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&file.Node); errors.Is(err, io.EOF) {
		return file, nil
	} else if err != nil {
		return nil, err
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, at(&trailing, "only one YAML document is allowed")
	}
	root := file.Node.Content[0]
	if root.Kind != yaml.MappingNode || root.Tag != "!!map" {
		return nil, at(root, "expected a YAML mapping")
	}
	seen := make(map[string]bool)
	for i := 0; i < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return nil, at(key, "expected a string key")
		}
		if seen[key.Value] {
			return nil, at(key, "duplicate field %q", key.Value)
		}
		seen[key.Value] = true
		switch key.Value {
		case "server":
			if value.Tag != "!!str" || !ValidAlias(value.Value) {
				return nil, at(value, "server must be a profile alias")
			}
			file.Server = value.Value
		case "mode":
			if value.Tag != "!!str" || !ValidMode(value.Value) {
				return nil, at(value, "mode must be smart, global or direct")
			}
			file.Mode = value.Value
		case "tun", "ipv6":
			if value.Kind != yaml.ScalarNode || value.Tag != "!!bool" ||
				(!strings.EqualFold(value.Value, "true") && !strings.EqualFold(value.Value, "false")) {
				return nil, at(value, "%s must be true or false", key.Value)
			}
			if key.Value == "tun" {
				file.TUN = strings.EqualFold(value.Value, "true")
			} else {
				file.IPv6 = strings.EqualFold(value.Value, "true")
			}
		case "rules":
			if value.Kind != yaml.SequenceNode || value.Tag != "!!seq" {
				return nil, at(value, "rules must be an ordered list")
			}
			for _, item := range value.Content {
				if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
					return nil, at(item, "rule must be a string")
				}
				rule, err := ParseRule(item.Value)
				if err != nil {
					return nil, at(item, "%s", err)
				}
				file.Rules = append(file.Rules, rule)
			}
		default:
			return nil, at(key, "unknown field %q", key.Value)
		}
	}
	return file, nil
}

// Encode serializes the YAML node, including comments and changes to the node.
func (y *YAML) Encode() ([]byte, error) {
	if y.Node.Kind == 0 {
		return nil, nil
	}
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&y.Node); err != nil {
		return nil, err
	}
	return out.Bytes(), encoder.Close()
}

func at(node *yaml.Node, format string, args ...any) error {
	return fmt.Errorf("line %d: %s", max(node.Line, 1), fmt.Sprintf(format, args...))
}

func ValidMode(mode string) bool { return mode == Smart || mode == Global || mode == Direct }

func ValidAlias(alias string) bool {
	return alias != "" && len(alias) <= 64 && strings.IndexFunc(alias, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_')
	}) < 0
}

// FormatRule renders a rule in the text form ParseRule accepts.
func FormatRule(rule Rule) string {
	var match string
	switch rule.Field {
	case "domain_suffix":
		match = "suffix:" + rule.Match
	case "domain_keyword":
		match = "keyword:" + rule.Match
	case "package_name":
		match = "app:" + rule.Match
	case "process_name", "process_path":
		match = "process:" + rule.Match
	default: // domain and ip_cidr are written bare
		match = rule.Match
	}
	return match + " -> " + rule.Action
}

// ParseRule parses "<match> -> proxy|direct|block". A match is a domain, a
// suffix:, keyword:, app: (Android package) or process: (desktop process name
// or path) matcher, or an IP address or CIDR.
func ParseRule(text string) (Rule, error) {
	match, action, found := strings.Cut(text, "->")
	match, action = strings.TrimSpace(match), strings.TrimSpace(action)
	if !found || match == "" || (action != "proxy" && action != "direct" && action != "block") {
		return Rule{}, errors.New("expected <match> -> proxy|direct|block")
	}
	if ip, err := netip.ParsePrefix(match); err == nil {
		return Rule{Field: "ip_cidr", Match: ip.Masked().String(), Action: action}, nil
	}
	if ip, err := netip.ParseAddr(match); err == nil && ip.Zone() == "" {
		return Rule{Field: "ip_cidr", Match: netip.PrefixFrom(ip, ip.BitLen()).String(), Action: action}, nil
	}
	if kind, value, found := strings.Cut(match, ":"); found && value != "" && strings.IndexFunc(value, unicode.IsControl) < 0 {
		switch kind {
		case "suffix":
			value = strings.TrimPrefix(value, ".")
			if link.ValidHost(value) && !strings.Contains(value, ":") {
				return Rule{"domain_suffix", strings.ToLower(value), action}, nil
			}
		case "keyword":
			if strings.IndexFunc(value, unicode.IsSpace) < 0 {
				return Rule{"domain_keyword", strings.ToLower(value), action}, nil
			}
		case "app":
			if link.ValidHost(value) && !strings.Contains(value, ":") {
				return Rule{"package_name", value, action}, nil
			}
		case "process":
			if strings.ContainsAny(value, `/\`) {
				return Rule{"process_path", value, action}, nil
			}
			return Rule{"process_name", value, action}, nil
		}
	}
	if link.ValidHost(match) {
		return Rule{"domain", strings.ToLower(match), action}, nil
	}
	return Rule{}, errors.New("invalid domain, suffix, keyword, CIDR, app or process matcher")
}
