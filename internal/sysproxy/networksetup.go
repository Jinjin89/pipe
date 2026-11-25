// SPDX-License-Identifier: GPL-3.0-or-later

package sysproxy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Networksetup drives macOS network services through networksetup(8).
type Networksetup struct{ Run Runner }

type macProxy struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Port    int    `json:"port"`
}

type macService struct {
	Name   string   `json:"name"`
	Web    macProxy `json:"web"`
	Secure macProxy `json:"secure"`
	Socks  macProxy `json:"socks"`
	Bypass []string `json:"bypass"`
}

// Each kind has its own get and set flag family.
var macKinds = []struct{ get, set, state string }{
	{"-getwebproxy", "-setwebproxy", "-setwebproxystate"},
	{"-getsecurewebproxy", "-setsecurewebproxy", "-setsecurewebproxystate"},
	{"-getsocksfirewallproxy", "-setsocksfirewallproxy", "-setsocksfirewallproxystate"},
}

func (n Networksetup) services() ([]string, error) {
	out, err := n.Run("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	return parseServices(out), nil
}

// parseServices keeps enabled services. Disabled ones start with "*" and the
// first line is an explanatory header.
func parseServices(out string) []string {
	var names []string
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "*") || (i == 0 && strings.HasPrefix(line, "An asterisk")) {
			continue
		}
		names = append(names, line)
	}
	return names
}

func parseProxy(out string) macProxy {
	var p macProxy
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "Enabled":
			p.Enabled = strings.EqualFold(value, "yes")
		case "Server":
			p.Server = value
		case "Port":
			p.Port, _ = strconv.Atoi(value)
		}
	}
	return p
}

func parseBypass(out string) []string {
	if strings.Contains(out, "There aren't any") {
		return nil
	}
	var list []string
	for _, line := range strings.Split(out, "\n") {
		if line = trim(line); line != "" {
			list = append(list, line)
		}
	}
	return list
}

func (n Networksetup) Capture() (json.RawMessage, error) {
	names, err := n.services()
	if err != nil {
		return nil, err
	}
	var saved []macService
	for _, name := range names {
		svc := macService{Name: name}
		targets := []*macProxy{&svc.Web, &svc.Secure, &svc.Socks}
		for i, kind := range macKinds {
			out, err := n.Run("networksetup", kind.get, name)
			if err != nil {
				return nil, err
			}
			*targets[i] = parseProxy(out)
		}
		out, err := n.Run("networksetup", "-getproxybypassdomains", name)
		if err != nil {
			return nil, err
		}
		svc.Bypass = parseBypass(out)
		saved = append(saved, svc)
	}
	return json.Marshal(saved)
}

func (n Networksetup) Apply(host string, port int) error {
	names, err := n.services()
	if err != nil {
		return err
	}
	bypass := append([]string{"localhost", "*.local"}, bypassAddresses...)
	for _, name := range names {
		for _, kind := range macKinds {
			if _, err := n.Run("networksetup", kind.set, name, host, strconv.Itoa(port)); err != nil {
				return err
			}
		}
		if _, err := n.Run("networksetup", append([]string{"-setproxybypassdomains", name}, bypass...)...); err != nil {
			return err
		}
	}
	return nil
}

func (n Networksetup) IsApplied(host string, port int) bool {
	names, err := n.services()
	if err != nil {
		return false
	}
	for _, name := range names {
		if n.serviceApplied(name, host, port) {
			return true
		}
	}
	return false
}

func (n Networksetup) serviceApplied(name, host string, port int) bool {
	out, err := n.Run("networksetup", "-getwebproxy", name)
	p := parseProxy(out)
	return err == nil && p.Enabled && p.Server == host && p.Port == port
}

// RestoreIfApplied restores each saved service separately, and only if that
// service still points at host:port. Errors on one service don't stop the rest.
func (n Networksetup) RestoreIfApplied(raw json.RawMessage, host string, port int) error {
	var saved []macService
	if err := json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	var first error
	for _, svc := range saved {
		if !n.serviceApplied(svc.Name, host, port) {
			continue
		}
		if err := n.restoreService(svc); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (n Networksetup) Restore(raw json.RawMessage) error {
	var saved []macService
	if err := json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	var first error
	for _, svc := range saved {
		if err := n.restoreService(svc); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		return fmt.Errorf("restore proxy: %w", first)
	}
	return nil
}

func (n Networksetup) restoreService(svc macService) error {
	var first error
	note := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	for i, p := range []macProxy{svc.Web, svc.Secure, svc.Socks} {
		kind := macKinds[i]
		if p.Server != "" {
			_, err := n.Run("networksetup", kind.set, svc.Name, p.Server, strconv.Itoa(p.Port))
			note(err)
		}
		state := "off"
		if p.Enabled {
			state = "on"
		}
		_, err := n.Run("networksetup", kind.state, svc.Name, state)
		note(err)
	}
	list := svc.Bypass
	if len(list) == 0 {
		list = []string{"Empty"}
	}
	_, err := n.Run("networksetup", append([]string{"-setproxybypassdomains", svc.Name}, list...)...)
	note(err)
	return first
}
