// SPDX-License-Identifier: GPL-3.0-or-later

package sysproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

func (p macProxy) pointsTo(host string, port int) bool {
	return p.Enabled && p.Server == host && p.Port == port
}

type macService struct {
	Name   string   `json:"name"`
	Web    macProxy `json:"web"`
	Secure macProxy `json:"secure"`
	Socks  macProxy `json:"socks"`
	Bypass []string `json:"bypass"`
}

type macSnapshot struct {
	Location string       `json:"location,omitempty"`
	Services []macService `json:"services"`
}

func unmarshalMacSnapshot(raw json.RawMessage) (macSnapshot, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var list []macService
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return macSnapshot{}, err
		}
		return macSnapshot{Services: list}, nil
	}
	var snap macSnapshot
	if err := json.Unmarshal(trimmed, &snap); err != nil {
		return macSnapshot{}, err
	}
	if snap.Services == nil {
		return macSnapshot{}, errors.New("macOS proxy snapshot is missing services")
	}
	return snap, nil
}

func marshalMacSnapshot(snap macSnapshot) (json.RawMessage, error) {
	if snap.Services == nil {
		snap.Services = []macService{}
	}
	if snap.Location == "" {
		return json.Marshal(snap.Services)
	}
	return json.Marshal(snap)
}

func (n Networksetup) currentLocation() (string, error) {
	out, err := n.Run("networksetup", "-getcurrentlocation")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func (n Networksetup) checkLocation(saved string) error {
	if saved == "" {
		return nil
	}
	current, err := n.currentLocation()
	if err != nil {
		return fmt.Errorf("read macOS network location: %w", err)
	}
	if current != saved {
		return fmt.Errorf("macOS network location changed from %q to %q; switch back to restore proxy", saved, current)
	}
	return nil
}

// Each kind has its own get and set flag family.
var macKinds = []struct{ get, set, state string }{
	{"-getwebproxy", "-setwebproxy", "-setwebproxystate"},
	{"-getsecurewebproxy", "-setsecurewebproxy", "-setsecurewebproxystate"},
	{"-getsocksfirewallproxy", "-setsocksfirewallproxy", "-setsocksfirewallproxystate"},
}

func (n Networksetup) services() ([]string, error) {
	return n.listServices(false)
}

func (n Networksetup) allServices() ([]string, error) {
	return n.listServices(true)
}

func (n Networksetup) listServices(includeDisabled bool) ([]string, error) {
	out, err := n.Run("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	return parseServices(out, includeDisabled), nil
}

// parseServices drops the header and handles the '*' marker for disabled services.
func parseServices(out string, includeDisabled bool) []string {
	var names []string
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || (i == 0 && strings.HasPrefix(line, "An asterisk")) || (!includeDisabled && strings.HasPrefix(line, "*")) {
			continue
		}
		names = append(names, strings.TrimPrefix(line, "*"))
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
	loc, err := n.currentLocation()
	if err != nil {
		return nil, err
	}
	names, err := n.services()
	if err != nil {
		return nil, err
	}
	saved := make([]macService, 0, len(names))
	return n.captureServices(loc, saved, names)
}

func (n Networksetup) Extend(raw json.RawMessage) (json.RawMessage, error) {
	snap, err := unmarshalMacSnapshot(raw)
	if err != nil {
		return nil, err
	}
	if err := n.checkLocation(snap.Location); err != nil {
		return nil, err
	}
	names, err := n.services()
	if err != nil {
		return nil, err
	}
	return n.captureServices(snap.Location, snap.Services, names)
}

func savedServiceNames(saved []macService) map[string]bool {
	names := make(map[string]bool, len(saved))
	for _, svc := range saved {
		names[svc.Name] = true
	}
	return names
}

func (n Networksetup) captureServices(location string, saved []macService, names []string) (json.RawMessage, error) {
	known := savedServiceNames(saved)
	for _, name := range names {
		if known[name] {
			continue
		}
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
		known[name] = true
	}
	return marshalMacSnapshot(macSnapshot{Location: location, Services: saved})
}

func (n Networksetup) Apply(host string, port int) error {
	names, err := n.services()
	if err != nil {
		return err
	}
	return n.applyServices(names, host, port)
}

// applySaved checks that the snapshot covers every enabled service before writing.
func (n Networksetup) applySaved(raw json.RawMessage, host string, port int) error {
	snap, err := unmarshalMacSnapshot(raw)
	if err != nil {
		return err
	}
	if err := n.checkLocation(snap.Location); err != nil {
		return err
	}
	names, err := n.services()
	if err != nil {
		return err
	}
	known := savedServiceNames(snap.Services)
	for _, name := range names {
		if !known[name] {
			return fmt.Errorf("%w: %q", errServicesChanged, name)
		}
	}
	if err := n.applyServices(names, host, port); err != nil {
		return err
	}
	if err := n.checkLocation(snap.Location); err != nil {
		return err
	}
	after, err := n.services()
	if err != nil {
		return err
	}
	for _, name := range after {
		if !slices.Contains(names, name) {
			return fmt.Errorf("%w: %q", errServicesChanged, name)
		}
	}
	return nil
}

func (n Networksetup) applyServices(names []string, host string, port int) error {
	bypass := macBypass()
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

func macBypass() []string {
	return append([]string{"localhost", "*.local"}, bypassAddresses...)
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
	return err == nil && parseProxy(out).pointsTo(host, port)
}

// RestoreIfApplied checks each protocol and the bypass list independently.
func (n Networksetup) RestoreIfApplied(raw json.RawMessage, host string, port int) error {
	snap, err := unmarshalMacSnapshot(raw)
	if err != nil {
		return err
	}
	if err := n.checkLocation(snap.Location); err != nil {
		return err
	}
	existing, err := n.allServices()
	if err != nil {
		return err
	}
	var result error
	for _, svc := range snap.Services {
		if !slices.Contains(existing, svc.Name) {
			continue
		}
		for i, p := range []macProxy{svc.Web, svc.Secure, svc.Socks} {
			out, err := n.Run("networksetup", macKinds[i].get, svc.Name)
			if err == nil && parseProxy(out).pointsTo(host, port) {
				err = n.restoreKind(i, svc.Name, p)
			}
			result = errors.Join(result, err)
		}
		out, err := n.Run("networksetup", "-getproxybypassdomains", svc.Name)
		if err == nil && slices.Equal(parseBypass(out), macBypass()) {
			err = n.restoreBypass(svc)
		}
		result = errors.Join(result, err)
	}
	return result
}

func (n Networksetup) verifyClearedSaved(raw json.RawMessage, host string, port int) error {
	snap, err := unmarshalMacSnapshot(raw)
	if err != nil {
		return err
	}
	if err := n.checkLocation(snap.Location); err != nil {
		return err
	}
	return n.verifyCleared(host, port)
}

func (n Networksetup) verifyCleared(host string, port int) error {
	names, err := n.allServices()
	if err != nil {
		return err
	}
	for _, name := range names {
		for _, kind := range macKinds {
			out, err := n.Run("networksetup", kind.get, name)
			if err != nil {
				return fmt.Errorf("verify proxy settings for %q: %w", name, err)
			}
			if parseProxy(out).pointsTo(host, port) {
				return fmt.Errorf("network service %q still uses Pipe's proxy", name)
			}
		}
	}
	return nil
}

func (n Networksetup) Restore(raw json.RawMessage) error {
	snap, err := unmarshalMacSnapshot(raw)
	if err != nil {
		return err
	}
	if err := n.checkLocation(snap.Location); err != nil {
		return err
	}
	existing, err := n.allServices()
	if err != nil {
		return err
	}
	var first error
	for _, svc := range snap.Services {
		if !slices.Contains(existing, svc.Name) {
			continue
		}
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
	var result error
	for i, p := range []macProxy{svc.Web, svc.Secure, svc.Socks} {
		result = errors.Join(result, n.restoreKind(i, svc.Name, p))
	}
	return errors.Join(result, n.restoreBypass(svc))
}

func (n Networksetup) restoreKind(i int, name string, p macProxy) error {
	kind := macKinds[i]
	if p.Server != "" {
		if _, err := n.Run("networksetup", kind.set, name, p.Server, strconv.Itoa(p.Port)); err != nil {
			return err
		}
	}
	state := "off"
	if p.Enabled {
		state = "on"
	}
	_, err := n.Run("networksetup", kind.state, name, state)
	return err
}

func (n Networksetup) restoreBypass(svc macService) error {
	list := svc.Bypass
	if len(list) == 0 {
		list = []string{"Empty"}
	}
	_, err := n.Run("networksetup", append([]string{"-setproxybypassdomains", svc.Name}, list...)...)
	return err
}
