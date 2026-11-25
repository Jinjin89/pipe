// SPDX-License-Identifier: GPL-3.0-or-later

package sysdns

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Networksetup controls DNS on macOS network services and reads the active
// service's DHCP/RA resolver list from scutil.
type Networksetup struct{ Run Runner }

type serviceDNS struct {
	Name      string   `json:"name"`
	Automatic bool     `json:"automatic"`
	Servers   []string `json:"servers,omitempty"`
}

type macSnapshot struct {
	Services []serviceDNS `json:"services"`
	Global   []string     `json:"global,omitempty"`
}

func (n Networksetup) run(name string, args ...string) (string, error) {
	run := n.Run
	if run == nil {
		run = ExecRunner
	}
	return run(name, args...)
}

func (n Networksetup) services() ([]string, error) {
	out, err := n.run("/usr/sbin/networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	return parseServices(out), nil
}

func (n Networksetup) allServices() ([]string, error) {
	out, err := n.run("/usr/sbin/networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var names []string
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || (i == 0 && strings.HasPrefix(line, "An asterisk")) {
			continue
		}
		names = append(names, strings.TrimPrefix(line, "*"))
	}
	return names, nil
}

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

func parseDNSList(out string) (servers []string, automatic bool, err error) {
	if strings.Contains(strings.ToLower(out), "there aren't any dns servers") {
		return nil, true, nil
	}
	for _, line := range strings.Split(out, "\n") {
		value := strings.TrimSpace(line)
		if addr, err := netip.ParseAddr(value); err == nil {
			servers = append(servers, addr.String())
		}
	}
	if len(servers) == 0 {
		return nil, false, errors.New("networksetup returned an unrecognized DNS server list")
	}
	return servers, false, nil
}

func parseAddresses(values []string, primaryInterface ...string) []netip.AddrPort {
	servers := make([]netip.AddrPort, 0, len(values))
	zone := ""
	if len(primaryInterface) > 0 && !strings.ContainsAny(primaryInterface[0], "/% \t\r\n") {
		zone = primaryInterface[0]
	}
	for _, value := range values {
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err == nil {
			if addr.IsLinkLocalUnicast() && addr.Zone() == "" && zone != "" {
				addr = addr.WithZone(zone)
			}
			servers = append(servers, netip.AddrPortFrom(addr, 53))
		}
	}
	return servers
}

func (n Networksetup) Capture() (json.RawMessage, error) {
	names, err := n.services()
	if err != nil {
		return nil, err
	}
	saved := macSnapshot{Services: make([]serviceDNS, 0, len(names))}
	for _, name := range names {
		out, err := n.run("/usr/sbin/networksetup", "-getdnsservers", name)
		if err != nil {
			return nil, err
		}
		servers, automatic, err := parseDNSList(out)
		if err != nil {
			return nil, err
		}
		saved.Services = append(saved.Services, serviceDNS{Name: name, Automatic: automatic, Servers: servers})
	}
	global, err := n.run("/usr/sbin/scutil", "show", "State:/Network/Global/DNS")
	if err != nil {
		return nil, err
	}
	saved.Global = parseScutilServers(global)
	return json.Marshal(saved)
}

func (n Networksetup) Extend(raw json.RawMessage) (json.RawMessage, error) {
	var saved macSnapshot
	if err := json.Unmarshal(raw, &saved); err != nil {
		return nil, err
	}
	known := make(map[string]struct{}, len(saved.Services))
	for _, service := range saved.Services {
		known[service.Name] = struct{}{}
	}
	names, err := n.services()
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if _, ok := known[name]; ok {
			continue
		}
		out, err := n.run("/usr/sbin/networksetup", "-getdnsservers", name)
		if err != nil {
			return nil, err
		}
		servers, automatic, err := parseDNSList(out)
		if err != nil {
			return nil, err
		}
		saved.Services = append(saved.Services, serviceDNS{Name: name, Automatic: automatic, Servers: servers})
	}
	return json.Marshal(saved)
}

func (n Networksetup) Apply(raw json.RawMessage) error {
	var saved macSnapshot
	if err := json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	names, err := n.services()
	if err != nil {
		return err
	}
	active := make(map[string]struct{}, len(names))
	for _, name := range names {
		active[name] = struct{}{}
	}
	for _, service := range saved.Services {
		if _, ok := active[service.Name]; !ok {
			continue
		}
		if _, err := n.run("/usr/sbin/networksetup", "-setdnsservers", service.Name, TUNDNSAddress); err != nil {
			return err
		}
	}
	_ = flushDNS(n.run)
	return nil
}

func (n Networksetup) Restore(raw json.RawMessage) (json.RawMessage, error) {
	var saved macSnapshot
	if err := json.Unmarshal(raw, &saved); err != nil {
		return nil, err
	}
	existing, err := n.allServices()
	if err != nil {
		return raw, err
	}
	exists := make(map[string]struct{}, len(existing))
	for _, name := range existing {
		exists[name] = struct{}{}
	}
	var remaining []serviceDNS
	var failures []error
	for _, service := range saved.Services {
		if _, ok := exists[service.Name]; !ok {
			continue
		}
		if err := n.restoreService(service); err != nil {
			remaining = append(remaining, service)
			failures = append(failures, fmt.Errorf("%s: %w", service.Name, err))
		}
	}
	_ = flushDNS(n.run)
	return snapshotRemainder(saved, remaining, failures)
}

func (n Networksetup) RestoreIfApplied(raw json.RawMessage) (json.RawMessage, error) {
	var saved macSnapshot
	if err := json.Unmarshal(raw, &saved); err != nil {
		return nil, err
	}
	existing, err := n.allServices()
	if err != nil {
		return raw, err
	}
	exists := make(map[string]struct{}, len(existing))
	for _, name := range existing {
		exists[name] = struct{}{}
	}
	var remaining []serviceDNS
	var failures []error
	for _, service := range saved.Services {
		if _, ok := exists[service.Name]; !ok {
			continue
		}
		out, err := n.run("/usr/sbin/networksetup", "-getdnsservers", service.Name)
		if err != nil {
			remaining = append(remaining, service)
			failures = append(failures, fmt.Errorf("%s: %w", service.Name, err))
			continue
		}
		servers, automatic, parseErr := parseDNSList(out)
		if parseErr != nil {
			remaining = append(remaining, service)
			failures = append(failures, fmt.Errorf("%s: %w", service.Name, parseErr))
			continue
		}
		if automatic || len(servers) != 1 || servers[0] != TUNDNSAddress {
			continue
		}
		if err := n.restoreService(service); err != nil {
			remaining = append(remaining, service)
			failures = append(failures, fmt.Errorf("%s: %w", service.Name, err))
		}
	}
	_ = flushDNS(n.run)
	return snapshotRemainder(saved, remaining, failures)
}

func snapshotRemainder(saved macSnapshot, remaining []serviceDNS, failures []error) (json.RawMessage, error) {
	if len(remaining) == 0 {
		return nil, wrapRestoreErrors(failures)
	}
	saved.Services = remaining
	updated, err := json.Marshal(saved)
	if err != nil {
		return nil, errors.Join(append(failures, err)...)
	}
	return updated, wrapRestoreErrors(failures)
}

func wrapRestoreErrors(failures []error) error {
	if len(failures) == 0 {
		return nil
	}
	return fmt.Errorf("restore system DNS: %w", errors.Join(failures...))
}

func (n Networksetup) restoreService(service serviceDNS) error {
	args := []string{"-setdnsservers", service.Name}
	if service.Automatic || len(service.Servers) == 0 {
		args = append(args, "Empty")
	} else {
		args = append(args, service.Servers...)
	}
	_, err := n.run("/usr/sbin/networksetup", args...)
	return err
}

func flushDNS(run Runner) error {
	var first error
	for _, command := range [][]string{{"/usr/bin/dscacheutil", "-flushcache"}, {"/usr/bin/killall", "-HUP", "mDNSResponder"}} {
		if _, err := run(command[0], command[1:]...); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func parseScutilValue(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(name) == key {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func parseScutilServers(out string) []string {
	var servers []string
	inArray := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !inArray {
			if key, value, ok := strings.Cut(trimmed, ":"); ok && strings.TrimSpace(key) == "ServerAddresses" && strings.Contains(value, "<array>") {
				inArray = true
			}
			continue
		}
		if trimmed == "}" {
			break
		}
		_, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		if addr, err := netip.ParseAddr(value); err == nil {
			servers = append(servers, addr.String())
		}
	}
	return servers
}

func (n Networksetup) CurrentServers() ([]netip.AddrPort, error) {
	global, ipv4Err := n.run("/usr/sbin/scutil", "show", "State:/Network/Global/IPv4")
	service := parseScutilValue(global, "PrimaryService")
	primaryInterface := parseScutilValue(global, "PrimaryInterface")
	if service == "" {
		global6, ipv6Err := n.run("/usr/sbin/scutil", "show", "State:/Network/Global/IPv6")
		if ipv6Err == nil {
			service = parseScutilValue(global6, "PrimaryService")
			if primaryInterface == "" {
				primaryInterface = parseScutilValue(global6, "PrimaryInterface")
			}
		} else if ipv4Err != nil {
			return nil, errors.Join(ipv4Err, ipv6Err)
		}
	}
	if service == "" || strings.ContainsAny(service, "/\r\n") {
		return nil, errors.New("active network service is unavailable")
	}
	state, err := n.run("/usr/sbin/scutil", "show", "State:/Network/Service/"+service+"/DNS")
	if err != nil {
		return nil, err
	}
	return parseAddresses(parseScutilServers(state), primaryInterface), nil
}

func (n Networksetup) SavedServers(raw json.RawMessage) []netip.AddrPort {
	var saved macSnapshot
	if json.Unmarshal(raw, &saved) != nil {
		return nil
	}
	return parseAddresses(saved.Global)
}
