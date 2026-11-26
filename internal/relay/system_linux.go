// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !android

package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"pipe/internal/localfile"

	"golang.org/x/sys/unix"
)

const (
	unitName     = "pipe-relay.service"
	unitPath     = "/etc/systemd/system/" + unitName
	bootBinary   = "/usr/local/libexec/pipe-relay"
	sysctlPath   = "/etc/sysctl.d/90-pipe-relay.conf"
	conntrackMax = "net.netfilter.nf_conntrack_max"
)

type relaySystem struct {
	host       bool
	sysctlFile string
	run        func(context.Context, string, string, ...string) (string, error)
}

type sysctlSetting struct{ key, value string }

// Add allocates relay ports, activates the route, and returns its public instructions.
func Add(ctx context.Context, path string, request Request, host, executable string) (code, open, hint string, err error) {
	err = withSystem(path, func(system relaySystem, path string) error {
		if err := request.validate(); err != nil {
			return err
		}
		if host != "" && !request.validHost(host) {
			return errors.New("--host needs an IP address in a configured target family or a DNS name")
		}
		s, old, err := readState(path)
		if err != nil {
			return err
		}
		used, err := localPorts()
		if err != nil {
			return err
		}
		index, err := s.replace(request, host, used)
		if err != nil {
			return err
		}
		s.ingress, err = system.ingress(ctx, s.routes)
		if err != nil {
			return err
		}
		r := &s.routes[index]
		if r.Host == "" {
			names := s.IPv4
			if !request.IPv4.IsValid() {
				names = s.IPv6
			}
			r.Host, hint, err = uplinkHost(names, request)
			if err != nil {
				return err
			}
		}
		if err := system.change(ctx, path, s, old, executable); err != nil {
			return err
		}
		code, open = r.code(), r.exposedPorts()
		return nil
	})
	return
}

// Apply rebuilds the complete kernel ruleset using the saved ingress interfaces.
func Apply(ctx context.Context, path string) error {
	return withSystem(path, func(system relaySystem, path string) error {
		s, old, err := readState(path)
		if err != nil {
			return err
		}
		if old == "" {
			return fmt.Errorf("no Pipe relay state at %s", path)
		}
		_, err = system.apply(ctx, s)
		return err
	})
}

func Remove(ctx context.Context, path, to string) error {
	return withSystem(path, func(system relaySystem, path string) error {
		s, old, err := readState(path)
		if err != nil {
			return err
		}
		if err := s.remove(to); err != nil {
			return err
		}
		if len(s.routes) == 0 {
			return system.remove(ctx, path)
		}
		s.ingress, err = system.ingress(ctx, s.routes)
		if err != nil {
			return err
		}
		return system.change(ctx, path, s, old, "")
	})
}

func Status(ctx context.Context, path string) (string, error) {
	var status string
	err := withSystem(path, func(system relaySystem, path string) error {
		s, _, err := readState(path)
		if err != nil {
			return err
		}
		table, err := system.ownedTable(ctx)
		if err != nil {
			return err
		}
		var counters map[string]nftCounter
		if table.Handle != 0 && len(s.routes) != 0 {
			output, err := system.run(ctx, "nft", "", "-j", "list", "counters", "table", "inet", tableName)
			if err != nil {
				return err
			}
			counters, err = readCounters(output)
			if err != nil {
				return err
			}
		}
		status = statusText(s, table.Handle != 0, counters)
		return nil
	})
	return status, err
}

func (s relaySystem) change(ctx context.Context, path string, next state, old, executable string) error {
	if err := next.validate(); err != nil {
		return err
	}
	text, err := stateText(next)
	if err != nil {
		return err
	}
	if s.host && executable != "" {
		if _, err := readOwnedFile(unitPath); err != nil {
			return err
		}
		image, err := localfile.OpenTrustedRunningImage(executable)
		if err != nil {
			return fmt.Errorf("start relay setup from a root-owned, protected Pipe executable: %w", err)
		}
		defer image.Close()
		if err := localfile.MakeTrustedDirectory(filepath.Dir(unitPath)); err != nil {
			return err
		}
		if err := localfile.InstallTrustedExecutable(image, bootBinary); err != nil {
			return err
		}
		executable = bootBinary
	}
	if err := writeManagedFile(path, text); err != nil {
		return err
	}
	active, err := s.apply(ctx, next)
	if err != nil {
		if !active {
			if old == "" {
				return errors.Join(err, removeFile(path))
			}
			return errors.Join(err, writeManagedFile(path, old))
		}
		return err
	}
	if s.host && executable != "" {
		if err := writeManagedFile(unitPath, unitText(executable, path)); err != nil {
			return err
		}
		if _, err := s.run(ctx, "systemctl", "", "daemon-reload"); err != nil {
			return err
		}
		_, err = s.run(ctx, "systemctl", "", "enable", unitName)
	}
	return err
}

func (s relaySystem) apply(ctx context.Context, next state) (active bool, err error) {
	table, err := s.ownedTable(ctx)
	if err != nil {
		return false, err
	}
	before, err := s.sysctlBaseline(table)
	if err != nil {
		return false, err
	}
	keys := next.forwarding()
	previous, err := s.prepareSysctls(ctx, before, keys, next.IPv6)
	if err != nil {
		return false, err
	}
	// Restore removed families before taking away their forwarding guards.
	reset, undo, err := s.restoreSettings(ctx, before, previous)
	if err != nil {
		return false, err
	}
	if err := s.applyRestoration(ctx, reset); err != nil {
		return false, errors.Join(err, s.applySysctls(context.WithoutCancel(ctx), undo))
	}
	if err := s.writeTable(ctx, table.Handle, ruleText(next, previous)); err != nil {
		return false, errors.Join(err, s.applySysctls(context.WithoutCancel(ctx), undo))
	}
	// Loading the stateful rules can make the conntrack sysctl available.
	settings, err := s.tunings(ctx, keys, previous)
	if err != nil {
		return true, err
	}
	if s.host {
		if err := writeManagedFile(s.sysctlFile, sysctlText(settings, previous)); err != nil {
			return true, err
		}
	}
	return true, s.applySysctls(ctx, settings)
}

func (s relaySystem) remove(ctx context.Context, path string) error {
	table, err := s.ownedTable(ctx)
	if err != nil {
		return err
	}
	previous, err := s.sysctlBaseline(table)
	if err != nil {
		return err
	}
	var unit string
	if s.host {
		unit, err = readOwnedFile(unitPath)
		if err != nil {
			return err
		}
		if unit != "" {
			if _, err := s.run(ctx, "systemctl", "", "disable", "--now", unitName); err != nil {
				return err
			}
		}
	}
	if err := s.restoreSysctls(ctx, previous, nil); err != nil {
		return err
	}
	if err := s.writeTable(ctx, table.Handle, ""); err != nil {
		return err
	}
	if s.host {
		if err := errors.Join(removeFile(unitPath), removeFile(s.sysctlFile)); err != nil {
			return err
		}
		if unit != "" {
			if _, err := s.run(ctx, "systemctl", "", "daemon-reload"); err != nil {
				return err
			}
		}
	}
	return removeFile(path)
}

func readState(path string) (state, string, error) {
	raw, err := readManagedFile(path, maxStateBytes)
	if err != nil || raw == "" {
		return state{}, "", err
	}
	s, err := parseState(raw)
	if err != nil {
		return state{}, "", fmt.Errorf("read %s: %w", path, err)
	}
	return s, raw, nil
}

func removeFile(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func newSystem() (relaySystem, error) {
	if os.Geteuid() != 0 {
		return relaySystem{}, errors.New("pipe relay requires root")
	}
	self, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return relaySystem{}, err
	}
	initial, err := os.Stat("/proc/1/ns/net")
	if err != nil {
		return relaySystem{}, err
	}
	// A separate network namespace has no separate systemd or /etc.
	return relaySystem{host: os.SameFile(self, initial), sysctlFile: sysctlPath, run: runSystemTool}, nil
}

func withSystem(path string, operation func(relaySystem, string) error) error {
	system, err := newSystem()
	if err != nil {
		return err
	}
	if path == "" {
		return errors.New("--state requires a file path")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	path = filepath.Join(dir, filepath.Base(path))
	if !system.host && path == DefaultStatePath {
		return errors.New("pipe relay in a network namespace requires a non-default --state file")
	}
	if path == unitPath || path == sysctlPath || path == "/run/pipe-relay.lock" {
		return errors.New("--state conflicts with a Pipe relay system file")
	}
	lockPath, flags := dir, unix.O_RDONLY|unix.O_DIRECTORY
	if system.host {
		lockPath, flags = "/run/pipe-relay.lock", unix.O_CREAT|unix.O_RDWR
	}
	fd, err := unix.Open(lockPath, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("lock Pipe relay: %w", err)
	}
	return operation(system, path)
}

func runSystemTool(ctx context.Context, name, input string, args ...string) (string, error) {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		path := filepath.Join(dir, name)
		if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
			continue
		}
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Stdin = strings.NewReader(input)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
		return string(output), nil
	}
	return "", fmt.Errorf("%s is required", name)
}

func (s relaySystem) ownedTable(ctx context.Context) (nftTable, error) {
	output, err := s.run(ctx, "nft", "", "-j", "-a", "list", "tables")
	if err != nil {
		return nftTable{}, err
	}
	table, err := readRelayTable(output)
	if err != nil || table.Name == "" {
		return table, err
	}
	output, err = s.run(ctx, "nft", "", "-n", "-t", "list", "table", "inet", tableName)
	if err != nil {
		return nftTable{}, err
	}
	// Older nft JSON output omits table comments.
	previous, owned := relayTableForwarding(output)
	if table.Handle == 0 || !owned {
		return nftTable{}, errors.New("inet pipe_relay already exists without the Pipe relay ownership comment")
	}
	if previous[ipv6Forward] == "0" && strings.Contains(output, "\n\tset "+raSetName+" {") {
		output, err := s.run(ctx, "nft", "", "-j", "list", "set", "inet", tableName, raSetName)
		if err != nil {
			return nftTable{}, err
		}
		names, err := readRelayRA(output)
		if err != nil {
			return nftTable{}, err
		}
		for _, name := range names {
			previous[raSysctl(name)] = "1"
		}
	}
	table.previous = previous
	return table, nil
}

func (s relaySystem) writeTable(ctx context.Context, handle uint64, rules string) error {
	batch := replaceTable(handle, rules)
	if batch == "" {
		return nil
	}
	_, err := s.run(ctx, "nft", batch, "-f", "-")
	return err
}

func (s relaySystem) ingress(ctx context.Context, routes []route) (ingress, error) {
	var incoming ingress
	for _, family := range []struct {
		flag    string
		devices *[]string
	}{
		{"-4", &incoming.IPv4},
		{"-6", &incoming.IPv6},
	} {
		var fallback []string
		for _, r := range routes {
			target := r.IPv4
			if family.flag == "-6" {
				target = r.IPv6
			}
			if !target.IsValid() {
				continue
			}
			output, err := s.run(ctx, "ip", "", "-j", family.flag, "route", "get", target.String())
			if err != nil {
				return ingress{}, err
			}
			devices, err := routeDevices(output)
			if err != nil {
				return ingress{}, err
			}
			if len(devices) == 0 {
				return ingress{}, fmt.Errorf("relay target %s needs a route through a non-loopback interface", target)
			}
			fallback = append(fallback, devices...)
		}
		if len(fallback) == 0 {
			continue
		}
		output, err := s.run(ctx, "ip", "", "-j", family.flag, "route", "show", "table", "main", "default")
		if err != nil {
			return ingress{}, err
		}
		*family.devices, err = routeDevices(output)
		if err != nil {
			return ingress{}, err
		}
		if len(*family.devices) == 0 {
			slices.Sort(fallback)
			*family.devices = slices.Compact(fallback)
		}
	}
	return incoming, nil
}

func uplinkHost(names []string, request Request) (host, hint string, err error) {
	var fallback netip.Addr
	for _, name := range names {
		link, err := net.InterfaceByName(name)
		if err != nil {
			return "", "", err
		}
		addresses, err := link.Addrs()
		if err != nil {
			return "", "", err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if ip.Is4() != request.IPv4.IsValid() || !request.validHost(ip.String()) {
				continue
			}
			if PublicTarget(ip) {
				return ip.String(), "", nil
			}
			if !fallback.IsValid() {
				fallback = ip
			}
		}
	}
	if !fallback.IsValid() {
		return "", "", errors.New("no relay address on the uplink interfaces; specify --host")
	}
	return fallback.String(), "The relay uplink has no public address. Use --host for its public IP or DNS name.", nil
}

func (s relaySystem) tunings(ctx context.Context, keys []string, previous map[string]string) ([]sysctlSetting, error) {
	var settings []sysctlSetting
	if s.host {
		value, err := s.readSysctl(ctx, conntrackMax)
		if err != nil {
			return nil, fmt.Errorf("read %s after loading relay rules: %w", conntrackMax, err)
		}
		limit, err := strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", conntrackMax, err)
		}
		settings = append(settings, sysctlSetting{"net.core.default_qdisc", "fq"},
			sysctlSetting{conntrackMax, strconv.Itoa(max(limit, 262144))})
	}
	for _, name := range savedRAInterfaces(previous) {
		settings = append(settings, sysctlSetting{raSysctl(name), "2"})
	}
	for _, key := range keys {
		settings = append(settings, sysctlSetting{key, "1"})
	}
	return settings, nil
}

func (s relaySystem) readSysctl(ctx context.Context, key string) (string, error) {
	value, err := s.run(ctx, "sysctl", "", "-n", key)
	return strings.TrimSpace(value), err
}

func (s relaySystem) readAcceptRA(ctx context.Context, key string) (string, error) {
	value, err := s.run(ctx, "sysctl", "", "-e", "-n", key)
	return strings.TrimSpace(value), err
}

func (s relaySystem) setSysctls(ctx context.Context, settings []sysctlSetting, ignoreMissing bool) error {
	if len(settings) == 0 {
		return nil
	}
	args := []string{"-w"}
	if ignoreMissing {
		args = append(args, "-e")
	}
	for _, setting := range settings {
		args = append(args, setting.key+"="+setting.value)
	}
	_, err := s.run(ctx, "sysctl", "", args...)
	return err
}

func (s relaySystem) applySysctls(ctx context.Context, settings []sysctlSetting) error {
	var ra, required []sysctlSetting
	for _, setting := range settings {
		if _, ok := raInterface(setting.key); ok {
			ra = append(ra, setting)
		} else {
			required = append(required, setting)
		}
	}
	// On boot the per-interface keys can appear after the unit runs.
	if err := s.setSysctls(ctx, ra, true); err != nil {
		return err
	}
	return s.setSysctls(ctx, required, false)
}

func (s relaySystem) sysctlBaseline(table nftTable) (map[string]string, error) {
	if s.host {
		data, err := readOwnedFile(s.sysctlFile)
		if err != nil {
			return nil, err
		}
		if data != "" {
			previous := priorSysctls(data)
			for key, value := range table.previous {
				if previous[key] == "" {
					previous[key] = value
				}
			}
			return previous, nil
		}
	}
	return table.previous, nil
}

func (s relaySystem) prepareSysctls(ctx context.Context, before map[string]string, keys, ipv6Ingress []string) (map[string]string, error) {
	previous := make(map[string]string, len(keys))
	for _, key := range keys {
		value := before[key]
		if value == "" {
			var err error
			value, err = s.readSysctl(ctx, key)
			if err != nil {
				return nil, err
			}
		}
		if !validForwarding(key, value) {
			return nil, fmt.Errorf("invalid %s state %q", key, value)
		}
		previous[key] = value
	}
	if previous[ipv6Forward] == "0" {
		for _, name := range ipv6Ingress {
			key := raSysctl(name)
			value, err := s.readAcceptRA(ctx, key)
			if err != nil {
				return nil, err
			}
			if value == "1" || (before[key] == "1" && (value == "2" || value == "")) {
				previous[key] = "1"
			}
		}
	}
	return previous, nil
}

func (s relaySystem) restoreSettings(ctx context.Context, previous, keep map[string]string) (reset, undo []sysctlSetting, err error) {
	for _, key := range []string{ipv4Forward, ipv6Forward} {
		if previous[key] != "0" || keep[key] != "" {
			continue
		}
		value, err := s.readSysctl(ctx, key)
		if err != nil {
			return nil, nil, err
		}
		if value == "1" {
			reset = append(reset, sysctlSetting{key, "0"})
			undo = append(undo, sysctlSetting{key, "1"})
		}
	}
	for _, name := range savedRAInterfaces(previous) {
		key := raSysctl(name)
		if keep[key] != "" {
			continue
		}
		value, err := s.readAcceptRA(ctx, key)
		if err != nil {
			return nil, nil, err
		}
		if value == "2" {
			reset = append(reset, sysctlSetting{key, "1"})
			undo = append(undo, sysctlSetting{key, "2"})
		}
	}
	return reset, undo, nil
}

func (s relaySystem) applyRestoration(ctx context.Context, settings []sysctlSetting) error {
	var forwarding, ra []sysctlSetting
	for _, setting := range settings {
		if _, ok := raInterface(setting.key); ok {
			ra = append(ra, setting)
		} else {
			forwarding = append(forwarding, setting)
		}
	}
	if err := s.setSysctls(ctx, forwarding, false); err != nil {
		return err
	}
	return s.setSysctls(ctx, ra, true)
}

func (s relaySystem) restoreSysctls(ctx context.Context, previous, keep map[string]string) error {
	reset, _, err := s.restoreSettings(ctx, previous, keep)
	if err != nil {
		return err
	}
	return s.applyRestoration(ctx, reset)
}

func readOwnedFile(path string) (string, error) {
	return readManagedFile(path, 64<<10)
}

func readManagedFile(path string, limit int64) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		return "", fmt.Errorf("%s must be a regular Pipe relay file writable only by its owner", path)
	}
	if st.Size > limit {
		return "", fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > limit {
		return "", fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	if !strings.HasPrefix(string(data), ownedHeader) {
		return "", fmt.Errorf("%s is not owned by Pipe relay", path)
	}
	return string(data), nil
}

func writeManagedFile(path, contents string) error {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(0644); err != nil {
		return err
	}
	if _, err := file.WriteString(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
