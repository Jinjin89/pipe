// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux

package hostupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pipe/internal/helper"
)

const (
	pipeBinary  = "/usr/local/bin/pipe"
	relayBinary = "/usr/local/libexec/pipe-relay"
	unitShow    = "--property=LoadState,ActiveState,FragmentPath,DropInPaths,ExecStart,MainPID"
)

type unitRole struct {
	name, binary, command, subcommand string
	daemon                            bool
}

func managedRoles(helperBinary string) []unitRole {
	return []unitRole{
		{"pipe.service", pipeBinary, "server", "run", true},
		{helper.UnitName, helperBinary, "helper", "run", true},
		{"pipe-relay.service", relayBinary, "relay", "apply", false},
		{"pipe-hop.service", pipeBinary, "server", "hop-apply", false},
	}
}

type unitState struct {
	role   unitRole
	binary string
	active bool
	pid    int
}

func (h linuxHost) systemctlPath() (string, error) {
	// systemctl may be installed on a host booted with a different init system.
	booted, err := os.Stat(h.path("/run/systemd/system"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !booted.IsDir() {
		return "", errors.New("/run/systemd/system is not a directory")
	}
	for _, path := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		candidate := h.path(path)
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			resolved, err := filepath.EvalSymlinks(candidate)
			if err != nil {
				return "", err
			}
			if err := h.checkTrusted(resolved); err != nil {
				return "", fmt.Errorf("untrusted systemctl executable: %w", err)
			}
			return candidate, nil
		}
	}
	return "", errors.New("systemd is running but systemctl is unavailable")
}

func runSystemctl(ctx context.Context, path string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "SYSTEMD_PAGER=cat"}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (h linuxHost) inspectUnit(ctx context.Context, ctl string, role unitRole) (unitState, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := h.command(ctx, ctl, "show", unitShow, role.name)
	if ctx.Err() != nil {
		return unitState{}, fmt.Errorf("inspect %s: %w", role.name, ctx.Err())
	}
	properties := make(map[string]string)
	for line := range strings.SplitSeq(out, "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			properties[key] = strings.TrimSuffix(value, "\r")
		}
	}
	load := properties["LoadState"]
	fragment := properties["FragmentPath"]
	execStart := properties["ExecStart"]
	if load == "not-found" && fragment == "" && execStart == "" {
		return unitState{}, nil
	}
	if err != nil {
		return unitState{}, fmt.Errorf("inspect %s: %w", role.name, err)
	}
	if load != "loaded" || fragment == "" || properties["ActiveState"] == "" {
		return unitState{}, fmt.Errorf("cannot verify the installed %s unit", role.name)
	}
	for _, path := range append([]string{fragment}, strings.Fields(properties["DropInPaths"])...) {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return unitState{}, fmt.Errorf("%s contains an invalid unit file path", role.name)
		}
		if err := h.checkTrusted(h.path(path)); err != nil {
			return unitState{}, fmt.Errorf("untrusted %s configuration at %s: %w", role.name, path, err)
		}
	}
	binary, ok := unitExecutable(execStart, role)
	if !ok {
		return unitState{}, fmt.Errorf("%s has an unexpected ExecStart for the Pipe %s %s role", role.name, role.command, role.subcommand)
	}
	pid, _ := strconv.Atoi(properties["MainPID"])
	return unitState{role: role, binary: h.path(binary), active: properties["ActiveState"] == "active", pid: pid}, nil
}

func unitExecutable(start string, role unitRole) (string, bool) {
	// systemctl show prints one structured entry per ExecStart command.
	start = strings.TrimSpace(start)
	rest, ok := strings.CutPrefix(start, "{ path=")
	if !ok || !strings.HasSuffix(start, "}") || strings.Contains(rest, "{ path=") {
		return "", false
	}
	binary, rest, ok := strings.Cut(rest, " ; argv[]=")
	legacyRelay := role.binary == relayBinary && binary == pipeBinary
	if !ok || (binary != role.binary && !legacyRelay) {
		return "", false
	}
	argv, _, ok := strings.Cut(rest, " ; ")
	args := strings.Fields(argv)
	return binary, ok && len(args) >= 3 && args[0] == binary && args[1] == role.command && args[2] == role.subcommand
}

func (h linuxHost) rejectOfflineUnits(roles []unitRole) error {
	for _, dir := range []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
		for _, role := range roles {
			path := h.path(filepath.Join(dir, role.name))
			if _, err := os.Lstat(path); err == nil {
				return fmt.Errorf("cannot verify %s without a running systemd", role.name)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func (h linuxHost) restartDaemon(ctx context.Context, ctl, action string, original unitState, wantVersion string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	before, err := h.inspectUnit(ctx, ctl, original.role)
	if err != nil {
		return err
	}
	if before.binary != original.binary {
		return fmt.Errorf("%s changed before restart", original.role.name)
	}
	if _, err := h.command(ctx, ctl, action, original.role.name); err != nil {
		return fmt.Errorf("%s %s: %w", action, original.role.name, err)
	}
	wantFile, err := os.Stat(original.binary)
	if err != nil {
		return err
	}
	lastPID := 0
	for {
		current, err := h.inspectUnit(ctx, ctl, original.role)
		if err != nil {
			return err
		}
		if current.binary != original.binary {
			return fmt.Errorf("%s changed while restarting", original.role.name)
		}
		if current.active && current.pid > 0 && h.runningNewImage(current.pid, before.pid, wantFile) {
			if current.pid == lastPID && (original.role.name != helper.UnitName || h.helperReady(wantVersion)) && ctx.Err() == nil {
				return nil
			}
			lastPID = current.pid
		} else {
			lastPID = 0
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("%s did not become active on the new executable: %w", original.role.name, ctx.Err())
		case <-timer.C:
		}
	}
}

func (h linuxHost) runningNewImage(pid, previousPID int, want os.FileInfo) bool {
	proc := h.path(filepath.Join("/proc", strconv.Itoa(pid)))
	image, err := os.Stat(filepath.Join(proc, "exe"))
	if err == nil {
		return os.SameFile(image, want)
	}
	// A service under another UID may hide its exe from /proc. A new live
	// MainPID then provides the restart confirmation.
	if pid == previousPID || !errors.Is(err, os.ErrPermission) {
		return false
	}
	info, err := os.Stat(proc)
	return err == nil && info.IsDir()
}
