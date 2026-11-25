// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type UninstallOptions struct {
	Dir   string
	Purge bool
	Yes   bool
	// Confirm asks a yes/no question. Nil means stdin is not a terminal.
	Confirm func(prompt string) (bool, error)
	// Inform receives the report lines.
	Inform func(string)

	hooks *uninstallHooks
}

// uninstallHooks lets tests avoid the real system.
type uninstallHooks struct {
	systemdDir string
	sysctlDir  string
	systemctl  func(ctx context.Context, args ...string) error
	nft        func(ctx context.Context) error
	// otherNetns reports whether this process runs outside the initial
	// network namespace, where nft only sees its own tables.
	otherNetns func() bool
}

func inOtherNetns() bool {
	self, err1 := os.Readlink("/proc/self/ns/net")
	initial, err2 := os.Readlink("/proc/1/ns/net")
	return err1 == nil && err2 == nil && self != initial
}

func defaultUninstallHooks() *uninstallHooks {
	return &uninstallHooks{
		systemdDir: "/etc/systemd/system",
		sysctlDir:  "/etc/sysctl.d",
		systemctl: func(ctx context.Context, args ...string) error {
			output, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
			if err != nil && !errors.Is(err, exec.ErrNotFound) {
				return fmt.Errorf("systemctl %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
			}
			return err
		},
		nft:        func(ctx context.Context) error { return setHopTable(ctx, "", 0) },
		otherNetns: inOtherNetns,
	}
}

func Uninstall(ctx context.Context, opts UninstallOptions) error {
	hooks := opts.hooks
	if hooks == nil {
		hooks = defaultUninstallHooks()
	}
	inform := opts.Inform
	if inform == nil {
		inform = func(string) {}
	}
	purgeDir := ""
	if opts.Purge {
		var err error
		if purgeDir, err = purgeTarget(opts.Dir); err != nil {
			return err
		}
		if !opts.Yes {
			if opts.Confirm == nil {
				return errors.New("--purge needs a terminal to confirm. Use --yes to skip the question")
			}
			ok, err := opts.Confirm(fmt.Sprintf("Delete %s and all device keys? [y/N]", purgeDir))
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("purge cancelled")
			}
		}
	}
	ours, foreign := uninstallUnits(ctx, opts.Dir, hooks, inform)
	if foreign != "" && !hooks.otherNetns() {
		inform("Kept the Fast hopping table: it belongs to the install at " + foreign)
	} else {
		if err := hooks.nft(ctx); err != nil {
			return err
		}
		inform("Removed the Fast port hopping table.")
	}
	if ours {
		path := filepath.Join(hooks.sysctlDir, "90-pipe.conf")
		if data, err := os.ReadFile(path); err == nil && string(data) == sysctlConfig {
			if err := os.Remove(path); err == nil {
				inform("Removed " + path + ".")
			}
		}
	}
	inform("Kernel settings stay applied until reboot.")
	inform("The binary at /usr/local/bin/pipe is kept.")
	if dir, err := filepath.Abs(opts.Dir); err == nil {
		if _, err := os.Stat(filepath.Join(dir, "install", "pipe-nginx.conf")); err == nil {
			inform("Remove the pipe-nginx.conf you copied into nginx, then reload nginx.")
		}
	}
	if opts.Purge {
		if err := os.RemoveAll(purgeDir); err != nil {
			return err
		}
		inform("Deleted " + purgeDir + ".")
	}
	return nil
}

// uninstallUnits removes pipe's own units. It reports whether pipe.service was
// ours. If an installed pipe.service belongs to another state directory, it
// returns that directory and leaves every unit alone.
func uninstallUnits(ctx context.Context, dir string, hooks *uninstallHooks, inform func(string)) (bool, string) {
	state, err := filepath.Abs(dir)
	if err != nil {
		inform("No server state found, so systemd units were left alone.")
		return false, ""
	}
	fastHop := ""
	if settings, err := ReadSettings(dir); err == nil {
		fastHop = settings.FastHop
	}
	const pipeMarker = "Description=Pipe server"
	pipePath := filepath.Join(hooks.systemdDir, "pipe.service")
	pipeData, err := os.ReadFile(pipePath)
	installed := err == nil && strings.Contains(string(pipeData), pipeMarker)
	pipeOurs := installed && strings.Contains(string(pipeData), "server run --dir "+unitArgument(state))
	if installed && !pipeOurs {
		return false, unitStateDir(string(pipeData))
	}
	type unit struct {
		name, marker string
		matches      []string
	}
	var units []unit
	if pipeOurs {
		units = append(units, unit{"pipe.service", pipeMarker, []string{"server run --dir " + unitArgument(state)}})
		// The hop unit is only ever removed together with this dir's pipe.service.
		matches := []string{"hop-apply --dir " + unitArgument(state)}
		if fastHop != "" {
			matches = append(matches, "--fast-hop "+fastHop+" ")
		}
		units = append(units, unit{"pipe-hop.service", "Description=Pipe Fast UDP port hopping", matches})
	}
	var removed []string
	for _, unit := range units {
		path := filepath.Join(hooks.systemdDir, unit.name)
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), unit.marker) {
			continue
		}
		found := false
		for _, match := range unit.matches {
			found = found || strings.Contains(string(data), match)
		}
		if !found {
			continue
		}
		if err := hooks.systemctl(ctx, "disable", "--now", unit.name); err != nil && !errors.Is(err, exec.ErrNotFound) {
			inform("Warning: " + err.Error())
		}
		if err := os.Remove(path); err != nil {
			inform("Warning: " + err.Error())
			continue
		}
		removed = append(removed, unit.name)
		inform("Removed " + path + ".")
	}
	if len(removed) > 0 {
		if err := hooks.systemctl(ctx, "daemon-reload"); err != nil && !errors.Is(err, exec.ErrNotFound) {
			inform("Warning: " + err.Error())
		}
	}
	return pipeOurs, ""
}

func unitStateDir(unit string) string {
	for line := range strings.SplitSeq(unit, "\n") {
		if _, rest, ok := strings.Cut(line, "server run --dir "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return "another state directory"
}

// purgeTarget resolves the state directory and refuses anything that is not
// clearly a pipe state directory.
func purgeTarget(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	switch resolved {
	case "/", "/root", "/home", "/etc", "/usr", "/var", "/var/lib", "/tmp":
		return "", fmt.Errorf("refusing to purge %s", resolved)
	}
	parts := 0
	for part := range strings.SplitSeq(filepath.ToSlash(resolved), "/") {
		if part != "" {
			parts++
		}
	}
	if parts < 2 {
		return "", fmt.Errorf("refusing to purge %s", resolved)
	}
	if info, err := os.Stat(filepath.Join(resolved, "server.json")); err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s has no server.json, so it is not a pipe state directory", resolved)
	}
	return resolved, nil
}
