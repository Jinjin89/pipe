// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux

package hostupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"pipe/internal/clientctl"
	"pipe/internal/helper"
	"pipe/internal/localfile"
	"pipe/internal/update"
	"pipe/internal/version"
)

const (
	systemUpdateState = "/var/lib/pipe-update"
	systemUpdateLock  = "/run/pipe-update.lock"
)

type linuxHost struct {
	root           string // empty on a real host
	uid            int
	command        func(context.Context, string, ...string) (string, error)
	checkTrusted   func(string) error
	trustedRunning func(string) (*os.File, error)
	resolve        func(context.Context, update.ResolveOptions) (update.StagedRelease, error)
	install        func(*os.File, string) error
	helperStatus   func() clientctl.Status
	helperReady    func(string) bool
}

func run(ctx context.Context, opts Options) error {
	host := linuxHost{
		uid: os.Geteuid(), command: runSystemctl, checkTrusted: localfile.CheckTrustedFile,
		trustedRunning: localfile.OpenTrustedRunningImage, resolve: update.Resolve,
		install: localfile.InstallOwnerExecutable,
		helperStatus: func() clientctl.Status {
			return helper.NewRemote(helper.RemoteOptions{Version: version.Version}).Status()
		},
		helperReady: func(want string) bool {
			return helper.NewRemote(helper.RemoteOptions{Version: want}).Info().Version == want
		},
	}
	if host.uid == 0 {
		host.install = localfile.InstallTrustedExecutable
	}
	return host.run(ctx, opts)
}

func (h linuxHost) path(path string) string {
	if h.root == "" {
		return path
	}
	return filepath.Join(h.root, strings.TrimPrefix(path, "/"))
}

type linuxInventory struct {
	system                  bool
	stateDir, lockPath, ctl string
	targets                 []string
	units                   []unitState
}

func (i linuxInventory) sameTargets(other linuxInventory) bool {
	return i.lockPath == other.lockPath && slices.Equal(i.targets, other.targets)
}

func (h linuxHost) inventory(ctx context.Context) (linuxInventory, error) {
	paths, _ := helper.PathsFor("linux")
	roles := managedRoles(paths.Binary)
	ctl, err := h.systemctlPath()
	if err != nil {
		return linuxInventory{}, err
	}
	inv := linuxInventory{ctl: ctl}
	for _, logical := range []string{pipeBinary, relayBinary, paths.Binary} {
		path := h.path(logical)
		if _, err := os.Lstat(path); err == nil {
			inv.targets = append(inv.targets, path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return inv, err
		}
	}
	if ctl == "" {
		if err := h.rejectOfflineUnits(roles); err != nil {
			return inv, err
		}
	} else {
		for _, role := range roles {
			unit, err := h.inspectUnit(ctx, ctl, role)
			if err != nil {
				return inv, err
			}
			if unit.binary == "" {
				continue
			}
			if !slices.Contains(inv.targets, unit.binary) {
				return inv, fmt.Errorf("%s references a missing executable at %s", role.name, unit.binary)
			}
			inv.units = append(inv.units, unit)
		}
	}
	if len(inv.targets) != 0 {
		inv.system, inv.stateDir, inv.lockPath = true, h.path(systemUpdateState), h.path(systemUpdateLock)
		return inv, nil
	}
	path, err := h.executable()
	if err != nil {
		return inv, err
	}
	for _, dir := range []string{"/usr/bin", "/bin", "/sbin", "/usr/sbin"} {
		if strings.HasPrefix(path, h.path(dir)+"/") {
			return inv, fmt.Errorf("%s is a package-managed location. Use the system package manager to update Pipe", path)
		}
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return inv, err
	}
	if !filepath.IsAbs(configDir) {
		return inv, errors.New("the Pipe update state directory must be an absolute path")
	}
	inv.stateDir = filepath.Join(configDir, "pipe", "updates")
	inv.lockPath = filepath.Join(inv.stateDir, "update.lock")
	inv.targets = []string{path}
	return inv, nil
}

func (h linuxHost) executable() (string, error) {
	path, err := os.Readlink(h.path("/proc/self/exe"))
	if err != nil {
		return "", fmt.Errorf("locate the running Pipe executable: %w", err)
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("the running Pipe executable has no absolute path")
	}
	return filepath.Clean(path), nil
}

func (h linuxHost) run(ctx context.Context, opts Options) error {
	request, err := resolveOptions(opts)
	if err != nil {
		return err
	}
	inv, err := h.inventory(ctx)
	if err != nil {
		return err
	}
	if !opts.Check {
		if inv.system && h.uid != 0 {
			return errors.New("run sudo pipe update to update the system installation")
		}
		if h.uid == 0 {
			current, err := h.executable()
			if err != nil {
				return err
			}
			image, err := h.trustedRunning(current)
			if err != nil {
				return fmt.Errorf("run the update from a root-protected Pipe executable: %w", err)
			}
			defer image.Close()
		}
		unlock, err := lockUpdate(ctx, inv.lockPath, !inv.system)
		if err != nil {
			return err
		}
		defer unlock()
		locked, err := h.inventory(ctx)
		if err != nil {
			return err
		}
		if !inv.sameTargets(locked) {
			return errors.New("the Pipe installation changed while taking the update lock. Run pipe update again")
		}
		inv = locked
	}

	installed, err := h.openInstalled(inv, request.Target)
	if err != nil {
		return err
	}
	defer installed.close()
	request.Installed, request.Newest = installed.oldest, installed.newest
	request.StateDir = inv.stateDir
	request.ReadOnlyState = opts.Check && inv.system && h.uid != 0
	stateUnverified := request.ReadOnlyState && unreadableHostState(request.StateDir)
	if stateUnverified {
		request.StateDir = ""
	}
	release, err := h.resolve(ctx, request)
	if err != nil {
		return err
	}
	defer cleanStage(release)
	var pendingTargets []installedBinary
	if !release.Current {
		pendingTargets, err = installed.olderThan(release.Version)
		if err != nil {
			return err
		}
	}
	if opts.Check {
		release.StateUnverified = release.StateUnverified || stateUnverified
		return printCheck(opts.Out, installed, pendingTargets, unitsForTargets(inv.units, pendingTargets), release)
	}
	if len(pendingTargets) == 0 {
		_, err := fmt.Fprintf(opts.Out, "Pipe %s is already up to date.\n", installed.newest)
		return err
	}

	// A daemon may have started or a unit may have changed during download.
	ready, err := h.inventory(ctx)
	if err != nil {
		return err
	}
	if !inv.sameTargets(ready) {
		return errors.New("the Pipe installation changed while staging the update. Run pipe update again")
	}
	ready.units = unitsForTargets(ready.units, pendingTargets)
	if err := h.requireIdleHelper(ready.units); err != nil {
		return err
	}
	if err := h.publish(ctx, ready, pendingTargets, request.Target.ABI, release); err != nil {
		return err
	}
	return printUpdated(opts.Out, pendingTargets, ready.units, release.Version)
}

func unitsForTargets(units []unitState, targets []installedBinary) []unitState {
	var affected []unitState
	for _, unit := range units {
		if slices.ContainsFunc(targets, func(target installedBinary) bool { return target.path == unit.binary }) {
			affected = append(affected, unit)
		}
	}
	return affected
}

func (h linuxHost) requireIdleHelper(units []unitState) error {
	for _, unit := range units {
		if unit.role.name == helper.UnitName && unit.active {
			status := h.helperStatus()
			if status.State != clientctl.StateOff || status.Guarded {
				return errors.New("Disconnect and Quit Pipe before updating the active Pipe Helper")
			}
		}
	}
	return nil
}

func printCheck(out io.Writer, installed installedSet, pendingTargets []installedBinary, units []unitState, release update.StagedRelease) error {
	var plan strings.Builder
	for _, copy := range installed.copies {
		fmt.Fprintf(&plan, "Installed Pipe %s at %s\n", copy.version, copy.path)
	}
	if len(pendingTargets) == 0 {
		fmt.Fprintf(&plan, "Pipe %s is already up to date.\n", installed.newest)
	} else {
		fmt.Fprintf(&plan, "Offered Pipe %s\n", release.Version)
		for _, target := range pendingTargets {
			fmt.Fprintf(&plan, "Would update %s\n", target.path)
		}
		for _, unit := range units {
			if unit.role.daemon && unit.active {
				fmt.Fprintf(&plan, "Would restart %s\n", unit.role.name)
			}
		}
		printOneshotNotes(&plan, units)
	}
	if release.StateUnverified {
		fmt.Fprintln(&plan, "The host rollback record could not be verified. Run sudo pipe update --check to read it.")
	}
	_, err := io.WriteString(out, plan.String())
	return err
}

func printUpdated(out io.Writer, targets []installedBinary, units []unitState, release string) error {
	var summary strings.Builder
	fmt.Fprintf(&summary, "Updated Pipe to %s\n", release)
	for _, target := range targets {
		fmt.Fprintf(&summary, "Updated %s\n", target.path)
	}
	for _, unit := range units {
		if unit.role.daemon && unit.active {
			fmt.Fprintf(&summary, "Restarted %s\n", unit.role.name)
		}
	}
	printOneshotNotes(&summary, units)
	_, err := io.WriteString(out, summary.String())
	return err
}

func printOneshotNotes(out *strings.Builder, units []unitState) {
	for _, unit := range units {
		if !unit.role.daemon {
			fmt.Fprintf(out, "%s will use the new binary on the next apply or boot.\n", unit.role.name)
		}
	}
}
