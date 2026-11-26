// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"pipe/internal/clientctl"
	"pipe/internal/helper"
	"pipe/internal/localfile"
	"pipe/internal/update"
	"pipe/internal/version"
)

type desktopUpdates = update.Manager

type updateStatusResponse struct {
	update.Status
	CanApply       bool   `json:"canApply,omitempty"`
	AppliedVersion string `json:"appliedVersion,omitempty"`
	InstallHint    string `json:"installHint,omitempty"`
}

func newDesktopUpdates(s *Server) *desktopUpdates {
	installed := s.cfg.Version
	if installed == "" {
		installed = version.Version
	}
	// Select the asset using the same build identity the release signer reads.
	var target update.Target
	if fields := strings.Fields(version.ReleaseIdentity); len(fields) == 4 {
		target = update.Target{OS: fields[1], ABI: fields[2]}
	}
	return update.NewManager(installed, target, filepath.Join(s.cfg.Dir, "updates"))
}

func updateInstallPolicy(goos, exe string) (canApply bool, hint string) {
	switch goos {
	case "linux":
		if !path.IsAbs(exe) {
			return false, ""
		}
		if hint := linuxUpdateHint(path.Clean(exe)); hint != "" {
			return false, hint
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			hint = linuxUpdateHint(resolved)
		}
		return hint == "", hint
	case "darwin":
		return false, "Quit Pipe, then replace Pipe.app in Applications."
	case "windows":
		return false, "Quit Pipe, then replace Pipe.exe and pipe-cli.exe together."
	default:
		return false, ""
	}
}

func linuxUpdateHint(exe string) string {
	if exe == "/usr/local/bin/pipe" {
		return "Run sudo pipe update to install."
	}
	for _, dir := range []string{"/usr/bin/", "/bin/", "/sbin/", "/usr/sbin/"} {
		if strings.HasPrefix(exe, dir) {
			return "Update Pipe with your system package manager."
		}
	}
	return ""
}

func (s *Server) updateResponse(status update.Status) updateStatusResponse {
	canApply, hint := updateInstallPolicy(runtime.GOOS, s.cfg.Exe)
	s.mu.Lock()
	defer s.mu.Unlock()
	return updateStatusResponse{
		Status: status, CanApply: canApply, AppliedVersion: s.appliedUpdate, InstallHint: hint,
	}
}

func (s *Server) updateRoute() update.Route {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := s.active()
	if active == nil {
		return update.UnavailableRoute(update.ErrTunnelUnavailable)
	}
	status := active.Status()
	if s.getVia() == "" && status.State == clientctl.StateOff && !status.Guarded {
		switch s.helperInfo().State {
		case helper.StateMissing, helper.StateUnsupported:
			return update.DirectRoute()
		}
		active = s.cfg.Helper
		status = active.Status()
		if status.State == clientctl.StateOff && !status.Guarded {
			return update.DirectRoute()
		}
	}
	if status.State != clientctl.StateOn || status.Guarded {
		return update.UnavailableRoute(update.ErrTunnelUnavailable)
	}
	routes, ok := active.(interface{ UpdateRoute() update.Route })
	if !ok {
		return update.UnavailableRoute(update.ErrTunnelUnavailable)
	}
	return routes.UpdateRoute()
}

func (s *Server) updateStatus(r *http.Request) (any, error) {
	return s.updateResponse(s.updates.StatusAfterRestore(r.Context())), nil
}

func (s *Server) checkUpdate(r *http.Request) (any, error) {
	var input struct {
		Automatic bool `json:"automatic"`
	}
	if r.ContentLength != 0 {
		if err := readJSON(r, &input, 1024); err != nil {
			return nil, err
		}
	}
	if enabled := s.Settings().UpdateAuto; input.Automatic && enabled != nil && !*enabled {
		return s.updateStatus(r)
	}
	status := s.updates.CheckWithRoute(s.updateRoute, input.Automatic)
	if status.State == "available" && status.Verifying {
		return s.updateStatus(r)
	}
	return s.updateResponse(status), nil
}

func (s *Server) downloadUpdate(*http.Request) (any, error) {
	return s.updateResponse(s.updates.DownloadWithRoute(s.updateRoute)), nil
}

func (s *Server) applyUpdate(r *http.Request) (any, error) {
	if canApply, hint := updateInstallPolicy(runtime.GOOS, s.cfg.Exe); !canApply {
		if hint == "" {
			hint = "In-place installation is only available for portable Linux builds."
		}
		return nil, bad(hint)
	}
	var input struct {
		Artifact string `json:"artifact"`
	}
	if err := readJSON(r, &input, 1024); err != nil {
		return nil, err
	}

	exe, err := filepath.EvalSymlinks(s.cfg.Exe)
	if err != nil || !matchesRunningExecutable(exe) {
		return nil, bad("The install path does not match the running Pipe executable.")
	}
	if hint := linuxUpdateHint(exe); hint != "" {
		return nil, bad(hint)
	}
	extract := s.cfg.extractUpdate
	if extract == nil {
		extract = s.updates.ExtractVerifiedLinuxBinary
	}
	bin, ver, cleanup, err := extract(input.Artifact)
	if err != nil {
		return nil, bad(err.Error())
	}
	defer cleanup()

	// A concurrent apply or a path change during extraction invalidates the
	// earlier inode check. Serialize publication with apply and shutdown.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, bad("Pipe is quitting.")
	}
	if s.appliedUpdate != "" {
		return nil, bad("An update is already installed. Quit and reopen Pipe to use it.")
	}
	if !matchesRunningExecutable(exe) {
		return nil, bad("The install path does not match the running Pipe executable.")
	}
	applyPortable := s.cfg.applyPortable
	if applyPortable == nil {
		applyPortable = localfile.InstallOwnerExecutable
	}
	if err := applyPortable(bin, exe); err != nil {
		return nil, bad("Could not install the update. " + err.Error())
	}
	s.appliedUpdate = ver
	return updateStatusResponse{Status: s.updates.Status(), CanApply: true, AppliedVersion: ver}, nil
}

func matchesRunningExecutable(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	running, err := os.Stat("/proc/self/exe")
	return err == nil && os.SameFile(running, info)
}

func (s *Server) revealUpdate(r *http.Request) (any, error) {
	var input struct {
		Artifact string `json:"artifact"`
	}
	if err := readJSON(r, &input, 1024); err != nil {
		return nil, err
	}
	path, err := s.updates.Resolve(input.Artifact)
	if err != nil {
		return nil, bad(err.Error())
	}
	return nil, revealUpdateFile(path)
}

func revealUpdateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("The verified download is unavailable.")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("/usr/bin/open", "-R", path)
	case "windows":
		cmd = exec.Command("explorer.exe", "/select,", path)
	default:
		cmd = exec.Command("xdg-open", filepath.Dir(path))
	}
	if err := cmd.Start(); err != nil {
		return errors.New("Could not open the file manager.")
	}
	go cmd.Wait()
	return nil
}
