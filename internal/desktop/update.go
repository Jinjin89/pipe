// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"pipe/internal/clientctl"
	"pipe/internal/helper"
	"pipe/internal/update"
	"pipe/internal/version"
)

type desktopUpdates = update.Manager

const desktopReleasePrefix = "\x00pipe-desktop-release-v1 " + runtime.GOOS + " " + runtime.GOARCH + " "

// The release signer reads this marker from each packaged executable.
var desktopReleaseIdentity = desktopReleasePrefix + version.Version + "\x00"

func newDesktopUpdates(s *Server) *desktopUpdates {
	installed := s.cfg.Version
	if installed == "" {
		installed = desktopReleaseIdentity[len(desktopReleasePrefix) : len(desktopReleaseIdentity)-1]
	}
	return update.NewManager(installed, update.Target{OS: runtime.GOOS, ABI: runtime.GOARCH},
		filepath.Join(s.cfg.Dir, "updates"))
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
	return s.updates.StatusAfterRestore(r.Context()), nil
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
	return status, nil
}

func (s *Server) downloadUpdate(*http.Request) (any, error) {
	return s.updates.DownloadWithRoute(s.updateRoute), nil
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
