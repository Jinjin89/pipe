// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import "pipe/internal/helper"

// In-process control for front ends that live in this process, such as the
// macOS menu bar (§8.5). They use the same paths as the HTTP API.

// Snapshot is GET /api/status.
func (s *Server) Snapshot() StatusResponse { return s.status() }

// Connect is POST /api/connect.
func (s *Server) Connect() error { _, err := s.connect(); return err }

// Disconnect is POST /api/disconnect.
func (s *Server) Disconnect() error { _, err := s.disconnect(); return err }

// SetMode is PUT /api/mode.
func (s *Server) SetMode(mode string) error { _, err := s.setMode(mode); return err }

// SetTier is PUT /api/tier.
func (s *Server) SetTier(tier string) error { _, err := s.setTier(tier); return err }

// SetSystemProxy changes the System proxy setting, live when connected.
func (s *Server) SetSystemProxy(on bool) error {
	next := s.Settings()
	next.SystemProxy = on
	_, err := s.updateSettings(next)
	return err
}

// SetTUN chooses TUN or the system proxy, installing Pipe Helper first when
// needed (this blocks on the OS password prompt), and reconnects when
// connected.
func (s *Server) SetTUN(on bool) error {
	if on && s.cfg.Helper != nil && s.cfg.Helper.Info().State != helper.StateOK {
		if err := s.cfg.Helper.Install(); err != nil {
			return err
		}
	}
	next := s.Settings()
	next.TUN = on
	_, err := s.updateSettings(next)
	return err
}
