// SPDX-License-Identifier: GPL-3.0-or-later

// Package sysproxy sets and restores the operating system's proxy settings.
//
// Before changing anything it saves the previous values to an "armed" file, so
// a crash can be repaired on the next start.
package sysproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"pipe/internal/localfile"
)

// ErrUnsupported means this system has no supported proxy settings.
var ErrUnsupported = errors.New("system proxy is not supported here")

// Bypass lists local and private addresses on every OS.
var bypassAddresses = []string{
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
	"::1", "fe80::/10", "fc00::/7",
}

// Backend talks to one OS. Saved state is opaque JSON owned by the backend.
type Backend interface {
	// Capture returns the current settings in a form Restore understands.
	Capture() (json.RawMessage, error)
	Apply(host string, port int) error
	Restore(saved json.RawMessage) error
	// RestoreIfApplied is used by crash repair: it restores only the parts
	// that still point at host:port and keeps going past per-part errors.
	RestoreIfApplied(saved json.RawMessage, host string, port int) error
	// IsApplied reports whether the OS proxy still points at host:port.
	IsApplied(host string, port int) bool
}

// Manager applies a proxy and guarantees a way back.
type Manager struct {
	mu        sync.Mutex
	backend   Backend
	armedPath string
}

// New returns a manager. A nil backend reports ErrUnsupported.
func New(backend Backend, armedPath string) *Manager {
	return &Manager{backend: backend, armedPath: armedPath}
}

// Supported reports whether Set can work on this system.
func (m *Manager) Supported() bool { return m.backend != nil }

type armedFile struct {
	Saved json.RawMessage `json:"saved"`
	Host  string          `json:"host"`
	Port  int             `json:"port"`
}

// Set points the OS proxy at host:port. Calling it again while armed keeps the
// original saved values.
func (m *Manager) Set(host string, port int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend == nil {
		return ErrUnsupported
	}
	var saved json.RawMessage
	if data, err := ReadPrivate(m.armedPath); err == nil {
		var existing armedFile
		if json.Unmarshal(data, &existing) == nil && len(existing.Saved) > 0 {
			saved = existing.Saved // keep the original values; only the address changes
		}
	}
	if saved == nil {
		captured, err := m.backend.Capture()
		if err != nil {
			return err
		}
		saved = captured
	}
	data, err := json.Marshal(armedFile{Saved: saved, Host: host, Port: port})
	if err != nil {
		return err
	}
	if err := writeFile(m.armedPath, data); err != nil {
		return fmt.Errorf("save previous proxy settings: %w", err)
	}
	if err := m.backend.Apply(host, port); err != nil {
		_ = m.restoreLocked(false)
		return err
	}
	return nil
}

// Clear restores the saved settings. It does nothing when not armed.
func (m *Manager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreLocked(false)
}

// Repair restores settings left behind by a crash.
// It restores only if the OS proxy still points at pipe's own address, so a
// proxy the user changed since is never overwritten.
func (m *Manager) Repair() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreLocked(true)
}

// Armed reports whether settings are currently saved for restoring.
func (m *Manager) Armed() bool {
	_, err := os.Stat(m.armedPath)
	return err == nil
}

func (m *Manager) restoreLocked(onlyIfOurs bool) error {
	data, err := ReadPrivate(m.armedPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if m.backend == nil {
		return nil
	}
	var file armedFile
	if err := json.Unmarshal(data, &file); err != nil {
		_ = os.Remove(m.armedPath)
		return fmt.Errorf("proxy.armed is damaged and was removed: %w", err)
	}
	if onlyIfOurs {
		err := m.backend.RestoreIfApplied(file.Saved, file.Host, file.Port)
		if rmErr := os.Remove(m.armedPath); err == nil {
			err = rmErr
		}
		return err
	}
	if err := m.backend.Restore(file.Saved); err != nil {
		return err
	}
	return os.Remove(m.armedPath)
}

// ReadPrivate reads an owner-only regular file and refuses symlinks.
func ReadPrivate(path string) ([]byte, error) { return ReadPrivateLimit(path, 64<<10) }

// ReadPrivateLimit is ReadPrivate with a size limit.
func ReadPrivateLimit(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must not be a symlink", path)
	}
	return localfile.Read(path, limit, true)
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".armed-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(name, 0600)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}

// restoreIfApplied is the all-or-nothing form used by backends without parts.
func restoreIfApplied(b Backend, saved json.RawMessage, host string, port int) error {
	if !b.IsApplied(host, port) {
		return nil
	}
	return b.Restore(saved)
}
