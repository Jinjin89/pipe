// SPDX-License-Identifier: GPL-3.0-or-later

// Package sysproxy sets and restores the operating system's proxy settings.
//
// Before changing anything it saves the previous values to an "armed" file, so
// a crash can be repaired on the next start.
package sysproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

type extender interface {
	Extend(json.RawMessage) (json.RawMessage, error)
}

var errServicesChanged = errors.New("enabled network services changed while setting the system proxy")

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
	data, err := ReadPrivate(m.armedPath)
	switch {
	case err == nil:
		var existing armedFile
		if err := json.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("proxy.armed is damaged: %w", err)
		}
		if len(existing.Saved) == 0 || bytes.Equal(bytes.TrimSpace(existing.Saved), []byte("null")) {
			return errors.New("proxy.armed is damaged: saved proxy settings are missing")
		}
		saved = existing.Saved
		if backend, ok := m.backend.(extender); ok {
			saved, err = backend.Extend(saved)
			if err != nil {
				return err
			}
		}
	case errors.Is(err, os.ErrNotExist):
		saved, err = m.backend.Capture()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("read proxy.armed: %w", err)
	}
	file := armedFile{Saved: saved, Host: host, Port: port}
	if err := m.saveArmed(file); err != nil {
		return err
	}
	if err := m.apply(file); err != nil {
		return errors.Join(err, m.restoreLocked(false))
	}
	return nil
}

func (m *Manager) saveArmed(file armedFile) error {
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	if err := localfile.WritePrivateAtomic(m.armedPath, data); err != nil {
		return fmt.Errorf("save previous proxy settings: %w", err)
	}
	return nil
}

func (m *Manager) apply(file armedFile) error {
	backend, ok := m.backend.(interface {
		extender
		applySaved(json.RawMessage, string, int) error
	})
	if !ok {
		return m.backend.Apply(file.Host, file.Port)
	}
	const maxRetries = 2
	for retries := 0; ; retries++ {
		err := backend.applySaved(file.Saved, file.Host, file.Port)
		if !errors.Is(err, errServicesChanged) || retries == maxRetries {
			return err
		}
		file.Saved, err = backend.Extend(file.Saved)
		if err != nil {
			return err
		}
		if err := m.saveArmed(file); err != nil {
			return err
		}
	}
}

// Clear restores the saved settings. It does nothing when not armed.
func (m *Manager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreLocked(true)
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
		return fmt.Errorf("proxy.armed is damaged: %w", err)
	}
	if onlyIfOurs {
		if err := m.backend.RestoreIfApplied(file.Saved, file.Host, file.Port); err != nil {
			return err
		}
	} else if err := m.backend.Restore(file.Saved); err != nil {
		return err
	}
	if backend, ok := m.backend.(interface{ verifyClearedSaved(json.RawMessage, string, int) error }); ok {
		if err := backend.verifyClearedSaved(file.Saved, file.Host, file.Port); err != nil {
			return err
		}
	} else if backend, ok := m.backend.(interface{ verifyCleared(string, int) error }); ok {
		if err := backend.verifyCleared(file.Host, file.Port); err != nil {
			return err
		}
	} else if m.backend.IsApplied(file.Host, file.Port) {
		return errors.New("system proxy still points at Pipe")
	}
	return os.Remove(m.armedPath)
}

// ReadPrivate reads an owner-only regular file and refuses symlinks.
func ReadPrivate(path string) ([]byte, error) { return ReadPrivateLimit(path, 64<<10) }

// ReadPrivateLimit is ReadPrivate with a size limit.
func ReadPrivateLimit(path string, limit int64) ([]byte, error) {
	return localfile.ReadProtected(path, limit)
}

// restoreIfApplied is the all-or-nothing form used by backends without parts.
func restoreIfApplied(b Backend, saved json.RawMessage, host string, port int) error {
	if !b.IsApplied(host, port) {
		return nil
	}
	return b.Restore(saved)
}
