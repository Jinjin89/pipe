// SPDX-License-Identifier: GPL-3.0-or-later

// Package sysdns temporarily points macOS network services at Pipe's DNS
// listener and keeps enough state to restore them after a crash.
package sysdns

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"

	"pipe/internal/localfile"
	"pipe/internal/sysproxy"
)

const TUNDNSAddress = "172.19.0.2"

const defaultArmedPath = "/Library/Application Support/io.pipe.helper/dns.armed"

var ErrTUNProtected = errors.New("system DNS remains armed while TUN traffic is blocked")

// The controller and its DNS manager can be owned by separate components
// in the same process. Serialize restore operations with guard acquisition.
var restoreProtection struct {
	sync.RWMutex
	guards int
}

// HoldRestore keeps the saved resolver in place during a protected rebuild.
// The caller releases the hold after capture resumes or the user stops TUN.
func HoldRestore() func() {
	restoreProtection.Lock()
	restoreProtection.guards++
	restoreProtection.Unlock()
	return sync.OnceFunc(func() {
		restoreProtection.Lock()
		restoreProtection.guards--
		restoreProtection.Unlock()
	})
}

// Backend owns platform DNS settings. Saved state is opaque JSON owned by the
// platform implementation.
type Backend interface {
	Capture() (json.RawMessage, error)
	Extend(saved json.RawMessage) (json.RawMessage, error)
	Apply(saved json.RawMessage) error
	Restore(saved json.RawMessage) (json.RawMessage, error)
	RestoreIfApplied(saved json.RawMessage) (json.RawMessage, error)
	CurrentServers() ([]netip.AddrPort, error)
	SavedServers(saved json.RawMessage) []netip.AddrPort
}

// Manager applies system DNS while a TUN session is running.
type Manager struct {
	mu        sync.Mutex
	backend   Backend
	armedPath string
}

type armedFile struct {
	Saved json.RawMessage `json:"saved"`
}

// New returns a manager. A nil backend is a no-op for unsupported systems.
func New(backend Backend, armedPath string) *Manager {
	return &Manager{backend: backend, armedPath: armedPath}
}

// ArmedPath is the path shared by the helper and the CLI DNS manager.
func ArmedPath() string { return defaultArmedPath }

// Supported reports whether the manager can change system DNS.
func (m *Manager) Supported() bool { return m.backend != nil }

// Set saves the original DNS settings before pointing every enabled service at
// Pipe's resolver. Repeated calls preserve the first snapshot.
func (m *Manager) Set() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend == nil {
		return nil
	}
	var saved json.RawMessage
	data, err := sysproxy.ReadPrivateLimit(m.armedPath, 64<<10)
	wasArmed := err == nil
	if wasArmed {
		var existing armedFile
		if json.Unmarshal(data, &existing) != nil || len(existing.Saved) == 0 {
			return errors.New("system DNS armed file is damaged")
		}
		saved = existing.Saved
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if saved == nil {
		saved, err = m.backend.Capture()
		if err != nil {
			return err
		}
	} else {
		saved, err = m.backend.Extend(saved)
		if err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		data, err = json.Marshal(armedFile{Saved: saved})
		if err != nil {
			return err
		}
		if err := writeArmedFile(m.armedPath, data); err != nil {
			return fmt.Errorf("save previous DNS settings: %w", err)
		}
		err = m.backend.Apply(saved)
		if err == nil {
			return nil
		}
		if errors.Is(err, errDNSServicesChanged) && attempt < 2 {
			extended, extErr := m.backend.Extend(saved)
			if extErr != nil {
				err = errors.Join(err, extErr)
			} else {
				saved = extended
				continue
			}
		}
		if wasArmed {
			return err // the active TUN still owns the system resolver
		}
		restoreProtection.RLock()
		defer restoreProtection.RUnlock()
		if restoreProtection.guards != 0 {
			return err
		}
		remaining, restoreErr := m.backend.Restore(saved)
		fileErr := m.saveRemaining(saved, remaining, restoreErr)
		return errors.Join(err, restoreErr, fileErr)
	}
}

// Restore restores all saved service settings. It leaves the armed file in
// place if restoration fails, so a later shutdown or startup can retry.
func (m *Manager) Restore() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreLocked(false)
}

// Repair restores only services that still point at Pipe's resolver.
func (m *Manager) Repair() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreLocked(true)
}

func (m *Manager) restoreLocked(onlyIfApplied bool) error {
	if m.backend == nil || m.armedPath == "" {
		return nil
	}
	restoreProtection.RLock()
	defer restoreProtection.RUnlock()
	if restoreProtection.guards != 0 {
		return ErrTUNProtected
	}
	data, err := sysproxy.ReadPrivateLimit(m.armedPath, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var file armedFile
	if err := json.Unmarshal(data, &file); err != nil || len(file.Saved) == 0 {
		if err == nil {
			err = errors.New("saved DNS settings are missing")
		}
		return fmt.Errorf("system DNS armed file is damaged: %w", err)
	}
	var remaining json.RawMessage
	if onlyIfApplied {
		remaining, err = m.backend.RestoreIfApplied(file.Saved)
	} else {
		remaining, err = m.backend.Restore(file.Saved)
	}
	if fileErr := m.saveRemaining(file.Saved, remaining, err); fileErr != nil {
		err = errors.Join(err, fileErr)
	}
	return err
}

func (m *Manager) saveRemaining(original, remaining json.RawMessage, restoreErr error) error {
	if len(remaining) == 0 && restoreErr != nil {
		remaining = original
	}
	if len(remaining) != 0 {
		data, err := json.Marshal(armedFile{Saved: remaining})
		if err != nil {
			return err
		}
		return writeArmedFile(m.armedPath, data)
	}
	if err := os.Remove(m.armedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Servers returns the active network's DNS servers. The captured global list
// is used only when the active service has no usable server after Pipe's
// resolver is removed.
func (m *Manager) Servers() []netip.AddrPort {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend == nil {
		return nil
	}
	var saved json.RawMessage
	if data, err := sysproxy.ReadPrivateLimit(m.armedPath, 64<<10); err == nil {
		var file armedFile
		if json.Unmarshal(data, &file) == nil {
			saved = file.Saved
		}
	}
	current, _ := m.backend.CurrentServers()
	if current = usableServers(current); len(current) != 0 {
		return current
	}
	return usableServers(m.backend.SavedServers(saved))
}

func usableServers(servers []netip.AddrPort) []netip.AddrPort {
	tunnel := netip.MustParseAddr(TUNDNSAddress)
	seen := make(map[netip.AddrPort]struct{}, len(servers))
	result := make([]netip.AddrPort, 0, len(servers))
	for _, server := range servers {
		if !server.IsValid() || server.Port() == 0 || server.Addr().Unmap() == tunnel {
			continue
		}
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		result = append(result, server)
	}
	return result
}

func writeArmedFile(path string, data []byte) error {
	if path == "" {
		return errors.New("system DNS armed file path is empty")
	}
	return localfile.WritePrivateAtomicSyncDir(path, data)
}
