// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pipe/internal/localfile"
)

const maxState = 32 << 10

var (
	errStateRead = errors.New("Could not validate the saved update state.")
	errStateSave = errors.New("Could not save the verified update state.")
)

type storedUpdate struct {
	CheckedAt *time.Time     `json:"checkedAt,omitempty"`
	Release   *signedRelease `json:"release,omitempty"`
	ViaTunnel bool           `json:"viaTunnel,omitempty"`
	Artifact  string         `json:"artifact,omitempty"`
}

func (m *Manager) restore(key ed25519.PublicKey, installed releaseVersion) (string, error) {
	if err := inspectPrivateDir(m.dir, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", errStateRead
	}
	saved, err := readStoredUpdate(filepath.Join(m.dir, m.stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", errStateRead
	}
	if saved.Release != nil {
		rel, err := saved.Release.verify(key, installed.channel, m.target)
		if err != nil {
			return "", errStateRead
		}
		m.release, m.viaTunnel = rel, saved.ViaTunnel
		v, _ := parseVersion(rel.version)
		if v.compare(installed) > 0 {
			m.status.Version, m.status.State = rel.version, "available"
		}
	}
	if saved.CheckedAt != nil && !saved.CheckedAt.After(time.Now()) {
		m.status.CheckedAt = saved.CheckedAt
	}
	return saved.Artifact, nil
}

func readStoredUpdate(path string) (storedUpdate, error) {
	var saved storedUpdate
	raw, err := localfile.ReadProtected(path, maxState)
	if err != nil {
		return saved, err
	}
	err = json.Unmarshal(raw, &saved)
	return saved, err
}

// Startup jobs finish before a new check or download touches the saved offer
// or the staging directory. Status and cancellation remain responsive during
// the full artifact read.
func (m *Manager) restoreArtifact(handle string, verifySaved bool, verify artifactVerifier) {
	defer close(m.restored)
	var file artifact
	if verifySaved {
		expected := m.release.asset
		path := filepath.Join(m.dir, handle, expected.name)
		if verify(expected, m.ctx, m.dir, path) {
			file = artifact{handle: handle, path: path}
		}
	}
	m.mu.Lock()
	m.status.Verifying = false
	if m.ctx.Err() != nil {
		m.mu.Unlock()
		return
	}
	if handle != "" && file.handle == "" {
		_ = m.save(m.release, artifact{}, m.viaTunnel)
	}
	if file.handle != "" {
		m.file, m.status.Artifact = file, file.handle
		if !m.busy() {
			m.status.State, m.status.Error = "ready", ""
		}
	}
	m.mu.Unlock()
	m.pruneStages(file.handle)
}

func (m *Manager) pruneStages(keep string) {
	if inspectPrivateDir(m.dir, false) != nil {
		return
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	referenced := map[string]bool{keep: true}
	// Channel and target changes can leave other verified records here.
	for _, entry := range entries {
		name := entry.Name()
		if name == m.stateFile || !strings.HasPrefix(name, "verified-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		saved, err := readStoredUpdate(filepath.Join(m.dir, name))
		if err != nil {
			return
		}
		referenced[saved.Artifact] = true
	}
	for _, entry := range entries {
		if m.ctx.Err() != nil {
			return
		}
		if entry.IsDir() && !referenced[entry.Name()] {
			removeStage(m.dir, entry.Name(), m.target.filename())
		}
	}
}

func validHandle(handle string) bool {
	return len(handle) >= 26 && len(handle) <= 64 && strings.IndexFunc(handle, func(c rune) bool {
		return (c < 'A' || c > 'Z') && (c < '2' || c > '7')
	}) < 0
}

// save writes one record for the manager's channel and target. A ready handle
// is published only after the matching record and verified file both exist.
func (m *Manager) save(rel *release, file artifact, viaTunnel bool) error {
	if m.stateFile == "" {
		return nil
	}
	if err := privateDir(m.dir); err != nil {
		return errStateSave
	}
	state := storedUpdate{CheckedAt: m.status.CheckedAt, ViaTunnel: viaTunnel, Artifact: file.handle}
	if rel != nil {
		state.Release = &rel.signed
	}
	raw, err := json.Marshal(state)
	if err != nil || localfile.WritePrivateAtomic(filepath.Join(m.dir, m.stateFile), raw) != nil {
		return errStateSave
	}
	return nil
}
