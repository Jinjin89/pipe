// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pipe/internal/localfile"
)

const (
	maxState          = 32 << 10
	stateLockFilename = ".verified.lock"
)

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

type releaseState struct {
	dir     string
	channel string
	target  Target
	key     ed25519.PublicKey
}

func (s releaseState) path() string {
	return filepath.Join(s.dir, stateFilename(s.channel, s.target))
}

func (s releaseState) load() (*release, error) {
	if s.dir == "" {
		return nil, nil
	}
	if err := inspectPrivateDir(s.dir, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	_, floor, err := s.read()
	return floor, err
}

func (s releaseState) read() (storedUpdate, *release, error) {
	saved, err := readStoredUpdate(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return saved, nil, nil
	}
	if err != nil || saved.Release == nil {
		return saved, nil, err
	}
	floor, err := saved.Release.verify(s.key, s.channel, s.target)
	return saved, floor, err
}

func (s releaseState) raise(ctx context.Context, rel *release, viaTunnel bool) error {
	now := time.Now().UTC()
	return s.save(ctx, rel, storedUpdate{CheckedAt: &now, ViaTunnel: viaTunnel}, true)
}

func (s releaseState) save(ctx context.Context, rel *release, next storedUpdate, floorOnly bool) error {
	if s.dir == "" {
		return nil
	}
	return withUpdateStateLock(ctx, s.dir, func() error {
		_, floor, err := s.read()
		if err != nil {
			return errStateRead
		}
		if err := rel.checkFloor(floor); err != nil {
			return err
		}
		if floorOnly && rel.same(floor) {
			return nil
		}
		if rel != nil {
			next.Release = &rel.signed
		}
		raw, err := json.Marshal(next)
		if err != nil || localfile.WritePrivateAtomicSyncDir(s.path(), raw) != nil {
			return errStateSave
		}
		return nil
	})
}

func withUpdateStateLock(ctx context.Context, dir string, write func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := privateDir(dir); err != nil {
		return errStateSave
	}
	path := filepath.Join(dir, stateLockFilename)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errStateSave
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return errStateSave
	}
	defer file.Close()
	for {
		locked, err := tryLockUpdateFile(file)
		if err != nil {
			return errStateSave
		}
		if locked {
			if err := ctx.Err(); err != nil {
				return err
			}
			return write()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (m *Manager) restore(key ed25519.PublicKey, installed releaseVersion) (string, error) {
	if err := inspectPrivateDir(m.dir, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", errStateRead
	}
	state := releaseState{dir: m.dir, channel: installed.channel, target: m.target, key: key}
	saved, rel, err := state.read()
	if err != nil {
		return "", errStateRead
	}
	if rel != nil {
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
	raw, err := localfile.ReadProtected(path, maxState)
	if err != nil {
		return storedUpdate{}, err
	}
	var saved *storedUpdate
	if err := json.Unmarshal(raw, &saved); err != nil {
		return storedUpdate{}, err
	}
	if saved == nil || (saved.Release == nil && (saved.Artifact != "" || saved.ViaTunnel)) {
		return storedUpdate{}, errStateRead
	}
	return *saved, nil
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
		name := entry.Name()
		if entry.IsDir() && !strings.HasPrefix(name, cliStagePrefix) && !referenced[name] {
			removeStage(m.dir, name, m.target.filename())
		}
	}
}

func validHandle(handle string) bool {
	return len(handle) >= 26 && len(handle) <= 64 && strings.IndexFunc(handle, func(c rune) bool {
		return (c < 'A' || c > 'Z') && (c < '2' || c > '7')
	}) < 0
}

func stateFilename(channel string, target Target) string {
	return "verified-" + channel + "-" + target.OS + "-" + target.ABI + ".json"
}

// save writes one record for the manager's channel and target. A ready handle
// is published only after the matching record and verified file both exist.
func (m *Manager) save(rel *release, file artifact, viaTunnel bool) error {
	if m.stateFile == "" {
		return nil
	}
	installed, _ := parseVersion(m.status.Installed)
	state := releaseState{dir: m.dir, channel: installed.channel, target: m.target, key: m.key}
	return state.save(m.ctx, rel, storedUpdate{CheckedAt: m.status.CheckedAt, ViaTunnel: viaTunnel, Artifact: file.handle}, false)
}
