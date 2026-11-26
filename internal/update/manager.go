// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"path/filepath"
	"sync"
	"time"
)

const day = 24 * time.Hour

var (
	errReleaseChanged  = errors.New("The release changed. Review the new update before downloading.")
	errUpdateCancelled = errors.New("The update was cancelled.")
)

type Status struct {
	Installed string     `json:"installed"`
	State     string     `json:"state"`
	Version   string     `json:"version,omitempty"`
	CheckedAt *time.Time `json:"checkedAt,omitempty"`
	Artifact  string     `json:"artifact,omitempty"`
	Verifying bool       `json:"verifying,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// Manager owns one in-flight job and hands verified files to platform adapters
// using opaque handles. Each job uses one fixed authenticated or direct route.
type Manager struct {
	mu           sync.Mutex
	dir          string
	target       Target
	stateFile    string
	loadErr      error
	status       Status
	release      *release
	viaTunnel    bool
	file         artifact
	ctx          context.Context
	cancel       context.CancelFunc
	directCtx    context.Context
	cancelDirect context.CancelFunc
	restored     chan struct{}
	makeClient   func(context.Context, DialFunc) (releaseClient, *http.Transport)
}

func NewManager(installed string, target Target, dir string) *Manager {
	return newManager(installed, target, dir, embeddedKey(), asset.checkFile)
}

type artifactVerifier func(asset, context.Context, string, string) bool

func newManager(installed string, target Target, dir string, key ed25519.PublicKey, verify artifactVerifier) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		dir: dir, target: target, ctx: ctx, cancel: cancel,
		status: Status{Installed: installed, State: "idle"}, restored: make(chan struct{}),
		makeClient: func(ctx context.Context, dial DialFunc) (releaseClient, *http.Transport) {
			transport := releaseTransport(ctx, dial)
			return releaseClient{http: releaseHTTPClient(transport), key: key}, transport
		},
	}
	m.directCtx, m.cancelDirect = context.WithCancel(m.ctx)
	if v, ok := parseVersion(installed); ok && target.filename() != "" {
		m.stateFile = "verified-" + v.channel + "-" + target.OS + "-" + target.ABI + ".json"
		var handle string
		if abs, err := filepath.Abs(dir); err == nil {
			m.dir = abs
			handle, m.loadErr = m.restore(key, v)
		} else {
			m.loadErr = errStateRead
		}
		if m.loadErr == nil {
			m.status.Verifying = m.status.Version != "" && validHandle(handle)
			go m.restoreArtifact(handle, m.status.Verifying, verify)
			return m
		}
		m.fail(m.loadErr)
	}
	close(m.restored)
	return m
}

func (m *Manager) Close() {
	m.mu.Lock()
	m.cancel()
	m.mu.Unlock()
	<-m.restored
}

// CancelDirect cancels direct update requests when a session starts.
func (m *Manager) CancelDirect() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cancelDirect()
	m.directCtx, m.cancelDirect = context.WithCancel(m.ctx)
}

func (m *Manager) resolveRoute(resolve func() Route) (context.Context, Route) {
	// Capture the direct lifetime before calling into the session controller.
	// A session start can cancel it even if the route has just been selected.
	m.mu.Lock()
	direct := m.directCtx
	m.mu.Unlock()
	var route Route
	if resolve != nil {
		route = resolve()
	}
	if route.tunneled {
		return m.ctx, route
	}
	return direct, route
}

func (m *Manager) waitForRestore() bool {
	select {
	case <-m.restored:
		return m.ctx.Err() == nil
	case <-m.ctx.Done():
		return false
	}
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// StatusAfterRestore lets a request wait for a saved artifact when its client
// polls only during explicit checks and downloads.
func (m *Manager) StatusAfterRestore(ctx context.Context) Status {
	if st := m.Status(); st.State != "available" || !st.Verifying {
		return st
	}
	select {
	case <-m.restored:
	case <-ctx.Done():
	}
	return m.Status()
}

func (m *Manager) busy() bool {
	return m.status.State == "checking" || m.status.State == "downloading"
}

func (m *Manager) Check(route Route, automatic bool) Status {
	return m.CheckWithRoute(func() Route { return route }, automatic)
}

// CheckWithRoute resolves the route after startup verification.
func (m *Manager) CheckWithRoute(resolve func() Route, automatic bool) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.busy() || m.loadErr != nil || m.ctx.Err() != nil {
		return m.status
	}
	if at := m.status.CheckedAt; automatic && at != nil && time.Since(*at) >= 0 && time.Since(*at) < day {
		return m.status
	}
	m.status.State, m.status.Error = "checking", ""
	installed := m.status.Installed
	go m.check(resolve, installed, m.release)
	return m.status
}

func (m *Manager) check(resolve func() Route, installed string, verified *release) {
	if !m.waitForRestore() {
		return
	}
	parent, route := m.resolveRoute(resolve)
	var candidate *release
	err := m.run(parent, route, 45*time.Second, func(ctx context.Context, c releaseClient) (err error) {
		candidate, err = c.check(ctx, installed, m.target, verified)
		return err
	})
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return
	}
	if parent.Err() != nil {
		m.fail(errUpdateCancelled)
		return
	}
	m.status.CheckedAt = &now
	if err != nil {
		_ = m.save(m.release, m.file, m.viaTunnel)
		m.fail(err)
		return
	}
	next, file, via := m.release, artifact{}, m.viaTunnel
	if candidate != nil {
		next, via = candidate, route.tunneled
		if candidate.same(m.release) {
			file = m.file
		}
	}
	if err := m.commit(next, file, via); err != nil {
		m.fail(err)
		return
	}
	m.status.Artifact, m.status.Version, m.status.State = file.handle, "", "current"
	if candidate != nil {
		m.status.Version, m.status.State = candidate.version, "available"
		if file.handle != "" {
			m.status.State = "ready"
		}
	}
}

func (m *Manager) Download(route Route) Status {
	return m.DownloadWithRoute(func() Route { return route })
}

// DownloadWithRoute resolves the route when a download needs network access.
func (m *Manager) DownloadWithRoute(resolve func() Route) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.busy() || m.status.Version == "" || m.file.handle != "" || m.ctx.Err() != nil {
		return m.status
	}
	m.status.State, m.status.Error = "downloading", ""
	go m.download(resolve, m.status.Installed, *m.release, m.viaTunnel)
	return m.status
}

func (m *Manager) download(resolve func() Route, installed string, expected release, requiresTunnel bool) {
	if !m.waitForRestore() {
		return
	}
	m.mu.Lock()
	if m.file.handle != "" {
		m.status.State = "ready"
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	parent, route := m.resolveRoute(resolve)
	if requiresTunnel && !route.tunneled {
		m.mu.Lock()
		m.fail(ErrTunnelStopped)
		m.mu.Unlock()
		return
	}

	var file artifact
	var newer *release
	err := m.run(parent, route, 10*time.Minute, func(ctx context.Context, c releaseClient) error {
		// Reverify discovery and metadata on the same transport as the asset.
		// An update published between Check and Download needs a new approval.
		current, err := c.check(ctx, installed, m.target, &expected)
		if err != nil {
			return err
		}
		if !current.same(&expected) {
			newer = current
			return errReleaseChanged
		}
		file, err = c.download(ctx, *current, m.dir)
		return err
	})
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		removeStage(m.dir, file.handle, expected.asset.name)
		return
	}
	if parent.Err() != nil {
		err = errUpdateCancelled
	}
	if errors.Is(err, errReleaseChanged) && newer != nil {
		if err := m.commit(newer, artifact{}, route.tunneled); err != nil {
			m.fail(err)
			return
		}
		m.status.Version, m.status.State, m.status.Artifact = newer.version, "available", ""
		return
	}
	if err == nil {
		err = m.commit(m.release, file, route.tunneled)
	}
	if err != nil {
		removeStage(m.dir, file.handle, expected.asset.name)
		m.fail(err)
		return
	}
	m.status.Artifact, m.status.State = file.handle, "ready"
}

// commit updates the verified state before removing the previous download.
// The caller holds m.mu.
func (m *Manager) commit(rel *release, file artifact, viaTunnel bool) error {
	if err := m.save(rel, file, viaTunnel); err != nil {
		return err
	}
	if m.file.handle != file.handle {
		removeStage(m.dir, m.file.handle, m.target.filename())
	}
	m.release, m.file, m.viaTunnel = rel, file, viaTunnel
	return nil
}

func (m *Manager) fail(err error) {
	m.status.State, m.status.Error = "error", err.Error()
}

func (m *Manager) run(parent context.Context, route Route, timeout time.Duration, run func(context.Context, releaseClient) error) error {
	if route.err != nil {
		return route.err
	}
	if route.dial == nil {
		return ErrTunnelUnavailable
	}
	if parent.Err() != nil {
		return errUpdateCancelled
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if route.ctx != nil {
		if route.ctx.Err() != nil {
			return ErrTunnelStopped
		}
		defer context.AfterFunc(route.ctx, cancel)()
	}
	c, transport := m.makeClient(ctx, route.dial)
	defer transport.CloseIdleConnections()
	err := run(ctx, c)
	switch {
	case route.ctx != nil && route.ctx.Err() != nil:
		return ErrTunnelStopped
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return errors.New("The update request timed out.")
	case ctx.Err() != nil:
		return errUpdateCancelled
	}
	return err
}

// Resolve returns a path only to trusted platform code.
func (m *Manager) Resolve(handle string) (string, error) {
	m.mu.Lock()
	if handle == "" || handle != m.file.handle || m.release == nil {
		m.mu.Unlock()
		return "", errors.New("The verified download is unavailable.")
	}
	path, expected := m.file.path, m.release.asset
	m.mu.Unlock()

	valid := expected.checkFile(m.ctx, m.dir, path)
	m.mu.Lock()
	defer m.mu.Unlock()
	if handle != m.file.handle || m.ctx.Err() != nil {
		return "", errors.New("The verified download is unavailable.")
	}
	if !valid {
		err := errors.New("The verified download is missing or has changed.")
		m.file, m.status.Artifact = artifact{}, ""
		if m.save(m.release, m.file, m.viaTunnel) == nil {
			removeStage(m.dir, handle, expected.name)
		}
		if !m.busy() {
			m.fail(err)
		}
		return "", err
	}
	return path, nil
}
