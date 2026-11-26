// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type stagedAPK struct {
	dir, handle, path string
	key               ed25519.PublicKey
	target            Target
	checkedAt         time.Time
}

func savedAPK(t *testing.T) stagedAPK {
	t.Helper()
	const body = "signed APK fixture"
	key, signer := signingKey(t)
	f := stagedAPK{
		dir: filepath.Join(updateTestDir(t), "updates"), key: key, handle: rand.Text(),
		target: Target{OS: "android", ABI: "arm64-v8a"}, checkedAt: time.Now().UTC().Add(-time.Hour),
	}
	stage := filepath.Join(f.dir, f.handle)
	f.path = filepath.Join(stage, f.target.filename())
	manifest := []byte(manifestFor(nextVersion, f.target, body))
	signed := signedRelease{Tag: "v" + nextVersion, Manifest: manifest, Signature: ed25519.Sign(signer, manifest), Digest: sha256.Sum256(manifest)}
	rel, err := signed.verify(key, "alpha", f.target)
	if err != nil {
		t.Fatal(err)
	}
	m := newManager("0.7.5-alpha", f.target, f.dir, key, asset.checkFile)
	defer m.Close()
	waitRestore(t, m)
	if err := privateDir(stage); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	m.status.CheckedAt = &f.checkedAt
	if err := m.save(rel, artifact{handle: f.handle, path: f.path}, true); err != nil {
		t.Fatal(err)
	}
	return f
}

func waitRestore(t *testing.T, m *Manager) {
	t.Helper()
	select {
	case <-m.restored:
	case <-time.After(5 * time.Second):
		t.Fatal("startup verification did not finish")
	}
}

func TestAPKRestoreDoesNotBlockStartup(t *testing.T) {
	f := savedAPK(t)
	started, proceed := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-proceed:
		default:
			close(proceed)
		}
	}()
	result := make(chan *Manager, 1)
	go func() {
		result <- newManager("0.7.5-alpha", f.target, f.dir, f.key, func(expected asset, ctx context.Context, base, path string) bool {
			close(started)
			select {
			case <-proceed:
				return expected.checkFile(ctx, base, path)
			case <-ctx.Done():
				return false
			}
		})
	}()
	var m *Manager
	select {
	case m = <-result:
		t.Cleanup(m.Close)
	case <-time.After(5 * time.Second):
		t.Fatal("constructor blocked on staged APK verification")
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("startup did not begin verifying the APK")
	}
	if st := m.Status(); st.State != "available" || !st.Verifying || st.Version != nextVersion || st.Artifact != "" ||
		st.CheckedAt == nil || !st.CheckedAt.Equal(f.checkedAt) {
		t.Fatalf("wrong status during verification: %+v", st)
	}
	if _, err := m.Resolve(f.handle); err == nil {
		t.Fatal("an unverified startup handle resolved")
	}
	if st := m.Download(UnavailableRoute(errors.New("unexpected download request"))); st.State != "downloading" {
		t.Fatalf("download did not wait for the existing file: %+v", st)
	}
	close(proceed)
	if st := waitStatus(t, m, "ready"); st.Verifying || st.Artifact != f.handle {
		t.Fatalf("queued download did not reuse the reverified APK: %+v", st)
	}
}

func TestAPKRestoreCloseKeepsSavedHandle(t *testing.T) {
	f := savedAPK(t)
	started := make(chan struct{})
	m := newManager("0.7.5-alpha", f.target, f.dir, f.key, func(_ asset, ctx context.Context, _, _ string) bool {
		close(started)
		<-ctx.Done()
		return false
	})
	t.Cleanup(m.Close)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("startup did not begin verifying the APK")
	}
	m.Close()
	if st := m.Status(); st.State != "available" || st.Artifact != "" {
		t.Fatalf("cancelled verification published a handle: %+v", st)
	}
	saved, err := readStoredUpdate(filepath.Join(f.dir, m.stateFile))
	if err != nil || saved.Artifact != f.handle {
		t.Fatalf("cancelled verification lost the saved handle: %q, %v", saved.Artifact, err)
	}
}

func TestSupersededUpdateStageRemoved(t *testing.T) {
	const body = "verified bytes"
	f := fixture(t, body, "https://release-assets.githubusercontent.com/download", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})
	base := filepath.Join(updateTestDir(t), "updates")
	m := f.manager(t, base)
	route := TunnelRoute(t.Context(), f.dial)
	m.Check(route, false)
	waitStatus(t, m, "available")
	m.Download(route)
	handle := waitStatus(t, m, "ready").Artifact
	const newer = "0.7.8-alpha"
	f.publish(fixtureOffer{newer, manifestFor(newer, desktopTarget, body), false})
	m.Check(route, false)
	if st := waitStatus(t, m, "available"); st.Version != newer || st.Artifact != "" {
		t.Fatalf("new release inherited a superseded download: %+v", st)
	}
	if _, err := os.Lstat(filepath.Join(base, handle)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the superseded stage survived: %v", err)
	}
}

func TestInstalledUpdateRemovesAPKAndKeepsReleaseFloor(t *testing.T) {
	for _, installed := range []string{nextVersion, "0.7.7-alpha"} {
		t.Run(installed, func(t *testing.T) {
			f := savedAPK(t)
			m := newManager(installed, f.target, f.dir, f.key, func(asset, context.Context, string, string) bool {
				t.Error("hashed an APK for a release already installed")
				return false
			})
			t.Cleanup(m.Close)
			waitRestore(t, m)
			if st := m.Status(); st.Artifact != "" || st.Version != "" {
				t.Fatalf("already installed release was offered again: %+v", st)
			}
			if _, err := os.Lstat(filepath.Dir(f.path)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the obsolete APK stage survived: %v", err)
			}
			saved, err := readStoredUpdate(filepath.Join(f.dir, m.stateFile))
			if err != nil || saved.Release == nil || saved.Artifact != "" {
				t.Fatalf("clearing the restored handle lost the signed release: %+v, %v", saved, err)
			}
			if rel, err := saved.Release.verify(f.key, "alpha", f.target); err != nil || rel.version != nextVersion {
				t.Fatalf("saved rollback floor no longer verifies: %v, %v", rel, err)
			}
		})
	}
}

func TestStartupPrunesAbandonedStages(t *testing.T) {
	f := savedAPK(t)
	var removed, kept []string
	for _, tc := range []struct {
		name, file string
		prune      bool
	}{
		{rand.Text(), ".download", true},
		{rand.Text(), f.target.filename(), true},
		{rand.Text(), "notes.txt", false},
		{"notes", f.target.filename(), false},
	} {
		stage := filepath.Join(f.dir, tc.name)
		if err := privateDir(stage); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(stage, tc.file)
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		if tc.prune {
			removed = append(removed, stage)
		} else {
			kept = append(kept, path)
			if tc.file == "notes.txt" {
				archive := filepath.Join(stage, f.target.filename())
				if err := os.WriteFile(archive, []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
				kept = append(kept, archive)
			}
		}
	}
	plain := filepath.Join(f.dir, rand.Text())
	if err := os.WriteFile(plain, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	m := newManager("0.7.5-alpha", f.target, f.dir, f.key, asset.checkFile)
	t.Cleanup(m.Close)
	waitRestore(t, m)
	for _, path := range removed {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("abandoned stage survived: %s, %v", path, err)
		}
	}
	for _, path := range append(kept, plain, f.path) {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("startup removed a file it needed to keep: %s, %v", path, err)
		}
	}
}

func TestDeclinedInstallKeepsVerifiedAPK(t *testing.T) {
	f := savedAPK(t)
	m := newManager("0.7.5-alpha", f.target, f.dir, f.key, asset.checkFile)
	t.Cleanup(m.Close)
	waitRestore(t, m)
	if path, err := m.Resolve(f.handle); err != nil || path != f.path {
		t.Fatalf("could not hand off the verified APK: %q, %v", path, err)
	}
	// Android can decline an install after the service hands off the path.
	if st := m.Status(); st.State != "ready" || st.Artifact != f.handle {
		t.Fatalf("the handoff consumed the staged artifact: %+v", st)
	}
	m.Close()
	restarted := newManager("0.7.5-alpha", f.target, f.dir, f.key, asset.checkFile)
	t.Cleanup(restarted.Close)
	waitRestore(t, restarted)
	if path, err := restarted.Resolve(f.handle); err != nil || path != f.path {
		t.Fatalf("declining the install lost the verified APK on restart: %q, %v", path, err)
	}
}
