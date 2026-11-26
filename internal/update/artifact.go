// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type artifact struct {
	handle string
	path   string
}

var errUnsafeDirectory = errors.New("The update directory must have private, protected ancestors.")

var errAssetMismatch = errors.New("The archive does not match the signed release.")

func (c releaseClient) assetBody(ctx context.Context, rel *release) (io.ReadCloser, error) {
	resp, err := c.get(ctx, rel.url)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength >= 0 && resp.ContentLength != rel.asset.length {
		resp.Body.Close()
		return nil, errAssetMismatch
	}
	return resp.Body, nil
}

func (c releaseClient) download(ctx context.Context, rel release, dir string) (artifact, error) {
	body, err := c.assetBody(ctx, &rel)
	if err != nil {
		return artifact{}, err
	}
	defer body.Close()
	saveFailed := errors.New("Could not save the verified update.")
	if err := privateDir(dir); err != nil {
		return artifact{}, saveFailed
	}
	handle := rand.Text()
	stage := filepath.Join(dir, handle)
	if err := mkdirPrivate(stage); err != nil {
		return artifact{}, saveFailed
	}
	complete := false
	defer func() {
		if !complete {
			removeStage(dir, handle, rel.asset.name)
		}
	}()

	if !protectedStage(dir, stage) {
		return artifact{}, saveFailed
	}
	file, err := os.OpenFile(filepath.Join(stage, ".download"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return artifact{}, saveFailed
	}
	defer file.Close()
	if err := rel.asset.copyVerified(ctx, file, body); err != nil {
		if errors.Is(err, errAssetMismatch) || ctx.Err() != nil {
			return artifact{}, err
		}
		var localError *os.PathError
		if errors.As(err, &localError) {
			return artifact{}, saveFailed
		}
		return artifact{}, errors.New("The download ended before verification could finish.")
	}
	if err := file.Sync(); err != nil {
		return artifact{}, saveFailed
	}
	if err := file.Close(); err != nil {
		return artifact{}, saveFailed
	}
	if err := ctx.Err(); err != nil {
		return artifact{}, err
	}
	final := filepath.Join(stage, rel.asset.name)
	if !protectedStage(dir, stage) {
		return artifact{}, saveFailed
	}
	if err := os.Rename(file.Name(), final); err != nil {
		return artifact{}, saveFailed
	}
	complete = true
	return artifact{handle: handle, path: final}, nil
}

func (a asset) copyVerified(ctx context.Context, dst io.Writer, src io.Reader) error {
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, hash), io.LimitReader(artifactReader{ctx: ctx, Reader: src}, a.length+1))
	if err != nil {
		return err
	}
	if !a.matches(n, hash.Sum(nil)) {
		return errAssetMismatch
	}
	return ctx.Err()
}

func (a asset) matches(length int64, digest []byte) bool {
	return length == a.length && [sha256.Size]byte(digest) == a.digest
}

func (a asset) checkFile(ctx context.Context, base, path string) bool {
	stage := filepath.Dir(path)
	return ctx.Err() == nil && protectedStage(base, stage) && a.checkBytes(ctx, path) && protectedStage(base, stage)
}

func protectedStage(base, stage string) bool {
	return filepath.Dir(stage) == base && inspectPrivateDir(base, false) == nil &&
		inspectDirectory(stage, false, true) == nil
}

func removeStage(base, handle, filename string) {
	if !validHandle(handle) {
		return
	}
	stage := filepath.Join(base, handle)
	if !protectedStage(base, stage) {
		return
	}
	entries, err := os.ReadDir(stage)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || (name != ".download" && name != filename) {
			return
		}
	}
	for _, entry := range entries {
		_ = os.Remove(filepath.Join(stage, entry.Name()))
	}
	_ = os.Remove(stage) // removes the directory only when empty
}

type artifactReader struct {
	ctx context.Context
	io.Reader
}

func (r artifactReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

func (a asset) checkBytes(ctx context.Context, path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != a.length {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return false
	}
	return a.copyVerified(ctx, io.Discard, f) == nil
}

func privateDir(path string) error {
	return inspectPrivateDir(path, true)
}

// Check from the trusted root down so each existing directory is protected
// before inspecting or creating anything beneath it.
func inspectPrivateDir(path string, create bool) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	anchor, err := directoryAnchor(abs)
	if err != nil {
		return err
	}
	if abs == anchor || filepath.Dir(abs) == abs {
		return errUnsafeDirectory
	}
	if err := inspectAncestors(filepath.Dir(abs), anchor, create); err != nil {
		return err
	}
	return inspectDirectory(abs, create, true)
}

func inspectAncestors(path, anchor string, create bool) error {
	if path == anchor || filepath.Dir(path) == path {
		return inspectDirectory(path, false, anchor != "")
	}
	if err := inspectAncestors(filepath.Dir(path), anchor, create); err != nil {
		return err
	}
	return inspectDirectory(path, create, false)
}

func inspectDirectory(path string, create, private bool) error {
	info, err := os.Lstat(path)
	if create && errors.Is(err, os.ErrNotExist) {
		if err := mkdirPrivate(path); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errUnsafeDirectory
	}
	err = checkDirectory(path, info, private)
	if err != nil && private && !create {
		// A read-only system check must distinguish inaccessible state from
		// a readable directory with unsafe ownership or permissions.
		dir, accessErr := os.Open(path)
		if accessErr == nil {
			dir.Close()
		} else if errors.Is(accessErr, os.ErrPermission) {
			return accessErr
		}
	}
	return err
}
