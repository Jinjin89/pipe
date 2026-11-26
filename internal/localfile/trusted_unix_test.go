// SPDX-License-Identifier: GPL-3.0-or-later
//go:build unix

package localfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func executableTestDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return dir
	}
	// The root installer requires protected ancestors, including above the
	// fixture directory. The repository has them even when /tmp is sticky.
	dir, err := os.MkdirTemp(".", ".trusted-executable-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := MakeTrustedDirectory(dir); err != nil {
		t.Skipf("protected fixture directory unavailable: %v", err)
	}
	return dir
}

func TestInstallOwnerExecutable(t *testing.T) {
	dir := executableTestDir(t)
	source, dest := filepath.Join(dir, "source"), filepath.Join(dir, "pipe")
	if err := os.WriteFile(source, []byte("verified owner fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("previous fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	image, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	if _, err := image.Seek(4, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	previous, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer previous.Close()
	if err := InstallOwnerExecutable(image, dest); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(dest); err != nil || string(data) != "verified owner fixture" {
		t.Fatalf("installed body = %q, error = %v", data, err)
	}
	if data, err := io.ReadAll(previous); err != nil || string(data) != "previous fixture" {
		t.Fatalf("previous executable was overwritten in place: %q, %v", data, err)
	}
	if info, err := os.Stat(dest); err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("published permissions = %v, error = %v", info, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(dest, link); err != nil {
		t.Fatal(err)
	}
	if err := InstallOwnerExecutable(image, link); err == nil {
		t.Fatal("portable installer accepted a symbolic link destination")
	}
	if err := os.Chmod(source, 0770); err != nil {
		t.Fatal(err)
	}
	if err := InstallOwnerExecutable(image, dest); err == nil {
		t.Fatal("portable installer accepted a group-writable source")
	}
	if err := os.Chmod(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	if err := InstallOwnerExecutable(image, dest); err == nil {
		t.Fatal("portable installer accepted a group-writable directory")
	}
}

func TestPublishExecutableReportsSyncFailureAfterRename(t *testing.T) {
	dir := t.TempDir()
	source, dest := filepath.Join(dir, "source"), filepath.Join(dir, "pipe")
	if err := os.WriteFile(source, []byte("new executable"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("old executable"), 0755); err != nil {
		t.Fatal(err)
	}
	image, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	parent, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	err = publishExecutable(image, int(parent.Fd()), filepath.Base(dest), false, func(int) error {
		if data, err := os.ReadFile(dest); err != nil || string(data) != "new executable" {
			t.Fatalf("destination at directory sync = %q, error = %v", data, err)
		}
		return unix.EIO
	})
	if !errors.Is(err, ErrSyncAfterReplace) || !errors.Is(err, unix.EIO) {
		t.Fatalf("error after committed rename = %v", err)
	}
}

func TestCheckTrustedFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("fixture requires a root-owned file")
	}
	dir := executableTestDir(t)
	config := filepath.Join(dir, "pipe.service")
	if err := os.WriteFile(config, []byte("fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := CheckTrustedFile(config); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.service")
	if err := os.Symlink(config, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, dir, "pipe.service"} {
		if err := CheckTrustedFile(path); err == nil {
			t.Errorf("trusted file accepted %s", path)
		}
	}
	if err := os.Chmod(config, 0664); err != nil {
		t.Fatal(err)
	}
	if err := CheckTrustedFile(config); err == nil {
		t.Fatal("trusted file accepted group-writable contents")
	}
}

func TestInstallingExecutableUsesApprovedDescriptor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("fixture requires a root-owned directory")
	}
	dir, err := os.MkdirTemp(".", ".trusted-executable-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, []byte("approved fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	image, err := openTrustedExecutable(source)
	if err != nil {
		t.Skipf("trusted fixture directory unavailable: %v", err)
	}
	defer image.Close()
	if err := os.Rename(source, filepath.Join(dir, "previous")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("replacement fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "system", "pipe")
	if err := InstallTrustedExecutable(image, dest); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "approved fixture" {
		t.Fatalf("installed bytes = %q, error = %v", data, err)
	}
	writable := filepath.Join(dir, "writable")
	if err := os.Mkdir(writable, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0777); err != nil {
		t.Fatal(err)
	}
	if err := InstallTrustedExecutable(image, filepath.Join(writable, "pipe")); err == nil {
		t.Fatal("installation accepted a destination under a group- or world-writable ancestor")
	}
	portable := filepath.Join(writable, "pipe")
	if err := os.WriteFile(portable, []byte("portable fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := TrustedExecutable(portable); err == nil {
		t.Fatal("trusted server and relay executable check accepted a portable path")
	}
}
