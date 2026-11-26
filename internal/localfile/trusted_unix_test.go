// SPDX-License-Identifier: GPL-3.0-or-later
//go:build unix

package localfile

import (
	"os"
	"path/filepath"
	"testing"
)

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
