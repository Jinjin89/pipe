// SPDX-License-Identifier: GPL-3.0-or-later
//go:build unix && !android

package update

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestStageRejectsUnsafeAncestorsBeforeCreatingDirectories(t *testing.T) {
	parent := filepath.Join(updateTestDir(t), "shared")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "owned", "updates")
	if err := privateDir(dir); err == nil {
		t.Error("private stage accepted a replaceable ancestor")
	}
	if _, err := os.Stat(filepath.Dir(dir)); !os.IsNotExist(err) {
		t.Fatalf("stage created a child in an unsafe directory: %v", err)
	}
}

func TestReadyArtifactRefusesAnAncestorThatBecameWritable(t *testing.T) {
	const body = "verified bytes"
	f := fixture(t, body, "https://release-assets.githubusercontent.com/download", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})
	parent := filepath.Join(updateTestDir(t), "parent")
	m := f.manager(t, filepath.Join(parent, "updates"))
	route := TunnelRoute(context.Background(), f.dial)
	m.Check(route, false)
	waitStatus(t, m, "available")
	m.Download(route)
	handle := waitStatus(t, m, "ready").Artifact
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resolve(handle); err == nil {
		t.Fatal("resolved an archive under a replaceable ancestor")
	}
}
