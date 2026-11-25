// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"pipe/internal/link"
	"pipe/internal/localfile"
)

func TestDeviceLifecycle(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "origin.example", "cdn.example"); err != nil {
		t.Fatal(err)
	}
	settings, err := ReadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, "other.example", ""); err == nil {
		t.Fatal("init replaced existing settings")
	}
	encoded, code, err := Add(dir, "phone", true)
	if err != nil || code == nil {
		t.Fatalf("add: %v", err)
	}
	profile, err := link.Parse(encoded)
	if err != nil || profile.Host != settings.Domain || profile.CDN != settings.CDNDomain ||
		profile.WSPath != settings.WSPath || profile.Port != TestPorts().HTTPS {
		t.Fatalf("invalid generated profile: %v", err)
	}
	devices, err := ReadDevices(dir)
	if err != nil || len(devices) != 1 || devices[0].Credentials != link.Derive(profile.Seed) {
		t.Fatalf("bad device storage: %v", err)
	}
	for _, name := range []string{settingsFile, devicesFile} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil || strings.Contains(string(data), link.EncodeKey(profile.Seed)) {
			t.Fatalf("invalid state file %s: %v", name, err)
		}
		info, err := os.Stat(path)
		if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Fatalf("expected private file %s: %v", name, err)
		}
	}
	if _, _, err := Add(dir, "phone", false); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if err := Revoke(dir, "phone"); err != nil {
		t.Fatal(err)
	}
	if devices, err := ReadDevices(dir); err != nil || len(devices) != 0 {
		t.Fatalf("expected empty device file: %v", err)
	}
}

func TestServerFilesEnforceSizeAndPermissionsOnRead(t *testing.T) {
	for _, filename := range []string{settingsFile, devicesFile} {
		t.Run(filename, func(t *testing.T) {
			dir := t.TempDir()
			if err := Init(dir, "origin.example", ""); err != nil {
				t.Fatal(err)
			}
			read := func() error {
				if filename == settingsFile {
					_, err := ReadSettings(dir)
					return err
				}
				_, err := ReadDevices(dir)
				return err
			}
			path := filepath.Join(dir, filename)
			if runtime.GOOS != "windows" {
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
				if err := read(); err == nil || !strings.Contains(err.Error(), "owner") {
					t.Fatalf("accepted group-readable state: %v", err)
				}
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, bytes.Repeat([]byte{' '}, localfile.MaxConfigBytes+1), 0600); err != nil {
				t.Fatal(err)
			}
			if err := read(); err == nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("accepted oversized state: %v", err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := read(); err == nil || !strings.Contains(err.Error(), "regular file") {
				t.Fatalf("accepted state directory: %v", err)
			}
		})
	}
}

func TestConcurrentAdd(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "origin.example", ""); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, name := range []string{"phone", "laptop", "tablet"} {
		wg.Go(func() {
			if _, _, err := Add(dir, name, false); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if devices, err := ReadDevices(dir); err != nil || len(devices) != 3 {
		t.Fatalf("concurrent additions were lost: %v", err)
	}
}
