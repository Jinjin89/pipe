// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"pipe/internal/localfile"
)

func TestStoreRefusesWriteAfterProtectedReadFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.json")
	const original = `{"active":"saved-profile","mode":"global"}`
	if runtime.GOOS == "windows" {
		// An existing directory reliably fails the protected file reader.
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := os.WriteFile(path, []byte(original), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	}
	store := OpenStore(path)
	if err := store.Update(func(d *appData) { d.Active = "replacement" }); err == nil || !strings.Contains(err.Error(), "couldn't load app.json") {
		t.Fatalf("save after unreadable app.json returned %v", err)
	}
	if runtime.GOOS != "windows" {
		if raw, err := os.ReadFile(path); err != nil || string(raw) != original {
			t.Fatalf("failed settings update altered the original file: %v", err)
		}
	}
}

func TestStoreWritesProtectedAppJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.json")
	store := OpenStore(path)
	if err := store.Update(func(d *appData) { d.Active = "phone" }); err != nil {
		t.Fatal(err)
	}
	if _, err := localfile.ReadProtected(path, localfile.MaxConfigBytes); err != nil {
		t.Fatalf("saved app.json failed the protected reader: %v", err)
	}
	if got := OpenStore(path).Snapshot().Active; got != "phone" {
		t.Fatalf("active profile after reopening = %q", got)
	}
}

func TestStoreRefusesWriteAfterMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.json")
	const corrupt = `{"active": "saved",`
	if err := localfile.WritePrivate(path, []byte(corrupt)); err != nil {
		t.Fatal(err)
	}
	store := OpenStore(path)
	if err := store.Update(func(d *appData) { d.Active = "other" }); err == nil || !strings.Contains(err.Error(), "parse app.json") {
		t.Fatalf("save after malformed app.json returned %v", err)
	}
	if raw, err := localfile.ReadProtected(path, localfile.MaxConfigBytes); err != nil || string(raw) != corrupt {
		t.Fatalf("malformed app.json was overwritten: %q, err=%v", raw, err)
	}
}
