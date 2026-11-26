// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestLinuxBootstrapFallsBackToGIO(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux file opener")
	}
	dir := t.TempDir()
	opened := filepath.Join(dir, "opened")
	t.Setenv("PATH", dir)
	t.Setenv("PIPE_FIXTURE_OPENED", opened)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(dir, "absent-session-bus"))
	for name, script := range map[string]string{
		"xdg-open": "#!/bin/sh\nexit 1\n",
		"gio":      "#!/bin/sh\n[ \"$1\" = open ] && printf '%s' \"$2\" > \"$PIPE_FIXTURE_OPENED\"\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	bootstrap := filepath.Join(dir, "Pipe-open-fixture file.html")
	if err := os.WriteFile(bootstrap, []byte("fixture bootstrap"), 0600); err != nil {
		t.Fatal(err)
	}
	if portal, err := openDefaultBrowser(bootstrap); portal || err != nil {
		t.Fatalf("default opener reported portal=%t, error=%v", portal, err)
	}
	for end := time.Now().Add(time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		if raw, err := os.ReadFile(opened); err == nil && string(raw) == bootstrap {
			return
		}
	}
	t.Fatal("gio did not receive the bootstrap path after xdg-open failed")
}
