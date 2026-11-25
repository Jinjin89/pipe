// SPDX-License-Identifier: GPL-3.0-or-later
//go:build unix

package desktop

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestShouldDetach(t *testing.T) {
	bundled := "/Applications/Pipe.app/Contents/MacOS/Pipe"
	none := func(string) string { return "" }
	marked := func(k string) string {
		if k == detachEnv {
			return "1"
		}
		return ""
	}
	cases := []struct {
		name                 string
		goos, exe            string
		getenv               func(string) string
		background, noWindow bool
		want                 bool
	}{
		{"opened from Pipe.app", "darwin", bundled, none, false, false, true},
		{"already the detached copy", "darwin", bundled, marked, false, false, false},
		{"login item", "darwin", bundled, none, true, false, false},
		{"no window", "darwin", bundled, none, false, true, false},
		{"CLI next to the bundle", "darwin", "/Users/me/Downloads/pipe", none, false, false, false},
		{"linux", "linux", bundled, none, false, false, false},
		{"windows", "windows", `C:\Pipe\Pipe.exe`, none, false, false, false},
	}
	for _, c := range cases {
		if got := shouldDetach(c.goos, c.exe, c.getenv, c.background, c.noWindow); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// The detached copy must run in its own session (so launchd's process group
// cleanup doesn't kill it) with the marker set.
func TestStartDetachedNewSession(t *testing.T) {
	if out := os.Getenv("PIPE_DETACH_HELPER"); out != "" {
		sid, _ := unix.Getsid(0)
		os.WriteFile(out, []byte(fmt.Sprintf("%d %d %s", os.Getpid(), sid, os.Getenv(detachEnv))), 0600)
		return
	}
	out := filepath.Join(t.TempDir(), "child")
	t.Setenv("PIPE_DETACH_HELPER", out)
	if err := startDetached(os.Args[0], []string{"-test.run=^TestStartDetachedNewSession$"}); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if raw, _ = os.ReadFile(out); len(raw) > 0 {
			break
		}
	}
	f := strings.Fields(string(raw))
	if len(f) != 3 {
		t.Fatalf("child report: %q", raw)
	}
	if f[0] != f[1] {
		t.Errorf("child pid %s is not its session leader (sid %s)", f[0], f[1])
	}
	if f[2] != "1" {
		t.Errorf("marker %s=%q, want 1", detachEnv, f[2])
	}
}
