// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"os"
	"runtime"
	"strings"
)

// detachEnv marks the copy of Pipe that a Pipe.app launch hands off to.
const detachEnv = "PIPE_APP_DETACHED"

// On macOS, opening Pipe.app (Finder, Dock, Spotlight, `open`) registers
// the started process with LaunchServices as the app io.pipe.app. Opening it
// again while that process still runs doesn't start anything new: macOS sends
// the running process a "reopen" Apple event and waits for the answer. Pipe
// is a plain Go program with no Cocoa event loop, so the answer never comes
// and the second open fails. That happens every time the window was closed
// while connected, because Pipe keeps running in the background (D9).
//
// So the process macOS starts only hands off: it starts a detached copy of
// itself in a new session, which does the real work (the lock, the server,
// the window), and exits at once. macOS never sees a running Pipe.app and
// every open starts fresh. A fresh copy finds the lock held and asks the
// running one to show its window, as on Linux and Windows.

// shouldDetach reports whether this run was started from inside a macOS
// app bundle and must hand off to a detached copy.
func shouldDetach(goos, exe string, getenv func(string) string, background, noWindow bool) bool {
	if goos != "darwin" || background || noWindow || getenv(detachEnv) != "" {
		return false
	}
	return strings.Contains(exe, ".app/Contents/MacOS/")
}

// DetachIfBundled starts the detached copy described above and returns true
// when the caller should exit now. args are the arguments that follow
// "pipe app". In the detached copy it clears the marker, so the window
// process doesn't inherit it, and returns false.
func DetachIfBundled(exe string, args []string, background, noWindow bool) (bool, error) {
	if os.Getenv(detachEnv) != "" {
		os.Unsetenv(detachEnv)
		return false, nil
	}
	if !shouldDetach(runtime.GOOS, exe, os.Getenv, background, noWindow) {
		return false, nil
	}
	if err := startDetached(exe, append([]string{"app"}, args...)); err != nil {
		return false, err
	}
	return true, nil
}
