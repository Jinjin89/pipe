// SPDX-License-Identifier: GPL-3.0-or-later
//go:build unix

package desktop

import (
	"os"
	"os/exec"
	"syscall"
)

// startDetached runs exe in a new session with the hand-off marker set and
// doesn't wait for it. Its own session keeps it alive when launchd cleans up
// the process group of the app that started it. Standard input and output
// go to /dev/null.
func startDetached(exe string, args []string) error {
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), detachEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
