// SPDX-License-Identifier: GPL-3.0-or-later
//go:build windows

package desktop

import (
	"os/exec"
	"syscall"
)

// configureWindowCmd stops a console window from flashing up.
func configureWindowCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
