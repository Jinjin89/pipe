// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !windows

package desktop

import "os/exec"

func configureWindowCmd(cmd *exec.Cmd) {}
