// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package server

import (
	"os/exec"
	"syscall"
)

// dropCredentials runs cmd as uid:gid with no supplementary groups.
func dropCredentials(cmd *exec.Cmd, uid, gid uint32) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	return nil
}
