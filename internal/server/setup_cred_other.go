// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !unix

package server

import (
	"errors"
	"os/exec"
)

func dropCredentials(*exec.Cmd, uint32, uint32) error {
	return errors.New("dropping privileges is not supported on this system")
}
