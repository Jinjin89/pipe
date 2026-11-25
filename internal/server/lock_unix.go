// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux || darwin

package server

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func lockDir(dir string) (func(), error) {
	file, err := os.OpenFile(filepath.Join(dir, ".state.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			if err != nil {
				file.Close()
				return nil, err
			}
			return func() { file.Close() }, nil
		}
	}
}
