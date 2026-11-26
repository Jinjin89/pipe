// SPDX-License-Identifier: GPL-3.0-or-later
//go:build unix

package update

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func tryLockUpdateFile(f *os.File) (bool, error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
		return false, nil
	}
	return err == nil, err
}
