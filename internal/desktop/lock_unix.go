// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux || darwin

package desktop

import (
	"os"

	"golang.org/x/sys/unix"
)

// acquireLock takes the single-instance lock. held is true when another
// process owns it.
func acquireLock(path string) (release func(), held bool, err error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, false, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if err == unix.EWOULDBLOCK {
			return nil, true, nil
		}
		return nil, false, err
	}
	return func() { file.Close() }, false, nil
}
