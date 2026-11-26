// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func tryLockUpdateFile(f *os.File) (bool, error) {
	var offset windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &offset)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return err == nil, err
}
