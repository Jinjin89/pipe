// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func lockDir(dir string) (func(), error) {
	file, err := os.OpenFile(filepath.Join(dir, ".state.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var offset windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &offset); err != nil {
		file.Close()
		return nil, err
	}
	return func() { file.Close() }, nil
}
