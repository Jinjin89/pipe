// SPDX-License-Identifier: GPL-3.0-or-later
//go:build windows

package desktop

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/sys/windows"
)

// acquireLock takes a named mutex derived from the config path, so different
// config dirs get different instances.
func acquireLock(path string) (release func(), held bool, err error) {
	sum := sha256.Sum256([]byte(path))
	name, err := windows.UTF16PtrFromString(`Local\PipeApp-` + hex.EncodeToString(sum[:8]))
	if err != nil {
		return nil, false, err
	}
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			if handle != 0 {
				windows.CloseHandle(handle)
			}
			return nil, true, nil
		}
		return nil, false, err
	}
	return func() { windows.CloseHandle(handle) }, false, nil
}
