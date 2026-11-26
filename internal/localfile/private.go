// SPDX-License-Identifier: GPL-3.0-or-later

package localfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// ErrSyncAfterReplace reports an executable replacement whose parent sync failed.
var ErrSyncAfterReplace = errors.New("replaced executable but could not sync parent directory")

// WritePrivate creates an exclusive owner-only file and removes it on write failure.
func WritePrivate(path string, data []byte) error {
	f, err := createPrivate(path)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

// WritePrivateAtomic replaces a file with an owner-only file in the same directory.
func WritePrivateAtomic(path string, data []byte) error {
	return writePrivateAtomic(path, data, false)
}

// WritePrivateAtomicSyncDir makes the replacement durable in its parent directory.
func WritePrivateAtomicSyncDir(path string, data []byte) error {
	return writePrivateAtomic(path, data, true)
}

func writePrivateAtomic(path string, data []byte, syncDir bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temp := filepath.Join(dir, ".pipe-"+hex.EncodeToString(random[:]))
	if err := WritePrivate(temp, data); err != nil {
		return err
	}
	if err := replacePrivate(temp, path, syncDir); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}
