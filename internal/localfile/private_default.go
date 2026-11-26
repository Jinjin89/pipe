// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !windows

package localfile

import (
	"errors"
	"os"
	"syscall"
)

func createPrivate(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	if err := clearDarwinACL(int(f.Fd())); err != nil {
		f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return f, nil
}

func checkPrivateACL(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return CheckFDPrivateACL(int(file.Fd()), st.Uid)
	}
	return nil
}

func MigratePrivate(string) error {
	return errors.New("private file ACL migration is available on Windows")
}
