// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !unix

package localfile

import "os"

func openRegular(path string) (*os.File, error) { return os.Open(path) }

func openRegularNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, os.ErrInvalid
	}
	return os.Open(path)
}
