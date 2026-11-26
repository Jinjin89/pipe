// SPDX-License-Identifier: GPL-3.0-or-later
//go:build unix

package localfile

import (
	"os"
	"syscall"
)

func openRegular(path string) (*os.File, error) {
	// A FIFO must return promptly so the regular-file check can reject it.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func openRegularNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
