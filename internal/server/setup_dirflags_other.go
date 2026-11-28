// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix && !linux

package server

import "golang.org/x/sys/unix"

const setupDirTraversalFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
