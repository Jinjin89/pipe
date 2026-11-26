// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func openSetupFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func setupFileOwner(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

// openSetupOperatorFile resolves each component from an open directory. An
// operator-owned entry in a sticky directory such as /tmp cannot be replaced
// by Pipe. Outside that case, writable group bits can also represent ACLs.
func openSetupOperatorFile(path string, pipeUID uint32) (*os.File, error) {
	return openTrustedSetupPath(path, pipeUID, false, false)
}

func openSetupState(path string, pipeUID uint32, create bool) (*os.Root, error) {
	dir, err := openTrustedSetupPath(path, pipeUID, true, create)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	// Setup runs only on Linux. The descriptor anchors the root to the
	// directory opened without symlinks, even if its name is replaced.
	return os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", dir.Fd()))
}

func openTrustedSetupPath(path string, pipeUID uint32, state, create bool) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil || abs == "/" {
		return nil, fmt.Errorf("invalid setup path %q", path)
	}
	const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Open("/", dirFlags, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	parts := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	pathPart := "/"
	for i := 0; ; i++ {
		leaf := i == len(parts)
		if !state || !leaf {
			var stat unix.Stat_t
			if err := unix.Fstat(fd, &stat); err != nil {
				return nil, err
			}
			// The state directory will become Pipe-owned, so its immediate
			// parent must prohibit renames even if it is sticky.
			requireProtected := leaf || state && i == len(parts)-1
			if stat.Uid == pipeUID {
				return nil, fmt.Errorf("unsafe setup path %q: %q must not be owned by user pipe", path, pathPart)
			}
			sticky := stat.Mode&unix.S_ISVTX != 0
			if stat.Mode&0022 != 0 && (requireProtected || !sticky) {
				const writablePath = "unsafe setup path %q: %q is group- or world-writable; "
				if sticky {
					return nil, fmt.Errorf(writablePath+"choose a path under a protected directory writable only by root or the operator (for example, /root/pipe/setup.json for input or %s for state)", path, pathPart, setupStateDir)
				}
				if pathPart == "/" {
					return nil, fmt.Errorf(writablePath+"ask the system administrator to review the filesystem root permissions before running setup", path, pathPart)
				}
				argument := pathPart
				if strings.ContainsFunc(pathPart, func(r rune) bool {
					return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
						r >= '0' && r <= '9' || strings.ContainsRune("/._-", r))
				}) {
					argument = "'" + strings.ReplaceAll(pathPart, "'", `'\''`) + "'"
				}
				return nil, fmt.Errorf(writablePath+"run: chmod go-w %s", path, pathPart, argument)
			}
		}
		if leaf {
			file := os.NewFile(uintptr(fd), path)
			fd = -1
			return file, nil
		}
		flags := dirFlags
		if !state && i == len(parts)-1 {
			flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		}
		part := parts[i]
		pathPart = filepath.Join(pathPart, part)
		next, err := unix.Openat(fd, part, flags, 0)
		if err == unix.ENOENT && create {
			mode := uint32(0711)
			if i == len(parts)-1 {
				mode = 0700
			}
			if err = unix.Mkdirat(fd, part, mode); err == nil || err == unix.EEXIST {
				next, err = unix.Openat(fd, part, flags, 0)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("open setup path %q without following links: %w", pathPart, err)
		}
		_ = unix.Close(fd)
		fd = next
	}
}
