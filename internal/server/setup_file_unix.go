// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	return openTrustedSetupPath(path, pipeUID, trustedSetupOperator(), false, false)
}

func trustedSetupOperator() uint32 {
	if os.Getuid() != 0 {
		return uint32(os.Getuid())
	}
	uid, _ := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	return uint32(uid)
}

func createSetupOutput(path string, pipeUID uint32) (*os.File, func(bool) error, error) {
	operator := trustedSetupOperator()
	if operator == pipeUID {
		return nil, nil, fmt.Errorf("user pipe cannot own the enrollment output")
	}
	dir, err := openTrustedSetupPath(filepath.Dir(path), pipeUID, operator, false, false)
	if err != nil {
		return nil, nil, err
	}
	name := filepath.Base(path)
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0600)
	if err != nil {
		dir.Close()
		return nil, nil, &os.PathError{Op: "create enrollment file", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	if err := file.Chown(int(operator), -1); err != nil {
		file.Close()
		_ = unix.Unlinkat(int(dir.Fd()), name, 0)
		dir.Close()
		return nil, nil, err
	}
	// A failed delivery must leave neither an output file nor any exposed bytes.
	return file, func(keep bool) error {
		defer dir.Close()
		err := file.Close()
		if !keep {
			if removeErr := unix.Unlinkat(int(dir.Fd()), name, 0); removeErr != nil && removeErr != unix.ENOENT {
				return removeErr
			}
		}
		return err
	}, nil
}

func openSetupState(path string, pipeUID uint32, create bool) (*os.Root, error) {
	dir, err := openTrustedSetupPath(path, pipeUID, trustedSetupOperator(), true, create)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	// Setup runs only on Linux. The descriptor anchors the root to the
	// directory opened without symlinks, even if its name is replaced.
	return os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", dir.Fd()))
}

func openTrustedSetupPath(path string, pipeUID, operator uint32, state, create bool) (*os.File, error) {
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
			if stat.Uid != 0 && stat.Uid != operator {
				return nil, fmt.Errorf("unsafe setup path %q: %q must be owned by root or the setup operator", path, pathPart)
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
