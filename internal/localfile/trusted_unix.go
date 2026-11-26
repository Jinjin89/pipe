// SPDX-License-Identifier: GPL-3.0-or-later
//go:build unix

package localfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// TrustedExecutable resolves an executable to a path only root can replace.
func TrustedExecutable(path string) (string, error) {
	f, err := openTrustedExecutable(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return f.Name(), nil
}

func openTrustedExecutable(path string) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	dir, err := trustedDirectory(filepath.Dir(resolved), false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, filepath.Base(resolved), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), resolved)
	if err := checkExecutable(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func checkExecutable(f *os.File) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Uid != 0 || st.Mode&022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0111 == 0 {
		return fmt.Errorf("%s must be a root-owned, protected executable", f.Name())
	}
	if err := CheckFDNoNonOwnerWriteACL(int(f.Fd()), 0); err != nil {
		return fmt.Errorf("%s must not grant write access through an ACL: %w", f.Name(), err)
	}
	return nil
}

// OpenTrustedRunningImage opens the approved executable. On Linux the
// descriptor points to the running image, independently of its later name.
func OpenTrustedRunningImage(path string) (*os.File, error) {
	approved, err := openTrustedExecutable(path)
	if err != nil || runtime.GOOS != "linux" {
		return approved, err
	}
	defer approved.Close()
	running, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, err
	}
	a, aErr := approved.Stat()
	b, bErr := running.Stat()
	if aErr != nil || bErr != nil || !os.SameFile(a, b) {
		running.Close()
		return nil, errors.New("the running image differs from the approved executable")
	}
	if err := checkExecutable(running); err != nil {
		running.Close()
		return nil, err
	}
	return running, nil
}

// MakeTrustedDirectory creates missing directories under root-only ancestors.
func MakeTrustedDirectory(path string) error {
	fd, err := trustedDirectory(path, true)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func trustedDirectory(path string, create bool) (int, error) {
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if !filepath.IsAbs(path) {
		return -1, errors.New("trusted directory must have an absolute path")
	}
	fd, err := unix.Open("/", flags, 0)
	if err != nil {
		return -1, err
	}
	current := "/"
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	for i := 0; ; i++ {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil || st.Uid != 0 || st.Mode&022 != 0 {
			unix.Close(fd)
			return -1, fmt.Errorf("directory %s must be owned by root and protected from group and other writes", current)
		}
		if err := CheckFDNoNonOwnerWriteACL(fd, 0); err != nil {
			unix.Close(fd)
			return -1, fmt.Errorf("directory %s must not grant write access through an ACL: %w", current, err)
		}
		if i == len(parts) || parts[i] == "" {
			return fd, nil
		}
		part := parts[i]
		current = filepath.Join(current, part)
		next, err := unix.Openat(fd, part, flags, 0)
		if err == unix.ENOENT && create {
			if err = unix.Mkdirat(fd, part, 0755); err == nil || err == unix.EEXIST {
				next, err = unix.Openat(fd, part, flags, 0)
			}
		}
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("open trusted directory %s: %w", current, err)
		}
		fd = next
	}
}

// CheckTrustedFile verifies that path resolves without symlinks under
// root-owned, non-group/world-writable directories and is a root-owned regular file.
func CheckTrustedFile(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("trusted file must have an absolute path")
	}
	dir, err := trustedDirectory(filepath.Dir(path), false)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != 0 || st.Mode&022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%s must be a root-owned, protected file", path)
	}
	if err := CheckFDNoNonOwnerWriteACL(fd, 0); err != nil {
		return fmt.Errorf("%s must not grant write access through an ACL: %w", path, err)
	}
	return nil
}

// InstallTrustedExecutable publishes bytes from an approved, already open image.
func InstallTrustedExecutable(source *os.File, dest string) error {
	if os.Geteuid() != 0 {
		return errors.New("installing a system executable requires root")
	}
	if err := checkExecutable(source); err != nil {
		return err
	}
	dir, err := trustedDirectory(filepath.Dir(dest), true)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	return publishExecutable(source, dir, filepath.Base(dest), true, unix.Fsync)
}

// InstallOwnerExecutable atomically replaces dest from an already-verified open
// file inside an owner-controlled directory (for portable non-root updates).
func InstallOwnerExecutable(source *os.File, dest string) error {
	uid := uint32(os.Geteuid())
	var st unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &st); err != nil {
		return err
	}
	if st.Uid != uid || st.Mode&022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0111 == 0 {
		return fmt.Errorf("%s must be an owner-protected executable", source.Name())
	}
	if err := CheckFDNoNonOwnerWriteACL(int(source.Fd()), uid); err != nil {
		return fmt.Errorf("%s must not grant write access through an ACL: %w", source.Name(), err)
	}
	var dir int
	var err error
	if uid == 0 {
		dir, err = trustedDirectory(filepath.Dir(dest), false)
	} else {
		dir, err = ownerProtectedDirectory(filepath.Dir(dest), uid)
	}
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	name := filepath.Base(dest)
	var existing unix.Stat_t
	if err := unix.Fstatat(dir, name, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if existing.Uid != uid || existing.Mode&022 != 0 || existing.Mode&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("%s must be a protected, owner-owned regular file", dest)
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	return publishExecutable(source, dir, name, uid == 0, unix.Fsync)
}

func ownerProtectedDirectory(path string, uid uint32) (int, error) {
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if !filepath.IsAbs(path) {
		return -1, errors.New("destination directory must have an absolute path")
	}
	fd, err := unix.Open("/", flags, 0)
	if err != nil {
		return -1, err
	}
	current := "/"
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	for i := 0; ; i++ {
		leaf := i == len(parts) || parts[i] == ""
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return -1, err
		}
		if leaf {
			if st.Uid != uid || st.Mode&022 != 0 {
				unix.Close(fd)
				return -1, fmt.Errorf("directory %s must be owned by the current user and not writable by others", current)
			}
			if err := CheckFDNoNonOwnerWriteACL(fd, uid); err != nil {
				unix.Close(fd)
				return -1, fmt.Errorf("directory %s must not grant write access through an ACL: %w", current, err)
			}
			return fd, nil
		}
		stickyRoot := st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
		if (st.Uid != 0 && st.Uid != uid) || (st.Mode&022 != 0 && !stickyRoot) {
			unix.Close(fd)
			return -1, fmt.Errorf("directory %s must be protected from writes by other users", current)
		}
		if !stickyRoot {
			if err := CheckFDNoNonOwnerWriteACL(fd, st.Uid); err != nil {
				unix.Close(fd)
				return -1, fmt.Errorf("directory %s must not grant write access through an ACL: %w", current, err)
			}
		}
		part := parts[i]
		current = filepath.Join(current, part)
		next, err := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("open directory %s: %w", current, err)
		}
		fd = next
	}
}

func publishExecutable(source *os.File, dir int, name string, chownRoot bool, syncDir func(int) error) error {
	var a, b unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &a); err != nil {
		return err
	}
	if chownRoot && unix.Fstatat(dir, name, &b, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		a.Dev == b.Dev && a.Ino == b.Ino && b.Gid == 0 && b.Mode&07777 == 0755 {
		return nil
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temp := ".pipe-install-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(dir, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), temp)
	defer f.Close()
	defer unix.Unlinkat(dir, temp, 0)
	if err := clearDarwinACL(fd); err != nil {
		return err
	}
	if n, err := io.Copy(f, io.NewSectionReader(source, 0, a.Size)); err != nil {
		return err
	} else if n != a.Size {
		return io.ErrUnexpectedEOF
	}
	if chownRoot {
		if err := f.Chown(0, 0); err != nil {
			return err
		}
	}
	if err := f.Chmod(0755); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := unix.Renameat(dir, temp, dir, name); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("%w: %w", ErrSyncAfterReplace, err)
	}
	return nil
}
