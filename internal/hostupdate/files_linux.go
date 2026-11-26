// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux

package hostupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"pipe/internal/localfile"
	"pipe/internal/update"
	"pipe/internal/version"

	"golang.org/x/sys/unix"
)

// An unprivileged preview cannot inspect the system scope's root-only state.
func unreadableHostState(path string) bool {
	var st unix.Stat_t
	err := unix.Lstat(path, &st)
	return errors.Is(err, os.ErrPermission) ||
		(err == nil && st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&0077 == 0)
}

func lockUpdate(ctx context.Context, path string, portable bool) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	uid := uint32(os.Geteuid())
	if err := prepareLockDirectory(filepath.Dir(path), uid, portable, portable); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("open update lock: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Uid != uid || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 {
		unix.Close(fd)
		return nil, errors.New("the update lock must be a private regular file owned by the current user")
	}
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { unix.Close(fd) }, nil
		}
		if !errors.Is(err, unix.EINTR) || ctx.Err() != nil {
			unix.Close(fd)
			if errors.Is(err, unix.EWOULDBLOCK) {
				return nil, errors.New("another Pipe update is in progress")
			}
			return nil, fmt.Errorf("lock Pipe update: %w", err)
		}
	}
}

func prepareLockDirectory(path string, uid uint32, create, private bool) error {
	parent := filepath.Dir(path)
	if parent != path {
		if err := prepareLockDirectory(parent, uid, create, false); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if create && errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || (st.Uid != uid && st.Uid != 0) {
		return fmt.Errorf("unprotected update lock directory %s", path)
	}
	mode := info.Mode()
	if private && (st.Uid != uid || mode.Perm()&0077 != 0) {
		return fmt.Errorf("update state directory %s must be private and owned by the current user", path)
	}
	if mode.Perm()&0022 != 0 && (st.Uid != 0 || mode&os.ModeSticky == 0) {
		return fmt.Errorf("update lock directory %s must be protected from writes by other users", path)
	}
	return nil
}

type installedBinary struct {
	path, version string
	file          *os.File
	info          os.FileInfo
}

type installedSet struct {
	copies         []installedBinary
	oldest, newest string
}

func (s installedSet) close() {
	for _, binary := range s.copies {
		binary.file.Close()
	}
}

func (s installedSet) olderThan(version string) ([]installedBinary, error) {
	var targets []installedBinary
	for _, binary := range s.copies {
		cmp, ok := update.CompareVersions(binary.version, version)
		if !ok {
			return nil, fmt.Errorf("cannot compare installed Pipe %s with release %s", binary.version, version)
		}
		if cmp < 0 {
			targets = append(targets, binary)
		}
	}
	return targets, nil
}

func (h linuxHost) openInstalled(inv linuxInventory, target update.Target) (set installedSet, err error) {
	defer func() {
		if err != nil {
			set.close()
		}
	}()
	var channel string
	for _, path := range inv.targets {
		binary, err := h.openExecutable(path, inv.system, target)
		if err != nil {
			return set, err
		}
		set.copies = append(set.copies, binary)
		currentChannel, ok := update.ChannelOf(binary.version)
		if !ok {
			return set, legacyExecutable(path)
		}
		if channel == "" {
			channel, set.oldest, set.newest = currentChannel, binary.version, binary.version
		} else if currentChannel != channel {
			return set, fmt.Errorf("installed Pipe binaries use mixed release channels (%s and %s)", channel, currentChannel)
		}
		if cmp, _ := update.CompareVersions(binary.version, set.oldest); cmp < 0 {
			set.oldest = binary.version
		}
		if cmp, _ := update.CompareVersions(binary.version, set.newest); cmp > 0 {
			set.newest = binary.version
		}
	}
	return set, nil
}

func (h linuxHost) openExecutable(path string, system bool, target update.Target) (_ installedBinary, err error) {
	rootProtected := system || h.uid == 0
	if rootProtected {
		if err := h.checkTrusted(path); err != nil {
			return installedBinary{}, fmt.Errorf("untrusted installed executable %s: %w", path, err)
		}
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return installedBinary{}, fmt.Errorf("open installed executable %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() {
		if err != nil {
			file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return installedBinary{}, err
	}
	mode := info.Mode()
	if !mode.IsRegular() || mode.Perm()&0111 == 0 || mode.Perm()&0022 != 0 {
		return installedBinary{}, fmt.Errorf("%s must be a protected regular executable", path)
	}
	if !rootProtected {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uint32(os.Geteuid()) {
			return installedBinary{}, fmt.Errorf("%s must belong to the current user", path)
		}
	}
	if !system {
		running, err := os.Stat(h.path("/proc/self/exe"))
		if err != nil || !os.SameFile(info, running) {
			return installedBinary{}, errors.New("the portable executable differs from the running image. Restart Pipe from its installed path")
		}
	}
	goos, goarch, ver, ok := version.ScanIdentity(io.NewSectionReader(file, 0, info.Size()))
	if !ok || goos != target.OS || goarch != target.ABI {
		return installedBinary{}, legacyExecutable(path)
	}
	return installedBinary{path: path, version: ver, file: file, info: info}, nil
}

func legacyExecutable(path string) error {
	return fmt.Errorf("cannot identify the release in %s. Verify a current Pipe release and bootstrap it once with install -m 0755", path)
}

func (b installedBinary) unchanged() error {
	current, err := os.Lstat(b.path)
	if err != nil {
		return err
	}
	if !os.SameFile(current, b.info) || current.Size() != b.info.Size() || !current.ModTime().Equal(b.info.ModTime()) {
		return fmt.Errorf("%s changed while staging the update. Run pipe update again", b.path)
	}
	return nil
}

func snapshotBinary(dir string, index int, binary installedBinary) (*os.File, error) {
	if err := binary.unchanged(); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "previous-"+strconv.Itoa(index))
	backup, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0700)
	if err != nil {
		return nil, err
	}
	size := binary.info.Size()
	n, err := io.Copy(backup, io.NewSectionReader(binary.file, 0, size))
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
	}
	if err == nil {
		err = backup.Sync()
	}
	if err != nil {
		backup.Close()
		return nil, err
	}
	return backup, nil
}

func (h linuxHost) publish(ctx context.Context, inv linuxInventory, targets []installedBinary, abi string, release update.StagedRelease) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if release.ArchivePath == "" {
		return errors.New("the update did not stage a verified release archive")
	}
	stageDir := filepath.Dir(release.ArchivePath)
	image, cleanup, err := update.ExtractLinuxBinary(release.ArchivePath, abi, release.Version, stageDir)
	if err != nil {
		return err
	}
	defer cleanup()
	rollbackDir, err := os.MkdirTemp(stageDir, ".rollback-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(rollbackDir)

	var backups []*os.File
	defer func() {
		for _, backup := range backups {
			backup.Close()
		}
	}()
	for index, binary := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		backup, err := snapshotBinary(rollbackDir, index, binary)
		if err != nil {
			return fmt.Errorf("snapshot %s: %w", binary.path, err)
		}
		backups = append(backups, backup)
	}
	// The publication lock is still held. A check can have raised the floor
	// while the release downloaded or the backups were prepared.
	if err := release.VerifyFloor(); err != nil {
		return fmt.Errorf("recheck the verified release before installation: %w", err)
	}

	replaced := 0
	failed := func(err error) error {
		if replaced == 0 {
			return err
		}
		if rollbackErr := h.rollback(context.WithoutCancel(ctx), inv, targets[:replaced], backups); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("restore the previous Pipe installation: %w", rollbackErr))
		}
		return fmt.Errorf("update failed and the previous installation was restored: %w", err)
	}
	for _, binary := range targets {
		if err := ctx.Err(); err != nil {
			return failed(err)
		}
		if err := binary.unchanged(); err != nil {
			return failed(err)
		}
		if err := h.install(image, binary.path); err != nil {
			if errors.Is(err, localfile.ErrSyncAfterReplace) || binary.unchanged() != nil {
				replaced++
			}
			return failed(fmt.Errorf("replace %s: %w", binary.path, err))
		}
		replaced++
	}
	for _, unit := range inv.units {
		if unit.role.daemon && unit.active {
			if err := h.restartDaemon(ctx, inv.ctl, "try-restart", unit, release.Version); err != nil {
				return failed(err)
			}
		}
	}
	return nil
}

func (h linuxHost) rollback(ctx context.Context, inv linuxInventory, replaced []installedBinary, backups []*os.File) error {
	restored := make(map[string]string, len(replaced))
	var result error
	for n := len(replaced) - 1; n >= 0; n-- {
		binary := replaced[n]
		err := h.install(backups[n], binary.path)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("restore %s: %w", binary.path, err))
		}
		if err == nil || errors.Is(err, localfile.ErrSyncAfterReplace) {
			restored[binary.path] = binary.version
		}
	}
	for _, unit := range inv.units {
		if version, ok := restored[unit.binary]; ok && unit.role.daemon && unit.active {
			// A daemon that failed during the forward restart may now be stopped.
			result = errors.Join(result, h.restartDaemon(ctx, inv.ctl, "restart", unit, version))
		}
	}
	return result
}
