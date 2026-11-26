// SPDX-License-Identifier: GPL-3.0-or-later
//go:build unix

package update

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"pipe/internal/localfile"
)

func mkdirPrivate(path string) error { return os.Mkdir(path, 0700) }

func directoryAnchor(path string) (string, error) {
	if runtime.GOOS == "android" {
		// Android supplies dataDir/no_backup/updates. Anchor the walk at
		// the private app data directory below the platform's UID aliases.
		return filepath.Dir(filepath.Dir(path)), nil
	}
	return "", nil
}

func checkDirectory(path string, info os.FileInfo, private bool) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errUnsafeDirectory
	}
	user := uint32(os.Geteuid())
	mode := info.Mode()
	if private {
		if st.Uid != user || mode.Perm()&0077 != 0 {
			return errUnsafeDirectory
		}
		if localfile.CheckDirectoryACL(path, st, true) != nil {
			return errUnsafeDirectory
		}
		return nil
	}
	if st.Uid != 0 && st.Uid != user {
		return errUnsafeDirectory
	}
	if runtime.GOOS == "android" && st.Uid == user {
		// Ancestors inside the already verified app sandbox can use Android's
		// own no-backup directory mode.
		return nil
	}
	// A root-owned sticky directory permits creation of new entries, but
	// only trusted owners can replace the next entry, whose UID we check.
	if mode.Perm()&0022 != 0 && (st.Uid != 0 || mode&os.ModeSticky == 0) {
		return errUnsafeDirectory
	}
	if localfile.CheckDirectoryACL(path, st, false) != nil {
		return errUnsafeDirectory
	}
	return nil
}
