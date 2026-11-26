// SPDX-License-Identifier: GPL-3.0-or-later
//go:build unix && !darwin

package localfile

import "syscall"

// CheckFDNoNonOwnerWriteACL is a no-op outside Darwin.
func CheckFDNoNonOwnerWriteACL(int, uint32) error { return nil }

// CheckFDPrivateACL is a no-op outside Darwin.
func CheckFDPrivateACL(int, uint32) error { return nil }

func clearDarwinACL(int) error { return nil }

// CheckDirectoryACL is a no-op outside Darwin.
func CheckDirectoryACL(string, *syscall.Stat_t, bool) error { return nil }
