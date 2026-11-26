// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin

package localfile

import (
	"errors"
	"runtime"
	"sync"
	"syscall"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

const darwinACLTypeExtended = 0x100 // ACL_TYPE_EXTENDED from sys/acl.h

var errUnsafeDarwinACL = errors.New("file or directory ACL grants access to another user or group")

type darwinACLFunctions struct {
	getFD   func(int32, int32) uintptr
	setFD   func(int32, uintptr, int32) int32
	initACL func(int32) uintptr
	copyExt func(*byte, uintptr, int) int
	free    func(uintptr) int32
	getErr  func() *int32
	uidUUID func(uint32, *[16]byte) int32
}

var darwinACL = sync.OnceValue(func() *darwinACLFunctions {
	var api darwinACLFunctions
	for name, target := range map[string]any{
		"acl_get_fd_np":   &api.getFD,
		"acl_set_fd_np":   &api.setFD,
		"acl_init":        &api.initACL,
		"acl_copy_ext":    &api.copyExt,
		"acl_free":        &api.free,
		"__error":         &api.getErr,
		"mbr_uid_to_uuid": &api.uidUUID,
	} {
		addr, err := purego.Dlsym(purego.RTLD_DEFAULT, name)
		if err != nil {
			return nil
		}
		purego.RegisterFunc(target, addr)
	}
	return &api
})

func checkDarwinFDACL(fd int, ownerUID uint32, ownerOnly bool) error {
	api := darwinACL()
	if api == nil {
		return errUnsafeDarwinACL
	}
	runtime.LockOSThread()
	errno := api.getErr()
	*errno = 0
	acl := api.getFD(int32(fd), darwinACLTypeExtended)
	noACL := *errno == int32(unix.ENOENT)
	runtime.UnlockOSThread()
	if acl == 0 {
		if noACL {
			return nil
		}
		return errUnsafeDarwinACL
	}
	defer api.free(acl)

	var raw [darwinACLHeader + darwinACLMaxACEs*darwinACEBytes]byte
	n := api.copyExt(&raw[0], acl, len(raw))
	ownerUUID := sync.OnceValue(func() [16]byte {
		var uuid [16]byte
		if api.uidUUID(ownerUID, &uuid) != 0 {
			return [16]byte{}
		}
		return uuid
	})
	if n < 0 || n > len(raw) || !safeDarwinACL(raw[:n], func(principal [16]byte) bool {
		return principal != [16]byte{} && principal == ownerUUID()
	}, ownerOnly) {
		return errUnsafeDarwinACL
	}
	return nil
}

// CheckFDNoNonOwnerWriteACL rejects Darwin extended ACLs granting write/replace rights to non-owners.
func CheckFDNoNonOwnerWriteACL(fd int, ownerUID uint32) error {
	return checkDarwinFDACL(fd, ownerUID, false)
}

// CheckFDPrivateACL rejects Darwin extended ACLs granting any read or write access to non-owners.
func CheckFDPrivateACL(fd int, ownerUID uint32) error {
	return checkDarwinFDACL(fd, ownerUID, true)
}

// clearDarwinACL removes any inherited extended ACL on an open descriptor before writing secrets.
func clearDarwinACL(fd int) error {
	api := darwinACL()
	if api == nil {
		return errUnsafeDarwinACL
	}
	empty := api.initACL(0)
	if empty == 0 {
		return errUnsafeDarwinACL
	}
	defer api.free(empty)
	if api.setFD(int32(fd), empty, darwinACLTypeExtended) != 0 {
		return errUnsafeDarwinACL
	}
	return nil
}

// CheckDirectoryACL verifies the Darwin extended ACL on a directory matching expected stat metadata.
func CheckDirectoryACL(path string, expected *syscall.Stat_t, private bool) error {
	fd, err := unix.Open(path, unix.O_SEARCH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errUnsafeDarwinACL
	}
	defer unix.Close(fd)
	var opened unix.Stat_t
	if unix.Fstat(fd, &opened) != nil || opened.Dev != expected.Dev || opened.Ino != expected.Ino ||
		opened.Uid != expected.Uid || opened.Mode != expected.Mode {
		return errUnsafeDarwinACL
	}
	return checkDarwinFDACL(fd, opened.Uid, private)
}
