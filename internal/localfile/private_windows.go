// SPDX-License-Identifier: GPL-3.0-or-later

package localfile

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func createPrivate(path string) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := privateDescriptor(user.User.Sid)
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	attrs := windows.SecurityAttributes{SecurityDescriptor: sd}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &attrs, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "create private file", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

func privateDescriptor(user *windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	return windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.String() + ")")
}

func fileSecurity(handle windows.Handle) (*windows.SECURITY_DESCRIPTOR, error) {
	return windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
}

func checkPrivateACL(file *os.File) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := fileSecurity(windows.Handle(file.Fd()))
	if err != nil {
		return err
	}
	if err := validatePrivateACL(sd, user.User.Sid, false); err != nil {
		return fmt.Errorf("%w. To repair a legacy file you own, run pipe run --migrate-private with the file path, or re-import it from a trusted copy", err)
	}
	return nil
}

func trustedSecretSID(sid, user *windows.SID) bool {
	return sid != nil && (sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

func validatePrivateACL(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, migrating bool) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if !trustedSecretSID(owner, user) || (migrating && !owner.Equals(user)) {
		return errors.New("the file has an unexpected owner")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return errors.New("the file needs a current-user access list")
	}
	// Migration is safe for read-only exposure. A legacy file that another
	// account could have modified must be replaced from a trusted copy.
	const readOnly = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE |
		windows.GENERIC_READ | windows.GENERIC_EXECUTE
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var entry *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &entry); err != nil {
			return err
		}
		if entry.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("the file needs a current-user access list")
		}
		sid := (*windows.SID)(unsafe.Pointer(&entry.SidStart))
		if trustedSecretSID(sid, user) || (migrating && entry.Mask&^windows.ACCESS_MASK(readOnly) == 0) {
			continue
		}
		if migrating {
			return errors.New("another user could have modified the file. Replace it from a trusted copy")
		}
		return errors.New("the file grants access to another user or group")
	}
	return nil
}

// MigratePrivate replaces a current-user legacy file's read-only sharing ACL
// with a protected user-only ACL. The contents are never opened for writing.
func MigratePrivate(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// Open the object itself, excluding reparse points and concurrent content
	// writers or replacers. Ownership and DACL are checked on this handle.
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return &os.PathError{Op: "open for private ACL migration", Path: path, Err: err}
	}
	defer windows.CloseHandle(handle)
	kind, err := windows.GetFileType(handle)
	if err != nil {
		return err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if kind != windows.FILE_TYPE_DISK ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return errors.New("private ACL migration requires a regular file")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	existing, err := fileSecurity(handle)
	if err != nil {
		return err
	}
	if err := validatePrivateACL(existing, user.User.Sid, true); err != nil {
		return err
	}
	replacement, err := privateDescriptor(user.User.Sid)
	if err != nil {
		return err
	}
	dacl, _, err := replacement.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
