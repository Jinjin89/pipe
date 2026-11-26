// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func mkdirPrivate(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	return windows.CreateDirectory(name, &sa)
}

func directoryAnchor(path string) (string, error) {
	if len(filepath.VolumeName(path)) != 2 {
		return "", errUnsafeDirectory
	}
	return "", nil
}

func checkDirectory(path string, _ os.FileInfo, private bool) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errUnsafeDirectory
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return checkDirectorySecurity(sd, user.User.Sid, private)
}

func checkDirectorySecurity(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, private bool) error {
	trusted := func(sid *windows.SID) bool {
		const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
		return sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) ||
			sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.String() == trustedInstaller
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !trusted(owner) || (private && !owner.Equals(user)) {
		return errUnsafeDirectory
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errUnsafeDirectory
	}
	// Adding a sibling on a drive root cannot replace a protected child.
	// DELETE_CHILD can remove that child even when its own DACL denies DELETE.
	const deleteChild = 0x40
	const replacementRights windows.ACCESS_MASK = deleteChild | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_WRITE_ATTRIBUTES
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errUnsafeDirectory
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if (private || ace.Mask&replacementRights != 0) && !trusted(sid) {
			return errUnsafeDirectory
		}
	}
	return nil
}
