// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestStageWindowsRejectsDeleteChildOnAnAncestor(t *testing.T) {
	parent := filepath.Join(updateTestDir(t), "shared")
	if err := mkdirPrivate(parent); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "owned", "updates")
	if err := privateDir(dir); err != nil {
		t.Fatalf("protected ancestor was refused: %v", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;;0x40;;;AU)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err := privateDir(dir); !errors.Is(err, errUnsafeDirectory) {
		t.Fatalf("accepted DELETE_CHILD for unrelated users: %v", err)
	}
}
