// SPDX-License-Identifier: GPL-3.0-or-later

package localfile

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateACLPolicy(t *testing.T) {
	const current = "S-1-5-21-1-2-3-1001"
	user, err := windows.StringToSid(current)
	if err != nil {
		t.Fatal(err)
	}
	allowCurrent := "D:P(A;;FA;;;" + current + ")"
	for _, test := range []struct {
		name, descriptor string
		read, migrate    bool
	}{
		{"current user", "O:" + current + allowCurrent, true, true},
		{"local system", "O:SY" + allowCurrent, true, false},
		{"administrators", "O:BA" + allowCurrent, true, false},
		{"foreign owner", "O:S-1-5-21-1-2-3-1002" + allowCurrent, false, false},
		{"missing DACL", "O:" + current, false, false},
		{"empty DACL", "O:" + current + "D:P", false, false},
		{"null DACL", "O:" + current + "D:NO_ACCESS_CONTROL", false, false},
		{"denied ACE", "O:" + current + "D:P(D;;GW;;;WD)(A;;FA;;;" + current + ")", false, false},
		{"legacy shared reading", "O:" + current + allowCurrent + "(A;;GR;;;WD)", false, true},
		{"legacy shared writing", "O:" + current + allowCurrent + "(A;;GW;;;WD)", false, false},
		{"trusted ACEs", "O:" + current + allowCurrent + "(A;;FA;;;SY)(A;;FA;;;BA)", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(test.descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if err := validatePrivateACL(sd, user, false); (err == nil) != test.read {
				t.Errorf("read policy returned %v", err)
			}
			if err := validatePrivateACL(sd, user, true); (err == nil) != test.migrate {
				t.Errorf("migration policy returned %v", err)
			}
		})
	}
}

func TestPrivateReadRejectsExposedLegacyFileUntilMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.link")
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;GR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	attr := windows.SecurityAttributes{SecurityDescriptor: sd}
	attr.Length = uint32(unsafe.Sizeof(attr))
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &attr, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(handle), path)
	_, writeErr := f.WriteString("legacy fixture")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("write legacy fixture: %v, %v", writeErr, closeErr)
	}
	if data, err := Read(path, 4096, true); err == nil || data != nil {
		t.Fatal("owner-only reader returned an exposed secret")
	}
	if err := MigratePrivate(path); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadProtected(path, 4096); err != nil || string(data) != "legacy fixture" {
		t.Fatalf("read after ACL migration: %v", err)
	}
}

func TestPrivateWriteHasProtectedUserDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.link")
	if err := WritePrivateAtomic(path, []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := checkPrivateACL(f); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	flags, _, err := sd.Control()
	if err != nil || flags&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("file's ACL can inherit from the parent: %v", err)
	}
}
