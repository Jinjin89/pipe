// SPDX-License-Identifier: GPL-3.0-or-later

package version

import (
	"bytes"
	"runtime"
	"testing"
)

func TestParseAndScanIdentity(t *testing.T) {
	goos, goarch, ver, ok := ParseIdentity([]byte("prefix" + ReleaseIdentity + "suffix"))
	if !ok || goos != runtime.GOOS || goarch != runtime.GOARCH || ver != Version {
		t.Fatalf("ParseIdentity = (%q, %q, %q, %t)", goos, goarch, ver, ok)
	}

	// Marker crossing the 64 KiB read chunk boundary must still match once.
	big := make([]byte, 64*1024-5)
	big = append(big, []byte(ReleaseIdentity)...)
	big = append(big, make([]byte, 1024)...)
	goos, goarch, ver, ok = ScanIdentity(bytes.NewReader(big))
	if !ok || goos != runtime.GOOS || goarch != runtime.GOARCH || ver != Version {
		t.Fatalf("ScanIdentity across boundary = (%q, %q, %q, %t)", goos, goarch, ver, ok)
	}

	// Duplicate markers must be rejected.
	dup := append([]byte(ReleaseIdentity), []byte(ReleaseIdentity)...)
	if _, _, _, ok := ParseIdentity(dup); ok {
		t.Fatal("duplicate identity marker was accepted")
	}
	sharedNUL := []byte(ReleaseIdentity + ReleaseIdentity[1:])
	if _, _, _, ok := ParseIdentity(sharedNUL); ok {
		t.Fatal("duplicate identity marker with a shared terminator was accepted")
	}

	// Missing marker must be rejected.
	if _, _, _, ok := ParseIdentity([]byte("no marker here")); ok {
		t.Fatal("missing identity marker was accepted")
	}
}
