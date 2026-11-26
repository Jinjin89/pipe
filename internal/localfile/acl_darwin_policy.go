// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin || linux

package localfile

import "encoding/binary"

const (
	// Portable acl_copy_ext format from Darwin's sys/kauth.h.
	darwinACLMagic   = 0x012cc16d
	darwinACLHeader  = 44
	darwinACEBytes   = 24
	darwinACLMaxACEs = 128
	darwinACLAllow   = 1
	darwinACLDeny    = 2
	darwinACLKind    = 0xf
	darwinACEFlags   = 0x1ff // kind and inheritance flags

	darwinACLReadOnly = 1<<1 | 1<<3 | 1<<7 | 1<<9 | 1<<11 | 1<<20
	darwinACLWrite    = 1<<2 | 1<<4 | 1<<5 | 1<<6 | 1<<8 | 1<<10 | 1<<12 | 1<<13
	darwinACLSyncOnly = 1 << 20
)

// safeDarwinACL validates a raw acl_copy_ext buffer.
// When ownerOnly is false (executables and shared ancestors), any non-owner write/replace/security right is rejected.
// When ownerOnly is true (private secret files and 0700 dirs), any non-owner allow right beyond synchronize is rejected.
func safeDarwinACL(raw []byte, isOwner func([16]byte) bool, ownerOnly bool) bool {
	be := binary.BigEndian
	if len(raw) < darwinACLHeader || be.Uint32(raw) != darwinACLMagic {
		return false
	}
	count := be.Uint32(raw[36:])
	if count > darwinACLMaxACEs || len(raw) != darwinACLHeader+int(count)*darwinACEBytes {
		return false
	}
	for ace := raw[darwinACLHeader:]; len(ace) != 0; ace = ace[darwinACEBytes:] {
		flags, rights := be.Uint32(ace[16:]), be.Uint32(ace[20:])
		kind := flags & darwinACLKind
		if flags&^darwinACEFlags != 0 || rights&^(darwinACLReadOnly|darwinACLWrite) != 0 ||
			(kind != darwinACLAllow && kind != darwinACLDeny) {
			return false
		}
		if kind != darwinACLAllow || isOwner([16]byte(ace[:16])) {
			continue
		}
		if ownerOnly {
			if rights&^darwinACLSyncOnly != 0 {
				return false
			}
		} else if rights&darwinACLWrite != 0 {
			return false
		}
	}
	return true
}
