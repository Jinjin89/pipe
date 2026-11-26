// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin || linux

package localfile

import (
	"encoding/binary"
	"testing"
)

func TestDarwinACLPolicy(t *testing.T) {
	owner, other := [16]byte{1}, [16]byte{2}
	type entry struct {
		principal     [16]byte
		flags, rights uint32
	}
	encode := func(entries ...entry) []byte {
		raw := make([]byte, 44+len(entries)*24)
		binary.BigEndian.PutUint32(raw, 0x012cc16d)
		binary.BigEndian.PutUint32(raw[36:], uint32(len(entries)))
		for i, e := range entries {
			ace := raw[44+i*24:]
			copy(ace, e.principal[:])
			binary.BigEndian.PutUint32(ace[16:], e.flags)
			binary.BigEndian.PutUint32(ace[20:], e.rights)
		}
		return raw
	}
	for _, tc := range []struct {
		name      string
		raw       []byte
		ownerOnly bool
		want      bool
	}{
		{"empty dir", encode(), false, true},
		{"empty private", encode(), true, true},
		{"dir allows non-owner read/search", encode(entry{other, 1, 1<<1 | 1<<3}), false, true},
		{"private rejects non-owner read", encode(entry{other, 1, 1 << 1}), true, false},
		{"private rejects non-owner read attrs", encode(entry{other, 1, 1 << 7}), true, false},
		{"private allows owner read/write", encode(entry{owner, 1, 1<<1 | 1<<2}), true, true},
		{"deny delete allowed", encode(entry{other, 2, 1 << 4}), false, true},
		{"deny read on private allowed", encode(entry{other, 2, 1 << 1}), true, true},
		{"owner write and delete", encode(entry{owner, 1, 1<<2 | 1<<4}), false, true},
		{"non-owner write", encode(entry{other, 1, 1 << 2}), false, false},
		{"non-owner delete", encode(entry{other, 1, 1 << 4}), false, false},
		{"non-owner append", encode(entry{other, 1, 1 << 5}), false, false},
		{"inheritable delete child", encode(entry{other, 1 | 1<<6 | 1<<8, 1 << 6}), false, false},
		{"non-owner change security", encode(entry{other, 1, 1 << 12}), false, false},
		{"unexpected rights", encode(entry{owner, 1, 1 << 30}), false, false},
		{"unexpected entry kind", encode(entry{other, 3, 0}), false, false},
		{"unexpected entry flags", encode(entry{owner, 1 | 1<<29, 0}), false, false},
		{"truncated entry", encode(entry{owner, 1, 0})[:45], false, false},
		{"bad header", make([]byte, 44), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeDarwinACL(tc.raw, func(id [16]byte) bool { return id == owner }, tc.ownerOnly); got != tc.want {
				t.Errorf("ACL allowed = %t, want %t", got, tc.want)
			}
		})
	}
}
