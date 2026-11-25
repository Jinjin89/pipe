// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !android

package relay

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestRelayLocalPortEnumeration(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		var proc strings.Builder
		proc.WriteString("sl local_address rem_address st\n")
		state := "0A"
		if protocol == "udp" {
			state = "07"
		}
		for i, record := range []struct {
			address, state string
		}{
			{"0.0.0.0", state}, {"::", state}, {"10.0.0.1", state},
			{"127.0.1.2", state}, {"::1", state}, {"::ffff:127.0.0.1", state},
			{"1.1.1.1", "06"}, {"1.1.1.1", "01"},
		} {
			addr := netip.MustParseAddr(record.address).AsSlice()
			fmt.Fprintf(&proc, "%d: ", i)
			for j := 0; j < len(addr); j += 4 {
				fmt.Fprintf(&proc, "%08X", binary.NativeEndian.Uint32(addr[j:]))
			}
			fmt.Fprintf(&proc, ":%04X 0:0 %s\n", 8443+i, record.state)
		}
		var used portSet
		if err := readListeners(strings.NewReader(proc.String()), &used, protocol); err != nil {
			t.Fatal(err)
		}
		for i, want := range []bool{true, true, true, false, false, false, false, protocol == "udp"} {
			if got := used[8443+i]; got != want {
				t.Errorf("%s port %d used = %v, want %v", protocol, 8443+i, got, want)
			}
		}
	}
}
