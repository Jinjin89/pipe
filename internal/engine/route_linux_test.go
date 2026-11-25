// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !android

package engine

import (
	"encoding/binary"
	"maps"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxIPv6DefaultInterfaces(t *testing.T) {
	const mainTable = unix.RT_TABLE_MAIN
	attr := func(typ uint16, value []byte) []byte {
		data := binary.NativeEndian.AppendUint16(nil, uint16(unix.SizeofRtAttr+len(value)))
		data = binary.NativeEndian.AppendUint16(data, typ)
		return append(data, value...)
	}
	uint32Attr := func(typ uint16, value uint32) []byte {
		return attr(typ, binary.NativeEndian.AppendUint32(nil, value))
	}
	oif := func(index uint32) []byte {
		return uint32Attr(unix.RTA_OIF, index)
	}
	hop := func(index uint32, flags byte) []byte {
		data := binary.NativeEndian.AppendUint16(nil, unix.SizeofRtNexthop)
		data = append(data, flags, 0)
		return binary.NativeEndian.AppendUint32(data, index)
	}
	message := func(family, bits, table, typ byte, flags uint32, attrs []byte) syscall.NetlinkMessage {
		data := make([]byte, unix.SizeofRtMsg)
		data[0], data[1], data[4], data[7] = family, bits, table, typ
		binary.NativeEndian.PutUint32(data[8:12], flags)
		return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWROUTE}, Data: append(data, attrs...)}
	}
	hops := append(hop(3, 0), hop(4, unix.RTNH_F_LINKDOWN)...)
	messages := []syscall.NetlinkMessage{
		message(unix.AF_INET6, 0, mainTable, unix.RTN_UNICAST, 0, oif(2)),
		message(unix.AF_INET6, 0, mainTable, unix.RTN_UNICAST, 0, attr(unix.RTA_MULTIPATH, hops)),
		message(unix.AF_INET6, 1, mainTable, unix.RTN_UNICAST, 0, oif(5)),
		message(unix.AF_INET6, 0, mainTable, unix.RTN_UNREACHABLE, 0, oif(6)),
		message(unix.AF_INET, 0, mainTable, unix.RTN_UNICAST, 0, oif(7)),
		message(unix.AF_INET6, 0, mainTable, unix.RTN_UNICAST, unix.RTM_F_CLONED, oif(8)),
		message(unix.AF_INET6, 0, mainTable, unix.RTN_UNICAST, unix.RTNH_F_DEAD, oif(9)),
	}
	got, err := linuxIPv6DefaultInterfaces(messages, nil)
	want := map[int]struct{}{2: {}, 3: {}}
	if err != nil || !maps.Equal(got, want) {
		t.Fatalf("linuxIPv6DefaultInterfaces() = %v, %v, want %v", got, err, want)
	}
	t.Run("routing tables", func(t *testing.T) {
		messages := []syscall.NetlinkMessage{
			message(unix.AF_INET6, 0, mainTable, unix.RTN_UNICAST, 0, oif(2)),
			message(unix.AF_INET6, 0, 52, unix.RTN_UNICAST, 0, oif(3)),
			message(unix.AF_INET6, 0, unix.RT_TABLE_UNSPEC, unix.RTN_UNICAST, 0, append(oif(4), uint32Attr(unix.RTA_TABLE, mainTable)...)),
			message(unix.AF_INET6, 0, mainTable, unix.RTN_UNICAST, 0, append(oif(5), uint32Attr(unix.RTA_TABLE, 52)...)),
			message(unix.AF_INET6, 0, unix.RT_TABLE_UNSPEC, unix.RTN_UNICAST, 0, append(oif(6), uint32Attr(unix.RTA_TABLE, mainTable+256)...)),
		}
		got, err := linuxIPv6DefaultInterfaces(messages, nil)
		want := map[int]struct{}{2: {}, 4: {}}
		if err != nil || !maps.Equal(got, want) {
			t.Fatalf("linuxIPv6DefaultInterfaces() = %v, %v, want %v", got, err, want)
		}
	})

	// A route may carry only a nexthop ID when compatibility mode is off.
	nexthop := func(id, flags uint32, attrs []byte) []byte {
		data := make([]byte, linuxNexthopHeaderSize)
		binary.NativeEndian.PutUint32(data[4:8], flags)
		data = append(data, uint32Attr(unix.NHA_ID, id)...)
		return append(data, attrs...)
	}
	group := make([]byte, 2*linuxNexthopGroupEntrySize)
	binary.NativeEndian.PutUint32(group, 10)
	binary.NativeEndian.PutUint32(group[linuxNexthopGroupEntrySize:], 11)
	objects := []syscall.NetlinkMessage{
		message(unix.AF_INET6, 0, mainTable, unix.RTN_UNICAST, 0, uint32Attr(linuxRouteNexthopID, 12)),
		message(unix.AF_INET6, 0, mainTable, unix.RTN_UNICAST, 0, uint32Attr(linuxRouteNexthopID, 13)),
	}
	readNexthops := func() ([][]byte, error) {
		return [][]byte{
			nexthop(10, 0, uint32Attr(unix.NHA_OIF, 4)),
			nexthop(11, unix.RTNH_F_LINKDOWN, uint32Attr(unix.NHA_OIF, 5)),
			nexthop(12, 0, attr(unix.NHA_GROUP, group)),
			nexthop(13, 0, uint32Attr(unix.NHA_OIF, 6)),
		}, nil
	}
	got, err = linuxIPv6DefaultInterfaces(objects, readNexthops)
	want = map[int]struct{}{4: {}, 6: {}}
	if err != nil || !maps.Equal(got, want) {
		t.Fatalf("linuxIPv6DefaultInterfaces() with nexthop objects = %v, %v, want %v", got, err, want)
	}
}

func TestLinuxIPv6DefaultInterfacesRejectsPartialDump(t *testing.T) {
	messages := []syscall.NetlinkMessage{{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE, Flags: unix.NLM_F_DUMP_INTR}}}
	if _, err := linuxIPv6DefaultInterfaces(messages, nil); err != unix.EINTR {
		t.Fatalf("linuxIPv6DefaultInterfaces() error = %v, want %v", err, unix.EINTR)
	}
}
