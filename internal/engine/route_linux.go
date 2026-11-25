// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !android

package engine

import (
	"encoding/binary"
	"syscall"

	"github.com/sagernet/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	linuxRouteNexthopID        = 30 // RTA_NH_ID in linux/rtnetlink.h
	linuxNexthopHeaderSize     = 8
	linuxNexthopGroupEntrySize = 8
)

func ipv6DefaultInterfaces() (map[int]struct{}, error) {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETROUTE, unix.AF_INET6)
	if err != nil {
		return nil, err
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}
	return linuxIPv6DefaultInterfaces(messages, readLinuxNexthops)
}

func linuxIPv6DefaultInterfaces(messages []syscall.NetlinkMessage, readNexthops func() ([][]byte, error)) (map[int]struct{}, error) {
	interfaces := make(map[int]struct{})
	var nextHopIDs []uint32
	for _, message := range messages {
		if message.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
			return nil, unix.EINTR
		}
		data := message.Data
		if message.Header.Type == unix.NLMSG_DONE && len(data) >= 4 {
			if status := int32(binary.NativeEndian.Uint32(data)); status < 0 {
				return nil, syscall.Errno(-status)
			}
		}
		if message.Header.Type != unix.RTM_NEWROUTE {
			continue
		}
		if len(data) < unix.SizeofRtMsg || len(data)%unix.RTA_ALIGNTO != 0 {
			return nil, unix.EINVAL
		}
		// rtmsg holds the family, destination prefix length, type, and flags.
		if data[0] != unix.AF_INET6 || data[1] != 0 || data[7] != unix.RTN_UNICAST ||
			binary.NativeEndian.Uint32(data[8:12])&(unix.RTM_F_CLONED|unix.RTNH_F_DEAD|unix.RTNH_F_LINKDOWN) != 0 {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return nil, err
		}
		// RTA_TABLE carries the full table ID when present.
		table := uint32(data[4]) // rtm_table
		for _, attr := range attrs {
			if attr.Attr.Type != unix.RTA_TABLE {
				continue
			}
			if len(attr.Value) != 4 {
				return nil, unix.EINVAL
			}
			table = binary.NativeEndian.Uint32(attr.Value)
			break
		}
		if table != unix.RT_TABLE_MAIN {
			continue
		}
		var nextHopID uint32
		var hasInlineNexthop bool
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case unix.RTA_OIF:
				hasInlineNexthop = true
				if len(attr.Value) != 4 {
					return nil, unix.EINVAL
				}
				if index := int(int32(binary.NativeEndian.Uint32(attr.Value))); index > 0 {
					interfaces[index] = struct{}{}
				}
			case unix.RTA_MULTIPATH:
				hasInlineNexthop = true
				if err := addLinuxMultipathInterfaces(interfaces, attr.Value); err != nil {
					return nil, err
				}
			case linuxRouteNexthopID:
				if len(attr.Value) != 4 {
					return nil, unix.EINVAL
				}
				nextHopID = binary.NativeEndian.Uint32(attr.Value)
			}
		}
		if nextHopID != 0 && !hasInlineNexthop {
			nextHopIDs = append(nextHopIDs, nextHopID)
		}
	}
	if len(nextHopIDs) > 0 {
		messages, err := readNexthops()
		if err != nil {
			return nil, err
		}
		if err := addLinuxNexthopInterfaces(interfaces, nextHopIDs, messages); err != nil {
			return nil, err
		}
	}
	return interfaces, nil
}

func addLinuxMultipathInterfaces(interfaces map[int]struct{}, hops []byte) error {
	for len(hops) > 0 {
		if len(hops) < unix.SizeofRtNexthop {
			return unix.EINVAL
		}
		length := int(binary.NativeEndian.Uint16(hops))
		aligned := (length + unix.RTNH_ALIGNTO - 1) &^ (unix.RTNH_ALIGNTO - 1)
		if length < unix.SizeofRtNexthop || aligned > len(hops) {
			return unix.EINVAL
		}
		index := int(int32(binary.NativeEndian.Uint32(hops[4:8])))
		if index > 0 && hops[2]&(unix.RTNH_F_DEAD|unix.RTNH_F_LINKDOWN) == 0 {
			interfaces[index] = struct{}{}
		}
		hops = hops[aligned:]
	}
	return nil
}

func readLinuxNexthops() ([][]byte, error) {
	request := nl.NewNetlinkRequest(unix.RTM_GETNEXTHOP, unix.NLM_F_DUMP)
	request.AddRawData(make([]byte, linuxNexthopHeaderSize))
	return request.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWNEXTHOP)
}

func addLinuxNexthopInterfaces(interfaces map[int]struct{}, routeIDs []uint32, messages [][]byte) error {
	indexes := make(map[uint32]int)
	groups := make(map[uint32][]byte)
	for _, data := range messages {
		if len(data) < linuxNexthopHeaderSize || len(data)%unix.RTA_ALIGNTO != 0 {
			return unix.EINVAL
		}
		if binary.NativeEndian.Uint32(data[4:8])&(unix.RTNH_F_DEAD|unix.RTNH_F_LINKDOWN) != 0 {
			continue
		}
		attrs, err := nl.ParseRouteAttr(data[linuxNexthopHeaderSize:])
		if err != nil {
			return err
		}
		var id uint32
		var index int
		var group []byte
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case unix.NHA_ID, unix.NHA_OIF:
				if len(attr.Value) != 4 {
					return unix.EINVAL
				}
				value := binary.NativeEndian.Uint32(attr.Value)
				if attr.Attr.Type == unix.NHA_ID {
					id = value
				} else {
					index = int(int32(value))
				}
			case unix.NHA_GROUP:
				if len(attr.Value)%linuxNexthopGroupEntrySize != 0 {
					return unix.EINVAL
				}
				group = attr.Value
			}
		}
		if index > 0 {
			indexes[id] = index
		}
		if len(group) > 0 {
			groups[id] = group
		}
	}
	for _, id := range routeIDs {
		if index := indexes[id]; index > 0 {
			interfaces[index] = struct{}{}
		}
		for group := groups[id]; len(group) > 0; group = group[linuxNexthopGroupEntrySize:] {
			if index := indexes[binary.NativeEndian.Uint32(group)]; index > 0 {
				interfaces[index] = struct{}{}
			}
		}
	}
	return nil
}
