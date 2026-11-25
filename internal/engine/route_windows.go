// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func ipv6DefaultInterfaces() (map[int]struct{}, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET6, &table); err != nil {
		if err == windows.ERROR_NOT_FOUND {
			return nil, nil
		}
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	luids := windowsIPv6DefaultLUIDs(table.Rows())
	if len(luids) == 0 {
		return nil, nil
	}

	// net.Interfaces prefers an adapter's IPv4 index. Join by LUID so that
	// the route still matches when the adapter has separate IPv4 and IPv6 indexes.
	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER | windows.GAA_FLAG_SKIP_FRIENDLY_NAME
	size := uint32(15000)
	for {
		buf := make([]byte, size)
		adapters := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, adapters, &size)
		switch {
		case err == nil && size != 0:
			return windowsIPv6RouteIndexes(luids, adapters), nil
		case err == nil || err == windows.ERROR_NO_DATA:
			return nil, nil
		case err == windows.ERROR_BUFFER_OVERFLOW && size > uint32(len(buf)):
			continue
		default:
			return nil, err
		}
	}
}

func windowsIPv6DefaultLUIDs(rows []windows.MibIpForwardRow2) map[uint64]struct{} {
	luids := make(map[uint64]struct{})
	for _, row := range rows {
		prefix := row.DestinationPrefix
		if row.Loopback == 0 && row.InterfaceLuid != 0 && prefix.PrefixLength == 0 && prefix.Prefix.Family == windows.AF_INET6 &&
			(*windows.RawSockaddrInet6)(unsafe.Pointer(&prefix.Prefix)).Addr == [16]byte{} {
			luids[row.InterfaceLuid] = struct{}{}
		}
	}
	return luids
}

func windowsIPv6RouteIndexes(luids map[uint64]struct{}, adapters *windows.IpAdapterAddresses) map[int]struct{} {
	interfaces := make(map[int]struct{})
	for adapter := adapters; adapter != nil; adapter = adapter.Next {
		if _, routed := luids[adapter.Luid]; !routed {
			continue
		}
		index := adapter.IfIndex
		if index == 0 {
			index = adapter.Ipv6IfIndex
		}
		if index != 0 {
			interfaces[int(index)] = struct{}{}
		}
	}
	return interfaces
}
