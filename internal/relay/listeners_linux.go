// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !android

package relay

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

func localPorts() (*usedPorts, error) {
	used := new(usedPorts)
	for _, proto := range []string{"tcp", "udp"} {
		ports := &used.tcp
		if proto == "udp" {
			ports = &used.udp
		}
		for _, suffix := range []string{"", "6"} {
			path := "/proc/net/" + proto + suffix
			file, err := os.Open(path)
			if errors.Is(err, os.ErrNotExist) && suffix == "6" {
				continue
			}
			if err != nil {
				return nil, err
			}
			err = readListeners(file, ports, proto)
			file.Close()
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", path, err)
			}
		}
	}
	return used, nil
}

func readListeners(reader io.Reader, ports *portSet, proto string) error {
	scanner := bufio.NewScanner(reader)
	scanner.Scan() // Column headers.
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			return errors.New("invalid socket record")
		}
		state := fields[3]
		if proto == "tcp" && state != "0A" ||
			proto == "udp" && state != "07" && state != "01" {
			continue
		}
		ip, hexPort, _ := strings.Cut(fields[1], ":")
		addr, err := procAddress(ip)
		if err != nil {
			return err
		}
		port, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil {
			return err
		}
		if port != 0 && !addr.Unmap().IsLoopback() {
			ports[port] = true
		}
	}
	return scanner.Err()
}

func procAddress(hexAddress string) (netip.Addr, error) {
	if len(hexAddress) != 8 && len(hexAddress) != 32 {
		return netip.Addr{}, errors.New("invalid socket address")
	}
	var bytes [16]byte
	for i := 0; i < len(hexAddress); i += 8 {
		word, err := strconv.ParseUint(hexAddress[i:i+8], 16, 32)
		if err != nil {
			return netip.Addr{}, err
		}
		binary.NativeEndian.PutUint32(bytes[i/2:], uint32(word))
	}
	addr, _ := netip.AddrFromSlice(bytes[:len(hexAddress)/2])
	return addr, nil
}
