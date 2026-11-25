// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"errors"
	"net"
	"runtime"
	"syscall"
)

func bindWithIPv4Fallback[T any](host string, bind func(string) (T, error)) (T, string, error) {
	listener, err := bind(host)
	if host == "::" && ipv6Unavailable(err) {
		host = "0.0.0.0"
		listener, err = bind(host)
	}
	return listener, host, err
}

func listenTCP(host string, port uint16, listen func(string, string) (net.Listener, error)) (net.Listener, error) {
	listener, _, err := bindWithIPv4Fallback(host, func(address string) (net.Listener, error) {
		network := "tcp"
		if address == "0.0.0.0" {
			network = "tcp4"
		}
		return listen(network, addrPort(address, port))
	})
	return listener, err
}

func ipv6Unavailable(err error) bool {
	const (
		winsockFamilyUnsupported  = syscall.Errno(10047)
		winsockAddressUnavailable = syscall.Errno(10049)
	)
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) ||
		runtime.GOOS == "windows" && (errors.Is(err, winsockFamilyUnsupported) || errors.Is(err, winsockAddressUnavailable))
}

func portInUse(err error) bool {
	const winsockAddressInUse = syscall.Errno(10048)
	return errors.Is(err, syscall.EADDRINUSE) || runtime.GOOS == "windows" && errors.Is(err, winsockAddressInUse)
}
