// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"errors"

	"github.com/sagernet/sing-tun"
	"golang.org/x/sys/unix"
)

func duplicateVPNTun(fd int32) (int32, func(), error) {
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	release := func() { _ = unix.Close(int(fd)) }
	return int32(dup), release, err
}

func vpnInterfaceIndex(name string) int {
	request, err := unix.NewIfreq(name)
	if err != nil {
		return 0
	}
	// SIOCGIFINDEX queries this name on an unbound socket.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0
	}
	defer unix.Close(fd)
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFINDEX, request); err != nil {
		return 0
	}
	return int(request.Uint32())
}

func adoptVPNTun(fd int32, options *tun.Options) (tun.Tun, error) {
	if fd < 0 {
		return nil, errors.New("Android did not establish a VPN interface")
	}
	// A descriptor of zero has special meaning in sing-tun.
	if fd == 0 {
		dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
		unix.Close(int(fd))
		if err != nil {
			return nil, err
		}
		fd = int32(dup)
	}
	if err := unix.SetNonblock(int(fd), true); err != nil {
		unix.Close(int(fd))
		return nil, err
	}
	tunOptions := *options
	tunOptions.FileDescriptor = int(fd)
	tunOptions.EXP_ExternalConfiguration = true
	tunOptions.AutoRoute = false
	device, err := tun.New(tunOptions)
	if err != nil {
		unix.Close(int(fd))
		return nil, err
	}
	options.Name, err = device.Name()
	if err != nil {
		device.Close()
		return nil, err
	}
	return device, nil
}
