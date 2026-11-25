// SPDX-License-Identifier: GPL-3.0-or-later

package helper

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the kernel-reported uid of the process on the other end.
func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Xucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if serr != nil {
		return -1, serr
	}
	if cred == nil {
		return -1, errors.New("no peer credentials")
	}
	return int(cred.Uid), nil
}
