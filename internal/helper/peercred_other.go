// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !linux && !darwin

package helper

import (
	"errors"
	"net"
)

// peerUID refuses everything: there is no helper on this OS.
func peerUID(*net.UnixConn) (int, error) {
	return -1, errors.New("peer credentials are not available on this OS")
}
