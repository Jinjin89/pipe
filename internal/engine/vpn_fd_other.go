// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !android

package engine

import (
	"errors"

	"github.com/sagernet/sing-tun"
)

func duplicateVPNTun(int32) (int32, func(), error) {
	return -1, nil, errors.New("VpnService is only available on Android")
}

func vpnInterfaceIndex(string) int { return 0 }

func adoptVPNTun(int32, *tun.Options) (tun.Tun, error) {
	return nil, errors.New("VpnService is only available on Android")
}
