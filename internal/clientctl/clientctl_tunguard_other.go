// SPDX-License-Identifier: GPL-3.0-or-later
//go:build (!linux || android) && (!darwin || ios)

package clientctl

import "github.com/sagernet/sing-tun"

func prepareTUNGuardRoutes(*tun.Options) error { return nil }
