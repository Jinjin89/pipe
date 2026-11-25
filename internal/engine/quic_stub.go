// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !with_quic

package engine

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
)

func registerQUIC(*inbound.Registry, *outbound.Registry, map[string]*reloadableInbound, Options, *relayState) {
}
