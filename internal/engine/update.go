// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"net"

	M "github.com/sagernet/sing/common/metadata"

	"pipe/internal/update"
)

// DialUpdate bypasses routing rules and local DNS. The selected tier sends
// the release hostname to the authenticated Pipe server.
func (i *Instance) DialUpdate(ctx context.Context, tier, network, address string) (net.Conn, error) {
	if network != "tcp" || !update.AllowedAddress(address) {
		return nil, update.ErrTunnelUnavailable
	}
	switch tier {
	case "fast", "stealth", "rescue":
	default:
		return nil, update.ErrTunnelUnavailable
	}
	out, ok := i.box.Outbound().Outbound(tier)
	if !ok {
		return nil, update.ErrTunnelUnavailable
	}
	return out.DialContext(i.ProbeContext(ctx), network, M.ParseSocksaddr(address))
}
