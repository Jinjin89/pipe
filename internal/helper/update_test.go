// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux || darwin

package helper

import (
	"net"
	"sync/atomic"
	"testing"

	"pipe/internal/update"
)

func TestUpdateStreamRequiresOwnerAndApprovedDestination(t *testing.T) {
	var peer atomic.Int64
	peer.Store(4242)
	r := startServer(t, func(o *ServeOptions) {
		o.OwnerUID = 4242
		o.PeerUID = func(*net.UnixConn) (int, error) { return int(peer.Load()), nil }
	})
	for _, address := range []string{"example.com:443", "api.github.com:80", "127.0.0.1:443"} {
		resp := call(t, r.sock, "updateStream", updateStreamParams{Address: address})
		if resp.Error != "That update address isn't allowed." || len(resp.Result) != 0 {
			t.Fatalf("disallowed destination %q: %+v", address, resp)
		}
	}
	address := updateStreamParams{Address: "api.github.com:443"}
	resp := call(t, r.sock, "updateStream", address)
	if resp.Error != update.ErrTunnelUnavailable.Error() {
		t.Fatalf("stream proceeded without an authenticated tier: %+v", resp)
	}
	peer.Store(4243)
	resp = call(t, r.sock, "updateStream", address)
	if resp.Error != msgOtherUser {
		t.Fatalf("unrelated UID reached the stream dispatcher: %+v", resp)
	}
}
