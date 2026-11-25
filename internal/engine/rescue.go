// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"sync/atomic"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// RescueAuthenticator checks the client-generated VMess-AEAD early data before
// an HTTP WebSocket upgrade. The inbound still authenticates the actual stream.
type RescueAuthenticator struct {
	service atomic.Pointer[vmess.Service[int]]
}

func (a *RescueAuthenticator) SetUsers(uuids []string) error {
	service := vmess.NewService[int](rescueAuthHandler{})
	users := make([]int, len(uuids))
	for i := range users {
		users[i] = i
	}
	if err := service.UpdateUsers(users, uuids, make([]int, len(users))); err != nil {
		return err
	}
	a.service.Store(service)
	return nil
}

func (a *RescueAuthenticator) Authenticate(ctx context.Context, encoded string) bool {
	service := a.service.Load()
	encoding := base64.RawURLEncoding.Strict()
	if service == nil || encoded == "" || len(encoded) > encoding.EncodedLen(WebSocketEarlyDataLimit) {
		return false
	}
	data, err := encoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	var accepted atomic.Bool
	ctx = context.WithValue(ctx, rescueAuthKey{}, &accepted)
	conn := bufio.NewReadOnlyConn(bytes.NewReader(data))
	err = service.NewConnection(ctx, conn, M.Socksaddr{}, nil)
	return err == nil && accepted.Load()
}

type rescueAuthKey struct{}
type rescueAuthHandler struct{}

func (rescueAuthHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	ctx.Value(rescueAuthKey{}).(*atomic.Bool).Store(true)
	_ = conn.Close()
}

func (rescueAuthHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	ctx.Value(rescueAuthKey{}).(*atomic.Bool).Store(true)
	_ = conn.Close()
}
