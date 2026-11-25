// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

func TestRescueAuthenticatorRequiresValidVMessEarlyData(t *testing.T) {
	const known = "ab2cb5b2-8200-4132-b010-9fd96948afb0"
	const unknown = "f2873b20-b31b-4108-9bf0-91e2f3d12e55"
	var authenticator RescueAuthenticator
	if err := authenticator.SetUsers([]string{known}); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	for _, invalid := range []string{"", "invalid*", vmessEarlyData(t, unknown)} {
		if authenticator.Authenticate(ctx, invalid) {
			t.Fatal("accepted unauthenticated WebSocket early data")
		}
	}
	data := vmessEarlyData(t, known)
	if !authenticator.Authenticate(ctx, data) {
		t.Fatal("rejected valid early data from the pinned VMess client")
	}
	if authenticator.Authenticate(ctx, data) {
		t.Fatal("accepted replayed early data")
	}
	if err := authenticator.SetUsers(nil); err != nil {
		t.Fatal(err)
	}
	if authenticator.Authenticate(ctx, vmessEarlyData(t, known)) {
		t.Fatal("accepted early data from a revoked device")
	}
}

func vmessEarlyData(t *testing.T, uuid string) string {
	t.Helper()
	client, err := vmess.NewClient(uuid, "chacha20-poly1305", 0)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	conn := client.DialEarlyConn(bufio.NewWriteOnlyConn(&wire), M.ParseSocksaddrHostPort("example.test", 80))
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(wire.Bytes())
}
