// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux && !android

package desktop

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

func TestPortalOpenFilePassesReadOnlyBootstrap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Pipe-open-test.html")
	const body = "fixture bootstrap"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	const token = "pipe_fixture"
	const handle dbus.ObjectPath = portalPath + "/request/1_42/" + token
	got, err := requestBootstrapOpen(t.Context(), path, token, func(_ context.Context, method string, flags dbus.Flags, args ...any) *dbus.Call {
		if method != "org.freedesktop.portal.OpenURI.OpenFile" || flags != 0 || len(args) != 3 || args[0] != "" {
			t.Fatalf("unexpected portal method %q or argument shape", method)
		}
		fd, ok := args[1].(dbus.UnixFD)
		if !ok {
			t.Fatal("portal call did not pass a Unix file descriptor")
		}
		if options, ok := args[2].(map[string]dbus.Variant); !ok || options["handle_token"].Value() != token {
			t.Fatal("portal options did not include the request token")
		}
		access, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil || access&unix.O_ACCMODE != unix.O_RDONLY {
			t.Fatalf("portal descriptor must be read-only: %v", err)
		}
		buf := make([]byte, len(body))
		if n, err := unix.Pread(int(fd), buf, 0); err != nil || string(buf[:n]) != body {
			t.Fatalf("portal descriptor did not refer to the bootstrap: %v", err)
		}
		return &dbus.Call{Body: []any{handle}}
	})
	if err != nil || got != handle {
		t.Fatalf("OpenFile returned %q, error %v", got, err)
	}
}

func TestPortalResponseControlsBrowserFallback(t *testing.T) {
	results := map[string]dbus.Variant{}
	for _, tc := range []struct {
		name     string
		body     []any
		closed   bool
		fallback bool
	}{
		{name: "success", body: []any{uint32(0), results}},
		{name: "user cancelled", body: []any{uint32(1), results}},
		{name: "failed", body: []any{uint32(2), results}, fallback: true},
		{name: "malformed", body: []any{uint32(0)}, fallback: true},
		{name: "connection closed", closed: true, fallback: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const handle dbus.ObjectPath = portalPath + "/request/1_42/pipe_fixture"
			signals := make(chan *dbus.Signal, 2)
			done := make(chan struct{})
			var connectionClosed, fellBack bool
			go func() {
				observePortalResponse(t.Context(), signals, handle, func() error {
					connectionClosed = true
					return nil
				}, func() {
					if !connectionClosed {
						t.Error("fallback ran before closing the portal connection")
					}
					fellBack = true
				})
				close(done)
			}()
			signals <- &dbus.Signal{Path: handle + "_other", Name: portalResponse, Body: []any{uint32(2), results}}
			if tc.closed {
				close(signals)
			} else {
				signals <- &dbus.Signal{Path: handle, Name: portalResponse, Body: tc.body}
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("portal response observer did not finish")
			}
			if !connectionClosed || fellBack != tc.fallback {
				t.Fatalf("connection closed=%t, fallback=%t", connectionClosed, fellBack)
			}
		})
	}
}

func TestPortalResponseExpiryClosesConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), nonceTTL)
		defer cancel()
		closed := false
		observePortalResponse(ctx, make(chan *dbus.Signal), portalPath+"/request/1_42/pipe_fixture", func() error {
			closed = true
			return nil
		}, func() { t.Error("expired request launched a fallback") })
		if !closed || ctx.Err() != context.DeadlineExceeded {
			t.Fatal("portal connection did not close on expiry")
		}
	})
}
