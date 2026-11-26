// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux && !android

package desktop

import (
	"context"
	"crypto/rand"
	"os"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	desktopPortal  = "org.freedesktop.portal.Desktop"
	portalPath     = "/org/freedesktop/portal/desktop"
	portalRequest  = "org.freedesktop.portal.Request"
	portalResponse = portalRequest + ".Response"
)

func openBootstrapPortal(path string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dbus.SessionBusPrivateNoAutoStartup()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err = conn.Auth(nil); err != nil {
		return err
	}
	if err = conn.Hello(); err != nil {
		return err
	}
	responses := make(chan *dbus.Signal, 1)
	conn.Signal(responses)
	if err = conn.AddMatchSignalContext(ctx,
		dbus.WithMatchSender(desktopPortal),
		dbus.WithMatchInterface(portalRequest),
		dbus.WithMatchMember("Response"),
		dbus.WithMatchPathNamespace(portalPath+"/request"),
	); err != nil {
		return err
	}
	portal := conn.Object(desktopPortal, portalPath)
	handle, err := requestBootstrapOpen(ctx, path, "pipe_"+rand.Text(), portal.CallWithContext)
	if err != nil {
		return err
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), nonceTTL)
		defer cancel()
		observePortalResponse(ctx, responses, handle, conn.Close, func() {
			if fileExists(path) {
				_ = openLinuxBrowser(path)
			}
		})
	}()
	return nil
}

func requestBootstrapOpen(ctx context.Context, path, token string, call func(context.Context, string, dbus.Flags, ...any) *dbus.Call) (dbus.ObjectPath, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	options := map[string]dbus.Variant{"handle_token": dbus.MakeVariant(token)}
	var handle dbus.ObjectPath
	err = call(ctx, "org.freedesktop.portal.OpenURI.OpenFile", 0, "", dbus.UnixFD(f.Fd()), options).Store(&handle)
	return handle, err
}

func observePortalResponse(ctx context.Context, signals <-chan *dbus.Signal, handle dbus.ObjectPath, closeConn func() error, fallback func()) {
	failed := false
	defer func() {
		_ = closeConn()
		if failed && ctx.Err() == nil {
			fallback()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case signal := <-signals:
			if signal == nil {
				failed = true
				return
			}
			if signal.Path != handle || signal.Name != portalResponse {
				continue
			}
			var code uint32
			var results map[string]dbus.Variant
			failed = dbus.Store(signal.Body, &code, &results) != nil || code >= 2
			return
		}
	}
}
