// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin

package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"pipe/internal/desktop"
	"pipe/internal/helper"
	"pipe/internal/menubar"
)

// Cocoa runs only on the main thread, so the main goroutine stays on it.
func init() { runtime.LockOSThread() }

// runAppUI runs the app with the menu bar icon (APP_DESIGN §8.6). The main
// goroutine, locked to the main thread, runs the Cocoa event loop; the app
// itself runs beside it and stops the loop when it quits.
func runAppUI(ctx context.Context, opts desktop.AppOptions) error {
	if opts.NoWindow {
		return desktop.Run(ctx, opts)
	}
	cancel := menubar.Starting()
	defer cancel()
	ready := make(chan *desktop.App, 1)
	opts.KeepRunning = true
	opts.Started = func(a *desktop.App) { ready <- a }
	done := make(chan error, 1)
	go func() {
		err := desktop.Run(ctx, opts)
		menubar.Stop()
		done <- err
	}()
	select {
	case err := <-done:
		return err // another copy answered, or startup failed
	case a := <-ready:
		if err := menubar.Run(menuActions(a)); err != nil {
			a.SetKeepRunning(false) // no icon, so closing the window may quit again (D9)
			if opts.Logs != nil {
				opts.Logs.Add("warn", "pipe", "The menu bar icon isn't available: "+err.Error())
			}
		}
		return <-done
	}
}

func menuActions(a *desktop.App) menubar.Actions {
	s := a.Server()
	return menubar.Actions{
		Changes: s.Changes(),
		State: func() menubar.State {
			st := s.Snapshot()
			set := s.Settings()
			title := menuTitle(st)
			return menubar.State{
				Status: st.State, Title: title, Tooltip: "Pipe: " + title,
				Mode: st.Mode, Tier: st.TierPreference, Rescue: st.RescueAvailable,
				TUN: set.TUN, TUNAvailable: st.Helper.State != "" && st.Helper.State != helper.StateUnsupported,
				SystemProxy: set.SystemProxy, RelayHost: st.Relay, RelayState: st.RelayState,
			}
		},
		Connect:        func() { _ = s.Connect() },
		Disconnect:     func() { _ = s.Disconnect() },
		SetMode:        func(m string) { _ = s.SetMode(m) },
		SetTier:        func(t string) { _ = s.SetTier(t) },
		SetTUN:         func(on bool) { _ = s.SetTUN(on) },
		SetSystemProxy: func(on bool) { _ = s.SetSystemProxy(on) },
		Open:           a.Show,
		Quit:           a.Quit,
	}
}

// menuTitle is the first menu line, e.g. "Connected · Fast · 42 ms · TUN".
func menuTitle(st desktop.StatusResponse) string {
	switch st.State {
	case "on":
		parts := []string{"Connected"}
		if st.Tier != "" {
			parts = append(parts, menubar.Capital(st.Tier))
		}
		if st.LatencyMs != nil {
			parts = append(parts, fmt.Sprintf("%d ms", *st.LatencyMs))
		}
		if st.Via == "tun" {
			parts = append(parts, "TUN")
		}
		return strings.Join(parts, " · ")
	case "connecting":
		return "Connecting…"
	case "error":
		return "Couldn't connect"
	}
	return "Not connected"
}
