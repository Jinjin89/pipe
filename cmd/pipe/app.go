// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"pipe/internal/clientctl"
	"pipe/internal/config"
	"pipe/internal/desktop"
	"pipe/internal/helper"
	"pipe/internal/logring"
	"pipe/internal/sysproxy"
	"pipe/internal/version"
)

// defaultCommand is set at link time (-X main.defaultCommand=app) for
// Pipe.exe and the macOS app bundle, so a double click starts the app.
var defaultCommand string

func runApp(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pipe app", flag.ContinueOnError)
	var background, noWindow, installEntry bool
	var dir string
	fs.BoolVar(&background, "background", false, "start without a window")
	fs.BoolVar(&noWindow, "no-window", false, "print the private bootstrap file path instead of opening a window")
	fs.StringVar(&dir, "dir", "", "config directory (default: the user config dir, pipe)")
	fs.BoolVar(&installEntry, "install-desktop-entry", false, "add Pipe to the application menu (Linux)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("app takes no arguments")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if installEntry {
		return installDesktopEntry(exe)
	}
	// Opened from Pipe.app: hand off to a detached copy so macOS can open
	// Pipe again later (see internal/desktop/detach.go).
	if detached, err := desktop.DetachIfBundled(exe, args, background, noWindow); err != nil || detached {
		return err
	}
	profiles := ""
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(base, "pipe")
		profiles = os.Getenv("PIPE_PROFILE_DIR")
	}
	if profiles == "" {
		profiles = filepath.Join(dir, "profiles")
	}
	logs := logring.New(1000)
	var tunHelper desktop.Helper
	if _, ok := helper.PathsFor(runtime.GOOS); ok {
		tunHelper = helper.NewRemote(helper.RemoteOptions{Logs: logs, Version: version.Version, Exe: exe})
	}
	return runAppUI(ctx, desktop.AppOptions{
		Config: desktop.Config{
			Dir: dir, ProfilesDir: profiles,
			Controller: clientctl.New(logs), Helper: tunHelper, Logs: logs,
			ParseRule: config.ParseRule,
			Proxy:     sysproxy.New(sysproxy.Default(), filepath.Join(dir, "proxy.armed")),
			Autostart: desktop.DefaultAutostart(runtime.GOOS),
			Version:   version.Version, Exe: exe,
		},
		Background: background, NoWindow: noWindow, Stdout: os.Stdout,
	})
}

func installDesktopEntry(exe string) error {
	if runtime.GOOS != "linux" {
		return errors.New("--install-desktop-entry is only for Linux")
	}
	data, err := desktop.DataHome()
	if err != nil {
		return err
	}
	path, err := desktop.InstallDesktopEntry(data, exe)
	if err != nil {
		return err
	}
	fmt.Println("Installed", path)
	return nil
}
