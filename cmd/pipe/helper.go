// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"pipe/internal/clientctl"
	"pipe/internal/helper"
	"pipe/internal/logring"
	"pipe/internal/version"
)

const helperUsage = "Usage: pipe helper <install --uid N | remove | status | run>"

// runHelper is `pipe helper <install | remove | status | run>` (APP_DESIGN §8.3).
func runHelper(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New(helperUsage)
	}
	switch args[0] {
	case "run", "install", "remove":
		if os.Geteuid() != 0 {
			return errors.New("Run this as root.")
		}
	}
	paths, ok := helper.PathsFor(runtime.GOOS)
	if !ok {
		return errors.New("Pipe Helper isn't available on this system.")
	}
	switch args[0] {
	case "run":
		return helperRun(ctx, paths)
	case "install":
		fs := flag.NewFlagSet("helper install", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		uid := fs.Int("uid", 0, "")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *uid <= 0 {
			return errors.New("Usage: pipe helper install --uid N")
		}
		if err := helper.InstallService(*uid); err != nil {
			return err
		}
		fmt.Println("Pipe Helper installed.")
		return nil
	case "remove":
		if err := helper.RemoveService(); err != nil {
			return err
		}
		fmt.Println("Pipe Helper removed.")
		return nil
	case "status":
		info := helper.NewRemote(helper.RemoteOptions{Version: version.Version}).Info()
		switch info.State {
		case helper.StateOK:
			fmt.Printf("Pipe Helper is installed and running (version %s).\n", info.Version)
		case helper.StateOutdated:
			fmt.Printf("Pipe Helper is running version %s and needs an update to %s.\n", info.Version, version.Version)
		default:
			fmt.Println(info.Note)
		}
		return nil
	}
	return errors.New(helperUsage)
}

func helperRun(ctx context.Context, paths helper.Paths) error {
	uid, err := helper.ReadOwner(paths.Owner)
	if err != nil {
		return fmt.Errorf("Pipe Helper isn't set up (%v).", err)
	}
	ring := logring.New(logring.DefaultCapacity)
	session := clientctl.New(ring)
	defer session.Stop()
	fmt.Fprintf(os.Stderr, "pipe helper %s: serving %s\n", version.Version, paths.Socket)
	err = helper.Serve(ctx, helper.ServeOptions{
		Socket:   paths.Socket,
		OwnerUID: uid,
		Version:  version.Version,
		Logs:     ring,
		Session:  session,
	})
	if err != nil {
		return fmt.Errorf("Pipe Helper stopped: %v", err)
	}
	return nil
}
