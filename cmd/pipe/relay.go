// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"pipe/internal/relay"
)

func runRelay(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "Usage: pipe relay <add | remove | status | apply> [options]")
		return nil
	}
	action := args[0]
	fs := flag.NewFlagSet("pipe relay "+action, flag.ContinueOnError)
	path := fs.String("state", relay.DefaultStatePath, "route state file")
	var to, tcp, udp, host string
	switch action {
	case "add":
		fs.StringVar(&to, "to", "", "one public IPv4 and/or one public IPv6 literal")
		fs.StringVar(&tcp, "tcp", "", "server Stealth TCP port")
		fs.StringVar(&udp, "udp", "", "server Fast UDP port with an optional ,a-b hop range")
		fs.StringVar(&host, "host", "", "relay IP address or DNS name for the code")
	case "remove":
		fs.Func("to", "one public IPv4 and/or one public IPv6 literal for the route to remove", func(target string) error {
			if target == "" {
				return errors.New("--to requires one public IPv4 and/or one public IPv6 literal")
			}
			to = target
			return nil
		})
	case "status", "apply":
	default:
		return errors.New("unknown pipe relay command")
	}
	if err := parseFlags(fs, args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("relay %s takes only flags", action)
	}
	switch action {
	case "status":
		status, err := relay.Status(ctx, *path)
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(os.Stdout, status)
		return err
	case "remove":
		return relay.Remove(ctx, *path, to)
	case "apply":
		return relay.Apply(ctx, *path)
	}
	request, err := relay.ParseRequest(to, tcp, udp)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	code, open, hint, err := relay.Add(ctx, *path, request, host, executable)
	if err != nil {
		return err
	}
	if hint != "" {
		fmt.Fprintln(os.Stderr, hint)
	}
	_, err = fmt.Fprintf(os.Stdout, "%s\nOpen on this VPS: %s\n", code, open)
	return err
}
