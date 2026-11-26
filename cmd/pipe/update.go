// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"os"

	"pipe/internal/hostupdate"
)

func runUpdate(ctx context.Context, args []string) error {
	opts := hostupdate.Options{Out: os.Stdout}
	fs := flag.NewFlagSet("pipe update", flag.ContinueOnError)
	fs.BoolVar(&opts.Check, "check", false, "show the verified release and planned changes")
	fs.StringVar(&opts.From, "from", "", "use a local release directory or archive")
	fs.StringVar(&opts.Proxy, "proxy", "", "use this proxy URL for an online update")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("pipe update takes only flags")
	}
	return hostupdate.Run(ctx, opts)
}
