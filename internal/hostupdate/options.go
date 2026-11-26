// SPDX-License-Identifier: GPL-3.0-or-later

// Package hostupdate implements the synchronous `pipe update` command.
package hostupdate

import (
	"context"
	"errors"
	"io"
	"runtime"

	"pipe/internal/update"
)

type Options struct {
	Check bool
	From  string
	Proxy string
	Out   io.Writer
}

// Run checks for or installs a signed Pipe release in the current scope.
func Run(ctx context.Context, opts Options) error {
	if opts.From != "" && opts.Proxy != "" {
		return errors.New("--from and --proxy cannot be used together")
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	return run(ctx, opts)
}

func resolveOptions(opts Options) (update.ResolveOptions, error) {
	request := update.ResolveOptions{
		Target: update.Target{OS: runtime.GOOS, ABI: runtime.GOARCH},
		From:   opts.From, CheckOnly: opts.Check,
	}
	var err error
	if opts.Proxy != "" {
		request.Route, err = update.ProxyRoute(opts.Proxy)
	} else if opts.From == "" {
		request.Route, err = update.EnvProxyRoute()
	}
	return request, err
}

func cleanStage(release update.StagedRelease) {
	if release.Cleanup != nil {
		release.Cleanup()
	}
}
