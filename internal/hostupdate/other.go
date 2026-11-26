// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !linux

package hostupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"pipe/internal/update"
	"pipe/internal/version"
)

func run(ctx context.Context, opts Options) error {
	var instruction string
	switch runtime.GOOS {
	case "darwin":
		instruction = "Quit Pipe and replace Pipe.app, or replace the standalone pipe executable, from the ZIP."
	case "windows":
		instruction = "Quit Pipe and replace Pipe.exe and pipe-cli.exe together from the ZIP."
	default:
		return errors.New("pipe update is unavailable on this platform")
	}
	request, err := resolveOptions(opts)
	if err != nil {
		return err
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	request.Installed = version.Version
	request.StateDir = filepath.Join(configDir, "pipe", "updates")
	release, err := update.Resolve(ctx, request)
	if err != nil {
		return err
	}
	keepArchive := false
	defer func() {
		if !keepArchive {
			cleanStage(release)
		}
	}()
	var out strings.Builder
	if opts.Check {
		fmt.Fprintf(&out, "Installed Pipe %s\n", version.Version)
	}
	switch {
	case release.Current:
		fmt.Fprintf(&out, "Pipe %s is already up to date.\n", version.Version)
	case opts.Check:
		fmt.Fprintf(&out, "Verified offer for Pipe %s\n", release.Version)
		fmt.Fprintln(&out, instruction)
	default:
		fmt.Fprintf(&out, "Verified Pipe %s\n%s\n%s\n", release.Version, release.ArchivePath, instruction)
	}
	if _, err := opts.Out.Write([]byte(out.String())); err != nil {
		return err
	}
	keepArchive = !opts.Check && !release.Current
	return nil
}
