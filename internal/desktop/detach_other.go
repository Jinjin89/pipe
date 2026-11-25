// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !unix

package desktop

import "errors"

// startDetached is only needed on macOS (see detach.go).
func startDetached(exe string, args []string) error {
	return errors.New("detached start is not supported on this OS")
}
