// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !darwin

package main

import (
	"context"

	"pipe/internal/desktop"
)

// runAppUI runs the app. Only macOS has a menu bar icon (ui_darwin.go).
func runAppUI(ctx context.Context, opts desktop.AppOptions) error {
	return desktop.Run(ctx, opts)
}
