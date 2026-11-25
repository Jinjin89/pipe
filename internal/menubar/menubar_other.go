// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !darwin

package menubar

// Run has no menu bar to show on this OS.
func Run(Actions) error { return ErrUnsupported }

// Stop does nothing on this OS.
func Stop() {}

// Starting marks that Run is about to start. No-op on this OS.
func Starting() func() { return func() {} }

// OnMain runs fn on the Cocoa main thread. Unsupported on this OS.
func OnMain(func()) error { return ErrUnsupported }
