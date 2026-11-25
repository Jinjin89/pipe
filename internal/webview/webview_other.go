// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !darwin

package webview

// Window is a handle to an open webview window (unsupported on this OS).
type Window struct{}

// Open returns ErrUnsupported on non-macOS platforms.
func Open(string, Options) (*Window, error) { return nil, ErrUnsupported }

// Focus brings the window to the front.
func (*Window) Focus() {}

// Close closes the window.
func (*Window) Close() {}

// Done is closed once the window closes.
func (*Window) Done() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
