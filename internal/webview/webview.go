// SPDX-License-Identifier: GPL-3.0-or-later

// Package webview opens a locked-down system webview window for the desktop UI.
// On macOS it uses WKWebView through purego without cgo; other OSes return
// ErrUnsupported so the caller falls back to a browser window.
package webview

import "errors"

// ErrUnsupported is returned on platforms without a native webview backend.
var ErrUnsupported = errors.New("native webview is not supported on this OS")

// Options configures a newly opened webview window.
type Options struct {
	Title  string
	Width  int
	Height int
}
