// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !darwin && !windows

package webview

func CopySensitive(string) error { return ErrUnsupported }
