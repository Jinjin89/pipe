// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux

package sysproxy

import "os"

// Default picks GNOME or KDE tools, or nil when neither is usable.
func Default() Backend { return detectLinux(os.Getenv("XDG_CURRENT_DESKTOP"), lookPath, ExecRunner) }
