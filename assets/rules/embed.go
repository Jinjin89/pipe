// SPDX-License-Identifier: GPL-3.0-or-later

// Package rules provides the offline rule-set bundle used by pipe.
package rules

import "embed"

//go:embed *.srs
var Files embed.FS
