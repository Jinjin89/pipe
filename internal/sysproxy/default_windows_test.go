// SPDX-License-Identifier: GPL-3.0-or-later
//go:build windows

package sysproxy

import (
	"strings"
	"testing"
)

func TestWindowsBypassLeavesNumericHostsForPipe(t *testing.T) {
	bypass := strings.Split(windowsBypass(), ";")
	for _, pattern := range bypass {
		if pattern != "<local>" && pattern != "localhost" && pattern != "*.local" {
			t.Errorf("unexpected Windows bypass pattern %q", pattern)
		}
	}
}
