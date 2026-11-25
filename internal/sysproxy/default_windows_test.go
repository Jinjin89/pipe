// SPDX-License-Identifier: GPL-3.0-or-later
//go:build windows

package sysproxy

import (
	"strings"
	"testing"
)

func TestWindowsBypassIncludesIPv6LocalRanges(t *testing.T) {
	bypass := strings.Split(windowsBypass(), ";")
	for _, want := range []string{"::1/128", "fe80::/10", "fc00::/7", "[::1]", "[fe8*]", "[fe9*]", "[fea*]", "[feb*]", "[fc*]", "[fd*]"} {
		if !contains(bypass, want) {
			t.Errorf("Windows bypass is missing %q: %v", want, bypass)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
