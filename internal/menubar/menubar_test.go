// SPDX-License-Identifier: GPL-3.0-or-later

package menubar

import "testing"

func TestMenuTitleRelayState(t *testing.T) {
	const title = "Connected · Fast · TUN"
	for _, tc := range []struct {
		state, suffix string
	}{
		{"via", " · via 2001:db8::2"},
		{"direct", " · relay not reachable, direct"},
		{"pending", ""},
		{"", ""},
	} {
		state := State{Status: "on", Title: title, RelayHost: "2001:db8::2", RelayState: tc.state}
		if got, want := menuTitle(state), title+tc.suffix; got != want {
			t.Errorf("menu title for %q = %q, want %q", tc.state, got, want)
		}
	}
	if got := menuTitle(State{}); got != "Pipe" {
		t.Fatalf("default menu title = %q", got)
	}
}
