// SPDX-License-Identifier: GPL-3.0-or-later

package config

import "testing"

func TestParseRelayRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		input, canonical string
		want             Relay
	}{
		{"", "", Relay{}},
		{"Relay.Example", "relay.example", Relay{Host: "relay.example"}},
		{"192.0.2.9", "192.0.2.9", Relay{Host: "192.0.2.9"}},
		{"2001:0db8::9", "2001:db8::9", Relay{Host: "2001:db8::9"}},
		{"[2001:db8::9]", "2001:db8::9", Relay{Host: "2001:db8::9"}},
		{"2001:db8::9:8443", "2001:db8::9:8443", Relay{Host: "2001:db8::9:8443"}},
		{"relay.example:1", "relay.example:1", Relay{Host: "relay.example", StealthPort: 1}},
		{"relay.example/65535", "relay.example/65535", Relay{Host: "relay.example", FastPort: 65535}},
		{"192.0.2.9/30000-39999", "192.0.2.9/30000-39999", Relay{Host: "192.0.2.9", FastHop: "30000-39999"}},
		{"relay.example:8444/444", "relay.example:8444/444", Relay{Host: "relay.example", StealthPort: 8444, FastPort: 444}},
		{"[2001:db8::9]:8444", "[2001:db8::9]:8444", Relay{Host: "2001:db8::9", StealthPort: 8444}},
		{"[2001:db8::9]/444", "[2001:db8::9]/444", Relay{Host: "2001:db8::9", FastPort: 444}},
		{"[2001:DB8::9]:8444/30000-39999", "[2001:db8::9]:8444/30000-39999", Relay{Host: "2001:db8::9", StealthPort: 8444, FastHop: "30000-39999"}},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseRelay(tc.input, "origin.example")
			if err != nil || got != tc.want {
				t.Fatalf("got %+v, %v, want %+v", got, err, tc.want)
			}
			if code := got.String(); code != tc.canonical {
				t.Fatalf("canonical code %q, want %q", code, tc.canonical)
			}
			if again, err := ParseRelay(got.String(), "origin.example"); err != nil || again != got {
				t.Fatalf("round trip returned %+v, %v", again, err)
			}
		})
	}
}

func TestParseRelayRejectsInvalidCodes(t *testing.T) {
	for _, code := range []string{
		"https://relay.example", "relay.example/path", "relay.example?x=1", "user@relay.example:8444",
		" relay.example", "relay.example ", "relay..example", "relay.example: 8444", ":8444", "/443",
		"[relay.example]:8444", "[192.0.2.9]/443", "[2001:db8::9", "[2001:db8::9]foo", "[fe80::1%en0]:8444",
		"fe80::1%en0", "2001:db8::9/443", "2001:db8::9:65535", "relay.example:8444:443",
		"relay.example:", "relay.example/", "relay.example//443", "relay.example:0/443", "relay.example:65536",
		"relay.example:08444", "relay.example:+8444", "relay.example/0", "relay.example/65536", "relay.example/0443",
		"relay.example/1-1", "relay.example/10-1", "relay.example/0-1000", "relay.example/1-65536",
		"relay.example/10000-", "relay.example/01-10", "relay.example/30000-39999-40000", "relay.example:8444/443,30000-39999",
	} {
		if got, err := ParseRelay(code, "origin.example"); err == nil || got != (Relay{}) {
			t.Errorf("ParseRelay(%q) = %+v, %v", code, got, err)
		}
	}
}

func TestParseRelayRejectsServerAsRelay(t *testing.T) {
	for _, tc := range []struct{ code, server string }{
		{"Origin.Example:8444/443", "origin.example"},
		{"192.0.2.9/443", "192.0.2.9"},
		{"[2001:0db8:0:0::9]:8444", "2001:db8::9"},
		{"[::ffff:192.0.2.9]/443", "192.0.2.9"},
	} {
		if _, err := ParseRelay(tc.code, tc.server); err == nil {
			t.Errorf("ParseRelay(%q, %q) accepted the server as its own relay", tc.code, tc.server)
		}
	}
}

func TestRelayStringFormatsIPv6WithPorts(t *testing.T) {
	r := Relay{Host: "2001:0DB8::9", StealthPort: 8444, FastHop: "30000-39999"}
	if got, want := r.String(), "[2001:db8::9]:8444/30000-39999"; got != want {
		t.Fatalf("code %q, want %q", got, want)
	}
}
