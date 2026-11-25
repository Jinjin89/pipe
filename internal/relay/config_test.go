// SPDX-License-Identifier: GPL-3.0-or-later

package relay

import (
	"strings"
	"testing"
)

func TestRelayConfig(t *testing.T) {
	request, err := ParseRequest("2606:4700::1234,::ffff:93.184.216.34", "8443", "25004,25000-25003")
	if err != nil {
		t.Fatal(err)
	}
	want := "pipe relay add --to 93.184.216.34,2606:4700::1234 --tcp 8443 --udp 25004,25000-25003"
	if got := request.AddCommand(); got != want {
		t.Fatalf("AddCommand() = %q, want %q", got, want)
	}
}

func TestRelayRejectsInvalidTargets(t *testing.T) {
	for _, target := range []string{
		"", "origin.example", "127.0.0.1", "169.254.169.254", "10.2.3.4", "100.64.0.1",
		"0.0.0.0", "224.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1",
		"::", "::1", "fc00::1", "fe80::1%eth0", "ff02::1", "2001:db8::1", "3fff::1",
		"::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "93.184.216.34:443", "1.1.1.1,8.8.8.8",
		"pipe://secret-device-seed@origin.example",
	} {
		_, err := ParseRequest(target, "443", "")
		if err == nil || strings.Contains(err.Error(), "secret-device-seed") {
			t.Errorf("expected a redacted validation error for %q, got %v", target, err)
		}
	}
}

func TestRelayRejectsInvalidPorts(t *testing.T) {
	for _, ports := range []string{"", "0", "65536", "1024-1023", "443,", "443,,8443", "443,1-2,3-4", "443,2-2", "0443", "443,01-2", "https", "443; delete table inet filter"} {
		if _, err := ParseRequest("93.184.216.34", "", ports); err == nil {
			t.Errorf("accepted port list %q", ports)
		}
	}
}

func TestRelayRejectsMultipleTCPPorts(t *testing.T) {
	for _, ports := range []string{"8443,8444", "8443-8444", "08443"} {
		if _, err := ParseRequest("93.184.216.34", ports, "443"); err == nil {
			t.Errorf("accepted --tcp %q", ports)
		}
	}
}

func TestRelayRouteCodes(t *testing.T) {
	for _, test := range []struct {
		to, tcp, udp, host, want string
	}{
		{"93.184.216.34", "8443", "443", "relay.example", "relay.example"},
		{"93.184.216.34", "8443", "443,25000-25003", "Relay.Example", "relay.example"},
		{"93.184.216.34", "", "443", "relay.example", "relay.example/443"},
		{"93.184.216.34", "8443", "", "relay.example", "relay.example:8443"},
		{"2606:4700::1234", "", "443,25000-25003", "2606:4700::1235", "[2606:4700::1235]/25000-25003"},
		{"2606:4700::1234", "8443", "443,25000-25003", "2606:4700::1235", "2606:4700::1235"},
	} {
		r := testRoute(t, test.to, test.tcp, test.udp, test.host)
		if got := r.code(); got != test.want {
			t.Errorf("route code = %q, want %q", got, test.want)
		}
	}
}

func testRoute(t *testing.T, to, tcp, udp, host string) route {
	t.Helper()
	request, err := ParseRequest(to, tcp, udp)
	if err != nil {
		t.Fatal(err)
	}
	r, err := request.allocate(host, route{}, new(usedPorts))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
