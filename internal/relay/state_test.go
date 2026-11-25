// SPDX-License-Identifier: GPL-3.0-or-later

package relay

import (
	"reflect"
	"strings"
	"testing"
)

func TestRelayRouteLifecycle(t *testing.T) {
	first := testRoute(t, "93.184.216.34", "8443", "443,25000-25003", "relay.example")
	second := testRoute(t, "2606:4700::1234", "8443", "443,25000-25003", "relay.example")
	s := state{routes: []route{first}}
	index, err := s.replace(second.Request, second.Host, new(usedPorts))
	if err != nil || index != 1 || len(s.routes) != 2 {
		t.Fatalf("added route at %d, len = %d, err = %v", index, len(s.routes), err)
	}
	got := s.routes[index]
	if got.code() != "relay.example:8444/25004-25007" {
		t.Fatalf("added route code = %s", got.code())
	}
	if r, err := ParseRequest("93.184.216.34,2606:4700::1234", "8443", ""); err != nil {
		t.Fatal(err)
	} else if _, err := s.replace(r, "relay.example", new(usedPorts)); err == nil {
		t.Fatal("allowed a request overlapping both routes")
	}
	if err := s.remove("93.184.216.34"); err != nil || len(s.routes) != 1 {
		t.Fatalf("remove first route: %+v, %v", s.routes, err)
	}
	index, err = s.replace(second.Request, "relay.example", new(usedPorts))
	if err != nil || index != 0 || len(s.routes) != 1 || s.routes[index] != got {
		t.Fatalf("replaced route at %d: %+v, %v, want %+v", index, s.routes, err, got)
	}
	if err := s.remove(""); err != nil || len(s.routes) != 0 {
		t.Fatalf("remove all: %+v, %v", s.routes, err)
	}
}

func TestRelayReplaceKeepsSavedHost(t *testing.T) {
	const dualStack = "93.184.216.34,2606:4700::1234"
	for _, test := range []struct {
		name, targets, old, host, want string
	}{
		{"saved DNS name", "2606:4700::1234", "relay.example", "", "relay.example"},
		{"saved NAT address", dualStack, "198.51.100.4", "", "198.51.100.4"},
		{"new override", dualStack, "relay.example", "new.example", "new.example"},
		{"saved address family removed", "2606:4700::1234", "198.51.100.4", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			old := testRoute(t, dualStack, "8443", "", test.old)
			s := state{routes: []route{old}}
			request, err := ParseRequest(test.targets, "8444", "")
			if err != nil {
				t.Fatal(err)
			}
			index, err := s.replace(request, test.host, new(usedPorts))
			if err != nil || index != 0 || len(s.routes) != 1 {
				t.Fatalf("replaced route at %d, len = %d, err = %v", index, len(s.routes), err)
			}
			if got := s.routes[index].Host; got != test.want {
				t.Fatalf("replaced host = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRelayRemoveDualStackTargets(t *testing.T) {
	first := testRoute(t, "93.184.216.34,2606:4700::1234", "8443", "", "relay.example")
	second := testRoute(t, "2606:4700::1235", "8444", "", "relay.example")
	s := state{routes: []route{first, second}}
	if err := s.remove(first.IPv4.String() + "," + second.IPv6.String()); err == nil || !strings.Contains(err.Error(), "overlaps two") {
		t.Fatalf("remove across different routes: %v", err)
	}
	if !reflect.DeepEqual(s.routes, []route{first, second}) {
		t.Fatalf("ambiguous remove altered routes: %+v", s.routes)
	}
	if err := s.remove(first.targets()); err != nil || !reflect.DeepEqual(s.routes, []route{second}) {
		t.Fatalf("remove v4,v6 route: %+v, %v", s.routes, err)
	}
}

func TestRelayStateValidation(t *testing.T) {
	r := testRoute(t, "93.184.216.34", "8443", "443,25000-25003", "relay.example")
	s := state{ingress{IPv4: []string{"eth0"}}, []route{r}}
	text, err := stateText(s)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := parseState(text)
	if err != nil || !reflect.DeepEqual(decoded, s) {
		t.Fatalf("parseState() = %+v, %v, want %+v", decoded, err, s)
	}
	for _, input := range []string{
		strings.TrimPrefix(text, ownedHeader),
		strings.Replace(text, `"eth0"`, `"eth*"`, 1),
		strings.Replace(text, `"eth0"`, `"eth0","eth0"`, 1),
		strings.Replace(text, "ingress4", "ingress6", 1),
		strings.Replace(text, "relay_tcp", "relay_typo", 1),
		strings.Replace(text, `"relay_tcp":8443`, `"relay_tcp":65536`, 1),
		strings.Replace(text, "93.184.216.34", "10.1.1.1", 1),
		strings.Replace(text, "relay.example", "fe80::1%eth0", 1),
		text + strings.Split(text, "\n")[2] + "\n",
		text + strings.Replace(strings.Split(text, "\n")[2], "93.184.216.34", "8.8.4.4", 1) + "\n",
	} {
		if _, err := parseState(input); err == nil {
			t.Errorf("accepted invalid state\n%s", input)
		}
	}
}

func TestRelayStatusCounters(t *testing.T) {
	r := testRoute(t, "93.184.216.34", "8443", "443", "relay.example")
	s := state{routes: []route{r}}
	counters, err := readCounters(`{"nftables":[{"metainfo":{}},{"counter":{"family":"inet","name":"route_1_tcp","table":"pipe_relay","packets":4,"bytes":256}},{"counter":{"family":"inet","name":"route_1_udp","table":"pipe_relay","packets":6,"bytes":300}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := statusText(s, true, counters); got != "93.184.216.34 relay.example TCP 4 packets 256 bytes UDP 6 packets 300 bytes\n" {
		t.Fatalf("status = %q", got)
	}
	if got := statusText(s, false, nil); !strings.Contains(got, "no kernel table") || !strings.Contains(got, "93.184.216.34 relay.example") {
		t.Fatalf("status with no table = %q", got)
	}
}
