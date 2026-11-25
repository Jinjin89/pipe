// SPDX-License-Identifier: GPL-3.0-or-later

package relay

import "testing"

func TestRelayAllocateHop(t *testing.T) {
	for _, test := range []struct {
		name            string
		preferred, want portRange
		used            []portRange
	}{
		{"exact", portRange{25000, 45000}, portRange{25000, 45000}, nil},
		{"same width", portRange{25000, 25003}, portRange{25004, 25007}, []portRange{{25000, 25003}}},
		{"floor and cap", portRange{2500, 23000}, portRange{10000, 19999}, []portRange{{2500, 3500}}},
		{"wrap", portRange{65532, 65535}, portRange{10000, 10003}, []portRange{single(65534)}},
		{"largest shorter block", portRange{21000, 23999}, portRange{48000, 49999}, []portRange{
			{10000, 19999}, {21500, 47999}, {50000, 65535},
		}},
		{"no usable block", portRange{21000, 23999}, portRange{}, []portRange{
			{10000, 19999}, {20999, 65535},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var ports portSet
			for _, used := range test.used {
				ports.reserve(used)
			}
			if got := ports.allocateHop(test.preferred); got != test.want {
				t.Fatalf("allocateHop() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRelayAllocateOccupiedListeners(t *testing.T) {
	request, err := ParseRequest("93.184.216.34", "8443", "443,25000-25003")
	if err != nil {
		t.Fatal(err)
	}
	var used usedPorts
	used.tcp.reserve(single(8443))
	used.udp.reserve(single(443))
	used.udp.reserve(portRange{10000, 65535})
	r, err := request.allocate("relay.example", route{}, &used)
	if err != nil || r.RelayTCP != 8444 || r.RelayUDP != single(8443) {
		t.Fatalf("allocated TCP %d UDP %v, %v", r.RelayTCP, r.RelayUDP, err)
	}
	used.udp.reserve(portRange{8443, 9999})
	if _, err := request.allocate("relay.example", route{}, &used); err == nil {
		t.Fatal("accepted a route with no free UDP ports")
	}
}

func TestRelayReaddUDPMode(t *testing.T) {
	const target = "93.184.216.34"
	for _, test := range []struct {
		name, udp string
		old, want portRange
		occupied  []portRange
	}{
		{"gains hop", "443,25000-25003", single(8444), portRange{25000, 25003}, nil},
		{"keeps hop", "443,25000-25003", portRange{25004, 25007}, portRange{25004, 25007}, nil},
		{"replaces occupied hop", "443,25000-25003", portRange{25004, 25007}, portRange{25000, 25003}, []portRange{single(25007)}},
		{"disables hop", "443", portRange{25000, 25003}, single(443), nil},
		{"keeps single", "443", single(8444), single(8444), nil},
		{"keeps single if hop unavailable", "443,25000-25003", single(8444), single(8444), []portRange{{10000, 65535}}},
		{"replaces occupied single", "443,25000-25003", single(8444), single(443), []portRange{single(8444), {10000, 65535}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := ParseRequest(target, "", test.udp)
			if err != nil {
				t.Fatal(err)
			}
			var used usedPorts
			for _, ports := range test.occupied {
				used.udp.reserve(ports)
			}
			r, err := request.allocate("relay.example", route{RelayUDP: test.old}, &used)
			if err != nil || r.RelayUDP != test.want {
				t.Fatalf("re-add UDP ports = %v, %v, want %v", r.RelayUDP, err, test.want)
			}
		})
	}
}
