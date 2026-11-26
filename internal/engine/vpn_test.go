// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"

	"pipe/internal/sysdns"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	boxtun "github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

func TestVPNConfigSuppliesTunNameBeforePlatformOpen(t *testing.T) {
	registry := inbound.NewRegistry()
	boxtun.RegisterInbound(registry)
	instance := Instance{
		ctx: service.ContextWith[option.InboundOptionsRegistry](t.Context(), registry),
		vpn: &vpnPlatform{},
	}
	config := Object{"inbounds": []Object{
		{"type": "tun"},
		{"type": "tun", "interface_name": "custom"},
	}}
	decoded, err := instance.decode(config)
	if err != nil {
		t.Fatal(err)
	}
	if name := decoded.Inbounds[0].Options.(*option.TunInboundOptions).InterfaceName; name == "" {
		t.Fatal("a VPN TUN with no initial name would trigger native interface enumeration")
	}
	if name := decoded.Inbounds[1].Options.(*option.TunInboundOptions).InterfaceName; name != "custom" {
		t.Fatalf("explicit interface name changed to %q", name)
	}
	instance.vpn = nil
	decoded, err = instance.decode(config)
	if err != nil {
		t.Fatal(err)
	}
	if name := decoded.Inbounds[0].Options.(*option.TunInboundOptions).InterfaceName; name != "" {
		t.Fatalf("desktop TUN lost automatic naming with %q", name)
	}
}

func TestVPNPlatformBuildsRoutesDNSAndProtectsSockets(t *testing.T) {
	callback := &testVPNPlatform{}
	p := vpnPlatform{options: VPNOptions{Platform: callback, PerApp: "bypass", Packages: []string{"org.example"}}}
	if _, err := p.OpenInterface(&tun.Options{
		AutoRoute: true, MTU: 9000, Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
	}, option.TunPlatformOptions{}); !errors.Is(err, errTestTun) {
		t.Fatalf("platform error = %v", err)
	}
	var got struct {
		Addresses []string
		Routes    []string
		DNS       []string
		MTU       int
		PerApp    string
		Packages  []string
	}
	if err := json.Unmarshal([]byte(callback.options), &got); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Addresses, []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}) ||
		!slices.Equal(got.Routes, []string{"0.0.0.0/0", "::/0"}) ||
		!slices.Equal(got.DNS, []string{"172.19.0.2", "fdfe:dcba:9876::2"}) ||
		got.MTU != 9000 || got.PerApp != "bypass" || !slices.Equal(got.Packages, []string{"org.example"}) {
		t.Fatalf("unexpected TUN options %+v", got)
	}
	if err := p.AutoDetectInterfaceControl(42); err != nil || callback.protected != 42 {
		t.Fatalf("protect did not receive the socket: %v", err)
	}
	if err := p.AutoDetectInterfaceControl(43); err == nil {
		t.Fatal("an unprotected socket was accepted")
	}
}

func TestVPNUsesAndroidInterfacesAndPausesOffline(t *testing.T) {
	callback := &testVPNPlatform{network: `{
		"defaultInterface":"wlan0","interfaces":[
			{"name":"wlan0","index":7,"mtu":1500,"addresses":["10.0.2.15/24","fe80::1/64"],
			"flags":51,"type":"wifi","dns":["10.0.2.3"],"gateways":["10.0.2.2"]},
			{"name":"rmnet0","index":9,"mtu":1400,"flags":33,"type":"cellular","metered":true}]}`}
	p := &vpnPlatform{options: VPNOptions{Platform: callback}}
	native := &testVPNNetwork{finder: control.NewDefaultInterfaceFinder()}
	ctx := service.ContextWithRegistry(context.Background(), &vpnRegistry{Registry: service.NewRegistry(), platform: p})
	service.MustRegister[adapter.NetworkManager](ctx, native)
	ctx = pause.WithDefaultManager(ctx)
	manager := service.FromContext[adapter.NetworkManager](ctx)
	if err := p.Initialize(native); err != nil {
		t.Fatal(err)
	}
	if !p.UsePlatformNetworkInterfaces() || !p.UsePlatformConnectionOwnerFinder() {
		t.Fatal("VPN fell back to native Linux network discovery")
	}
	if owner, err := p.FindConnectionOwner(nil); owner != nil || !errors.Is(err, errUnsupportedVPNFeature) {
		t.Fatalf("unexpected connection owner result: %v, %v", owner, err)
	}
	interfaces, err := p.NetworkInterfaces()
	if err != nil || len(interfaces) != 2 {
		t.Fatalf("platform interfaces = %+v, %v", interfaces, err)
	}
	wifi := interfaces[0]
	if wifi.Index != 7 || wifi.Name != "wlan0" || wifi.MTU != 1500 || wifi.Type != C.InterfaceTypeWIFI ||
		wifi.Flags != net.FlagUp|net.FlagBroadcast|net.FlagMulticast|net.FlagRunning ||
		!slices.Equal(wifi.Addresses, []netip.Prefix{netip.MustParsePrefix("10.0.2.15/24"), netip.MustParsePrefix("fe80::1/64")}) ||
		!slices.Equal(wifi.DNSServers, []string{"10.0.2.3"}) ||
		!slices.Equal(wifi.Gateways, []netip.Addr{netip.MustParseAddr("10.0.2.2")}) ||
		interfaces[1].Type != C.InterfaceTypeCellular || !interfaces[1].Expensive {
		t.Fatalf("Android interface metadata was lost: %+v", interfaces)
	}
	if iface, _ := native.finder.ByIndex(7); iface == nil || iface.Name != "wlan0" {
		t.Fatal("Android interface missing from the engine's finder")
	}
	ownTun := control.Interface{
		Name: "tun7", Index: 27, MTU: 9000, Flags: net.FlagUp | net.FlagPointToPoint,
		Addresses: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30"), netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
	}
	if err := p.network.registerTun(ownTun); err != nil {
		t.Fatal(err)
	}
	if iface, err := manager.InterfaceFinder().ByName(ownTun.Name); err != nil || iface == nil || !ownTun.Equals(*iface) {
		t.Fatalf("direct outbound's TUN lookup returned %v, %v", iface, err)
	}
	if len(manager.NetworkInterfaces()) != 2 {
		t.Fatal("Android VPN TUN was exposed as an underlying network")
	}
	paused := service.FromContext[pause.Manager](ctx)
	if !p.applyNetwork(ctx, false) || paused.IsNetworkPaused() || native.resets != 0 ||
		p.monitor.DefaultInterface().Index != 7 || manager.DefaultNetworkInterface().Index != 7 {
		t.Fatal("initial network snapshot did not establish a baseline")
	}
	callback.network = `{"interfaces":[{"name":"rmnet0","index":9,"flags":33,"type":"cellular"}]}`
	if err := manager.UpdateInterfaces(); err != nil {
		t.Fatal(err)
	}
	if len(manager.NetworkInterfaces()) != 0 || p.monitor.DefaultInterface() != nil {
		t.Fatal("an interface is still available for binding after Android lost its default")
	}
	if iface, err := manager.InterfaceFinder().ByIndex(ownTun.Index); err != nil || iface == nil || !ownTun.Equals(*iface) {
		t.Fatalf("refresh lost the TUN: %v, %v", iface, err)
	}
	if p.applyNetwork(ctx, true) || !paused.IsNetworkPaused() || p.monitor.DefaultInterface() != nil || native.resets != 0 {
		t.Fatal("offline transition did not pause without resetting")
	}
	callback.network = `{"defaultInterface":"eth0","interfaces":[{"name":"eth0","index":8,"flags":51,"type":"ethernet"}]}`
	if err := manager.UpdateInterfaces(); err != nil {
		t.Fatal(err)
	}
	if !p.applyNetwork(ctx, true) || paused.IsNetworkPaused() || p.monitor.DefaultInterface().Index != 8 || native.resets != 1 {
		t.Fatal("online transition did not wake with the new default interface")
	}
}

func TestVPNNetworkIPv6UsesDefaultRouteAndUsableAddress(t *testing.T) {
	tests := []struct {
		name      string
		ipv6Route bool
		addresses []string
		wantIPv6  bool
	}{
		{name: "IPv4-only", addresses: []string{"192.0.2.10/24"}},
		{name: "dual-stack", ipv6Route: true, addresses: []string{"192.0.2.10/24", "2001:4860:1::1/64"}, wantIPv6: true},
		{name: "ULA-only", ipv6Route: true, addresses: []string{"fd12:3456::1/64"}, wantIPv6: true},
		{name: "link-local-only", ipv6Route: true, addresses: []string{"fe80::1/64"}},
		{name: "site-local-only", ipv6Route: true, addresses: []string{"fec0::1/64"}},
		{name: "IPv4-mapped", ipv6Route: true, addresses: []string{"::ffff:192.168.1.10/120"}},
		{name: "legacy tunnels", ipv6Route: true, addresses: []string{"2001::1/64", "2002:c000:201::1/64"}},
		{name: "CLAT", ipv6Route: true, addresses: []string{"2001:4860:1::1/64", "192.0.0.4/32"}, wantIPv6: true},
		{name: "no IPv6 default route", addresses: []string{"2001:4860:1::1/64"}},
		{name: "ULA without default route", addresses: []string{"fd12:3456::1/64"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, err := json.Marshal(struct {
				DefaultInterface string   `json:"defaultInterface"`
				DefaultIPv6Route bool     `json:"defaultIPv6Route"`
				DefaultAddresses []string `json:"defaultAddresses"`
			}{"wlan0", test.ipv6Route, test.addresses})
			if err != nil {
				t.Fatal(err)
			}
			if got := VPNNetworkIPv6(string(state)); got != test.wantIPv6 {
				t.Fatalf("VPNNetworkIPv6() = %v, want %v", got, test.wantIPv6)
			}
		})
	}
}

func TestVPNNetworkStateKeepsScopedDNSAndCLATAddress(t *testing.T) {
	callback := &testVPNPlatform{network: `{
		"defaultInterface":"rmnet0","defaultIPv6Route":true,
		"defaultAddresses":["2001:4860:1::1/64","192.0.0.4/32"],
		"interfaces":[
			{"name":"rmnet0","index":7,"flags":41,"type":"cellular",
			 "addresses":["2001:4860:1::1/64"],"dns":["fe80::53%rmnet0"],"gateways":["fe80::1%rmnet0"]},
			{"name":"v4-rmnet0","index":8,"flags":41,"type":"cellular",
			 "addresses":["192.0.0.4/32"]}]}`}
	platform := &vpnPlatform{options: VPNOptions{Platform: callback}}
	native := &testVPNNetwork{finder: control.NewDefaultInterfaceFinder()}
	network := &vpnNetworkManager{NetworkManager: native, platform: platform}
	if err := network.refresh(); err != nil {
		t.Fatal(err)
	}
	defaultNet := network.DefaultNetworkInterface()
	if defaultNet == nil || defaultNet.Name != "rmnet0" || !VPNNetworkIPv6(callback.network) ||
		!slices.Contains(defaultNet.DNSServers, "fe80::53%rmnet0") ||
		!slices.Contains(defaultNet.Gateways, netip.MustParseAddr("fe80::1%rmnet0")) {
		t.Fatalf("default network lost its route or scoped addresses: %+v", defaultNet)
	}
	dns, err := netip.ParseAddr(defaultNet.DNSServers[0])
	if err != nil || dns.Zone() != "rmnet0" {
		t.Fatalf("scoped DNS server did not parse: %v, %v", dns, err)
	}
	if monitor := platform.monitor.DefaultInterface(); monitor == nil || monitor.Index != defaultNet.Index {
		t.Fatal("the Android base link must be the monitor default before the first dial")
	}
	v4 := netip.MustParsePrefix("192.0.0.4/32")
	interfaces := network.NetworkInterfaces()
	if len(interfaces) != 2 || interfaces[1].Name != "v4-rmnet0" || interfaces[1].Index != 8 ||
		!slices.Equal(interfaces[1].Addresses, []netip.Prefix{v4}) || slices.Contains(defaultNet.Addresses, v4) {
		t.Fatalf("CLAT was not published separately from the base link: %+v", interfaces)
	}
	if iface, err := native.finder.ByIndex(8); err != nil || iface == nil || iface.Name != "v4-rmnet0" {
		t.Fatalf("CLAT was not available by its interface index: %v, %v", iface, err)
	}
	state, err := decodeAndroidNetworkState(callback.network)
	if err != nil || !slices.Contains(state.DefaultAddresses, v4) {
		t.Fatalf("the default snapshot omitted the CLAT address: %+v, %v", state.DefaultAddresses, err)
	}
}

func TestVPNNetworkLANDNSServersUsesDefaultSnapshot(t *testing.T) {
	config := Object{"inbounds": []Object{{
		"type": "tun", "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
	}}}
	state := `{"defaultInterface":"wlan0","interfaces":[
		{"name":"wlan0","index":7,"dns":["fe80::53%wlan0","fe80::54","192.168.1.1","invalid","172.19.0.1","fdfe:dcba:9876::1","` + sysdns.TUNDNSAddress + `"]},
		{"name":"rmnet0","dns":["10.0.0.1"]}]}`
	want := []netip.AddrPort{
		netip.MustParseAddrPort("[fe80::53%7]:53"),
		netip.MustParseAddrPort("[fe80::54%7]:53"),
		netip.MustParseAddrPort("192.168.1.1:53"),
	}
	if got := VPNNetworkLANDNSServers(state, config); !slices.Equal(got, want) {
		t.Fatalf("default LAN DNS servers = %v, want %v", got, want)
	}
	changed := `{"defaultInterface":"rmnet0","interfaces":[{"name":"rmnet0","dns":["fe80::53%rmnet0"]}]}`
	if got := VPNNetworkLANDNSServers(changed, config); !slices.Equal(got, []netip.AddrPort{netip.MustParseAddrPort("[fe80::53%rmnet0]:53")}) {
		t.Fatalf("updated LAN DNS servers = %v", got)
	}
}

func TestVPNNetworkLANDNSServersEmptyOrUnknown(t *testing.T) {
	config := Object{}
	for _, state := range []string{
		`{}`,
		`{"defaultInterface":"missing","interfaces":[{"name":"wlan0","dns":["192.168.1.1"]}]}`,
		`{"defaultInterface":"wlan0","interfaces":[{"name":"wlan0","dns":["invalid"]}]}`,
		`not-json`,
	} {
		if got := VPNNetworkLANDNSServers(state, config); len(got) != 0 {
			t.Fatalf("unexpected servers for %q: %v", state, got)
		}
	}
}

func TestVPNInstanceUsesSuppliedNetwork(t *testing.T) {
	callback := &testVPNPlatform{
		network: `{"defaultInterface":"wlan0","interfaces":[
			{"name":"wlan0","index":7,"flags":51,"type":"wifi","addresses":["fd12::1/64"]}]}`,
	}
	instance, err := New(t.Context(), Options{
		Config: Object{
			"route":     Object{"auto_detect_interface": true},
			"outbounds": []Object{{"type": "direct", "tag": "direct"}},
		},
		VPN: &VPNOptions{Platform: callback},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	network := service.FromContext[adapter.NetworkManager](instance.ctx)
	if !instance.VPNOnline() || len(network.NetworkInterfaces()) != 1 ||
		network.DefaultNetworkInterface().Name != "wlan0" || instance.DefaultInterface() != "wlan0" ||
		network.ProtectFunc() == nil {
		t.Fatal("running engine did not use the Android network and socket protection")
	}
	callback.network = `{"defaultInterface":"wlan0","interfaces":[
		{"name":"wlan0","index":7,"flags":51,"type":"wifi","addresses":["fd12::2/64"]}]}`
	if online, err := instance.RefreshVPNNetwork(false); err != nil || !online {
		t.Fatalf("engine refresh after address rotation: online=%v, err=%v", online, err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("fd12::2/64")}
	iface, err := network.InterfaceFinder().ByIndex(7)
	defaultIface := network.InterfaceMonitor().DefaultInterface()
	if err != nil || iface == nil || !slices.Equal(iface.Addresses, want) ||
		defaultIface == nil || !slices.Equal(defaultIface.Addresses, want) {
		t.Fatalf("engine refresh did not publish the new IPv6 address: %v, %v", iface, err)
	}
	callback.network = "{}"
	if online, err := instance.RefreshVPNNetwork(true); err != nil || online || instance.VPNOnline() || instance.DefaultInterface() != "" ||
		!service.FromContext[pause.Manager](instance.ctx).IsNetworkPaused() {
		t.Fatalf("engine refresh after Android lost its network: online=%v, err=%v", online, err)
	}
}

type testVPNNetwork struct {
	adapter.NetworkManager
	finder *control.DefaultInterfaceFinder
	resets int
}

func (n *testVPNNetwork) InterfaceFinder() control.InterfaceFinder { return n.finder }
func (n *testVPNNetwork) ResetNetwork(context.Context)             { n.resets++ }

var errTestTun = errors.New("test TUN")

type testVPNPlatform struct {
	options   string
	protected int32
	network   string
}

func (p *testVPNPlatform) NetworkState() string { return p.network }

func (p *testVPNPlatform) OpenTun(options string) (int32, error) {
	p.options = options
	return -1, errTestTun
}

func (p *testVPNPlatform) Protect(fd int32) bool {
	p.protected = fd
	return fd == 42
}
