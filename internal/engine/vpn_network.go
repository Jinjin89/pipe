// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

// Route and neighbor discovery in sing-box's network manager use Linux
// netlink, including when the interfaces come from the platform. Keep its
// routing and socket protection, and supply Android's interface data directly
// to the consumers of the manager.
type vpnRegistry struct {
	service.Registry
	platform *vpnPlatform
}

func (r *vpnRegistry) Register(key, value any) any {
	if key == (*adapter.NetworkManager)(nil) {
		r.platform.network = &vpnNetworkManager{
			NetworkManager: value.(adapter.NetworkManager),
			platform:       r.platform,
		}
		value = r.platform.network
	}
	return r.Registry.Register(key, value)
}

type vpnNetworkManager struct {
	adapter.NetworkManager
	platform *vpnPlatform

	mu         sync.RWMutex
	interfaces []adapter.NetworkInterface
	defaultNet *adapter.NetworkInterface
	tunnel     control.Interface
}

type androidNetworkState struct {
	DefaultInterface string         `json:"defaultInterface"`
	DefaultIPv6Route bool           `json:"defaultIPv6Route"`
	DefaultAddresses []netip.Prefix `json:"defaultAddresses"`
	Interfaces       []struct {
		Name      string         `json:"name"`
		Index     int            `json:"index"`
		MTU       int            `json:"mtu"`
		Addresses []netip.Prefix `json:"addresses"`
		Flags     net.Flags      `json:"flags"`
		Type      string         `json:"type"`
		DNS       []string       `json:"dns"`
		Gateways  []netip.Addr   `json:"gateways"`
		Metered   bool           `json:"metered"`
	} `json:"interfaces"`
}

func decodeAndroidNetworkState(raw string) (androidNetworkState, error) {
	var state androidNetworkState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return androidNetworkState{}, err
	}
	return state, nil
}

// VPNNetworkIPv6 reports whether Android's active, non-VPN default network
// has an IPv6 default route and a global or unique local IPv6 address.
func VPNNetworkIPv6(raw string) bool {
	state, err := decodeAndroidNetworkState(raw)
	if err != nil || state.DefaultInterface == "" || !state.DefaultIPv6Route {
		return false
	}
	for _, prefix := range state.DefaultAddresses {
		address := prefix.Addr()
		if unicastIPv6(address) && (globalIPv6.Contains(address) || address.IsPrivate()) {
			return true
		}
	}
	return false
}

// VPNNetworkOnline reports whether Android has an active, non-VPN default network.
func VPNNetworkOnline(raw string) bool {
	state, err := decodeAndroidNetworkState(raw)
	return err == nil && state.DefaultInterface != ""
}

// VPNNetworkLANDNSServers returns the active physical network's DNS servers.
func VPNNetworkLANDNSServers(raw string, config Object) []netip.AddrPort {
	state, err := decodeAndroidNetworkState(raw)
	if err != nil || state.DefaultInterface == "" {
		return nil
	}
	var servers []netip.AddrPort
	for _, iface := range state.Interfaces {
		if iface.Name != state.DefaultInterface {
			continue
		}
		for _, value := range iface.DNS {
			address, err := netip.ParseAddr(value)
			if err != nil || address.IsUnspecified() || address.IsMulticast() {
				continue
			}
			// A link-local server is scoped by the interface's number: Android
			// 11+ hides interface names from apps, so Go can't map a name zone.
			if address.Is6() && address.IsLinkLocalUnicast() && iface.Index > 0 &&
				(address.Zone() == "" || address.Zone() == iface.Name) {
				address = address.WithZone(strconv.Itoa(iface.Index))
			}
			servers = append(servers, netip.AddrPortFrom(address, 53))
		}
		break
	}
	return filterLANDNSServers(servers, tunAddresses(config))
}

func (n *vpnNetworkManager) NetworkInterfaces() []adapter.NetworkInterface {
	n.mu.RLock()
	defer n.mu.RUnlock()
	// Without an Android default, sing-box would try to bind a socket to
	// each available interface. Wait for Android to select the network.
	if n.defaultNet == nil {
		return nil
	}
	return n.interfaces
}

func (n *vpnNetworkManager) DefaultNetworkInterface() *adapter.NetworkInterface {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.defaultNet
}

func (n *vpnNetworkManager) UpdateInterfaces() error { return n.refresh() }

func (n *vpnNetworkManager) refresh() error {
	state, err := decodeAndroidNetworkState(n.platform.options.Platform.NetworkState())
	if err != nil {
		return errors.New("invalid Android network state")
	}
	interfaces := make([]adapter.NetworkInterface, 0, len(state.Interfaces))
	var defaultNet *adapter.NetworkInterface
	for _, iface := range state.Interfaces {
		if iface.Name == "" || iface.Index <= 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		typ, known := C.StringToInterfaceType[iface.Type]
		if !known {
			typ = C.InterfaceTypeOther
		}
		item := adapter.NetworkInterface{
			Interface: control.Interface{
				Index: iface.Index, Name: iface.Name, MTU: iface.MTU,
				Addresses: iface.Addresses, Flags: iface.Flags,
			},
			Type: typ, DNSServers: iface.DNS, Gateways: iface.Gateways, Expensive: iface.Metered,
		}
		interfaces = append(interfaces, item)
		if iface.Name == state.DefaultInterface {
			defaultNet = &item
		}
	}
	n.mu.Lock()
	n.interfaces, n.defaultNet = interfaces, defaultNet
	// Supply the default alongside its interface list, including at startup.
	// sing-box protects sockets on the default without binding to its device,
	// so Android can route IPv4 through CLAT on an IPv6-only base link.
	n.platform.monitor.mu.Lock()
	n.platform.monitor.defaultInterface = nil
	if defaultNet != nil {
		n.platform.monitor.defaultInterface = &defaultNet.Interface
	}
	n.platform.monitor.mu.Unlock()
	n.mu.Unlock()
	return n.publishInterfaces()
}

func (n *vpnNetworkManager) registerTun(tunnel control.Interface) error {
	n.mu.Lock()
	n.tunnel = tunnel
	n.mu.Unlock()
	return n.publishInterfaces()
}

func (n *vpnNetworkManager) publishInterfaces() error {
	finder, ok := n.InterfaceFinder().(interface{ UpdateInterfaces([]control.Interface) })
	if !ok {
		return errors.New("VPN interface finder cannot accept Android interfaces")
	}
	n.mu.RLock()
	lookup := make([]control.Interface, 0, len(n.interfaces)+1)
	if n.tunnel.Name != "" {
		lookup = append(lookup, n.tunnel)
	}
	for _, iface := range n.interfaces {
		lookup = append(lookup, iface.Interface)
	}
	n.mu.RUnlock()
	finder.UpdateInterfaces(lookup)
	return nil
}

func (p *vpnPlatform) applyNetwork(ctx context.Context, reset bool) bool {
	// The stock monitor's update handler queries Linux routes and neighbors.
	// Android supplies the default network, so drive pause and reset directly.
	manager := service.FromContext[pause.Manager](ctx)
	if p.monitor.DefaultInterface() == nil {
		manager.NetworkPause()
		return false
	}
	manager.NetworkWake()
	if reset {
		p.network.ResetNetwork(ctx)
	}
	return true
}
