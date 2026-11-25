// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

// VPNPlatform provides the operations owned by Android's VpnService.
// OpenTun transfers ownership of the detached file descriptor to Go.
type VPNPlatform interface {
	OpenTun(optionsJSON string) (int32, error)
	Protect(fd int32) bool
	NetworkState() string
}

type VPNOptions struct {
	Platform   VPNPlatform
	PerApp     string
	Packages   []string
	CountBytes func(up, down int64)
	// HoldTun takes ownership of the platform descriptor while the engine
	// uses its duplicate. The caller releases it after replacement or rollback.
	HoldTun func(release func())
}

type vpnPlatform struct {
	options VPNOptions
	monitor vpnInterfaceMonitor
	addrs   []netip.Addr
	network *vpnNetworkManager
}

var _ adapter.PlatformInterface = (*vpnPlatform)(nil)

func (p *vpnPlatform) Initialize(adapter.NetworkManager) error {
	return p.network.UpdateInterfaces()
}
func (p *vpnPlatform) UsePlatformAutoDetectInterfaceControl() bool { return true }
func (p *vpnPlatform) AutoDetectInterfaceControl(fd int) error {
	if !p.options.Platform.Protect(int32(fd)) {
		return errors.New("Android could not protect the socket")
	}
	return nil
}

func (p *vpnPlatform) UsePlatformInterface() bool { return true }

func (p *vpnPlatform) OpenInterface(options *tun.Options, _ option.TunPlatformOptions) (tun.Tun, error) {
	routes, err := options.BuildAutoRouteRanges(true)
	if err != nil {
		return nil, err
	}
	dnsServers, err := options.DNSServerAddress()
	if err != nil {
		return nil, err
	}
	addresses := slices.Concat(options.Inet4Address, options.Inet6Address)
	settings := struct {
		Addresses []netip.Prefix `json:"addresses"`
		Routes    []netip.Prefix `json:"routes"`
		DNS       []netip.Addr   `json:"dns"`
		MTU       uint32         `json:"mtu"`
		PerApp    string         `json:"perApp"`
		Packages  []string       `json:"packages"`
	}{addresses, routes, dnsServers, options.MTU, p.options.PerApp, p.options.Packages}
	body, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	fd, err := p.options.Platform.OpenTun(string(body))
	if err != nil {
		return nil, err
	}
	if hold := p.options.HoldTun; hold != nil && fd >= 0 {
		p.options.HoldTun = nil
		var release func()
		fd, release, err = duplicateVPNTun(fd)
		if release != nil {
			hold(release)
		}
		if err != nil {
			return nil, err
		}
	}
	device, err := adoptVPNTun(fd, options)
	if err != nil {
		return nil, err
	}
	p.monitor.RegisterMyInterface(options.Name)
	// The direct outbounds look up this name to find the TUN's local
	// prefixes. Android supplies only underlying interfaces in its snapshot.
	if err := p.network.registerTun(control.Interface{
		Name:      options.Name,
		Index:     vpnInterfaceIndex(options.Name),
		MTU:       int(options.MTU),
		Flags:     net.FlagUp | net.FlagRunning | net.FlagPointToPoint,
		Addresses: addresses,
	}); err != nil {
		_ = device.Close()
		return nil, err
	}
	tunAddresses := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		tunAddresses = append(tunAddresses, address.Addr())
	}
	p.monitor.mu.Lock()
	p.addrs = tunAddresses
	p.monitor.mu.Unlock()
	return device, nil
}

func (p *vpnPlatform) ProcessPlatformOptions(option.TunPlatformOptions) error { return nil }
func (p *vpnPlatform) UsePlatformDefaultInterfaceMonitor() bool               { return true }
func (p *vpnPlatform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return &p.monitor
}

func (p *vpnPlatform) UsePlatformNetworkInterfaces() bool { return true }
func (p *vpnPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	return p.network.NetworkInterfaces(), nil
}
func (p *vpnPlatform) UnderNetworkExtension() bool                     { return false }
func (p *vpnPlatform) NetworkExtensionIncludeAllNetworks() bool        { return false }
func (p *vpnPlatform) ClearDNSCache()                                  {}
func (p *vpnPlatform) RequestPermissionForWIFIState() error            { return errUnsupportedVPNFeature }
func (p *vpnPlatform) ReadWIFIState(context.Context) adapter.WIFIState { return adapter.WIFIState{} }
func (p *vpnPlatform) UsePlatformConnectionOwnerFinder() bool          { return true }
func (p *vpnPlatform) FindConnectionOwner(*adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, errUnsupportedVPNFeature
}
func (p *vpnPlatform) UsePlatformWIFIMonitor() bool                 { return false }
func (p *vpnPlatform) UsePlatformNotification() bool                { return false }
func (p *vpnPlatform) SendNotification(*adapter.Notification) error { return errUnsupportedVPNFeature }
func (p *vpnPlatform) CancelNotification(string, int32) error       { return errUnsupportedVPNFeature }
func (p *vpnPlatform) MyInterfaceAddress() []netip.Addr {
	p.monitor.mu.Lock()
	defer p.monitor.mu.Unlock()
	return p.addrs
}
func (p *vpnPlatform) UsePlatformNeighborResolver() bool { return false }
func (p *vpnPlatform) StartNeighborMonitor(adapter.NeighborUpdateListener) error {
	return errUnsupportedVPNFeature
}
func (p *vpnPlatform) CloseNeighborMonitor(adapter.NeighborUpdateListener) error { return nil }
func (p *vpnPlatform) UsePlatformShell() bool                                    { return false }
func (p *vpnPlatform) CheckPlatformShell() error                                 { return errUnsupportedVPNFeature }
func (p *vpnPlatform) OpenShellSession(*adapter.PlatformUser, string, []string, string, int32, int32) (adapter.ShellSession, error) {
	return nil, errUnsupportedVPNFeature
}
func (p *vpnPlatform) LookupUser(string) (*adapter.PlatformUser, error) {
	return nil, errUnsupportedVPNFeature
}
func (p *vpnPlatform) LookupSFTPServer() (string, error)     { return "", errUnsupportedVPNFeature }
func (p *vpnPlatform) ReadSystemSSHHostKey() ([]byte, error) { return nil, errUnsupportedVPNFeature }
func (p *vpnPlatform) TailscaleHostname() string             { return "" }
func (p *vpnPlatform) UsePlatformBridge() bool               { return false }
func (p *vpnPlatform) CreateBridge(adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, errUnsupportedVPNFeature
}

var errUnsupportedVPNFeature = errors.New("unsupported VPN platform feature")

// Android chooses the underlying interface for protected sockets. The monitor
// represents that default network and receives ConnectivityManager events.
type vpnInterfaceMonitor struct {
	mu               sync.Mutex
	callbacks        list.List[tun.DefaultInterfaceUpdateCallback]
	name             string
	defaultInterface *control.Interface
}

func (m *vpnInterfaceMonitor) Start() error { return nil }
func (m *vpnInterfaceMonitor) Close() error { return nil }
func (m *vpnInterfaceMonitor) DefaultInterface() *control.Interface {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.defaultInterface
}
func (m *vpnInterfaceMonitor) OverrideAndroidVPN() bool { return false }
func (m *vpnInterfaceMonitor) AndroidVPNEnabled() bool  { return true }

func (m *vpnInterfaceMonitor) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *vpnInterfaceMonitor) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks.Remove(element)
}

func (m *vpnInterfaceMonitor) RegisterMyInterface(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.name = name
}

func (m *vpnInterfaceMonitor) MyInterfaces() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.name == "" {
		return nil
	}
	return []string{m.name}
}
