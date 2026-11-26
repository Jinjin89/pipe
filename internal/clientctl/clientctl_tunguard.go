// SPDX-License-Identifier: GPL-3.0-or-later

package clientctl

import (
	"errors"
	"io"
	"net/netip"
	"runtime"

	"pipe/internal/sysdns"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
)

func guardTUNOptions() (tun.Options, error) {
	opts := tun.Options{
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.5/30")},
		Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::5/126")},
		MTU:          1500,
		AutoRoute:    true,
		StrictRoute:  true,
		DNSMode:      tun.DNSModeDisabled,
	}
	ranges, err := opts.BuildAutoRouteRanges(false)
	if err != nil {
		return tun.Options{}, err
	}
	// More-specific routes overlap live capture without replacing its entries.
	// They also leave the physical default visible to the engine's monitor.
	for _, prefix := range ranges {
		addr, bits := prefix.Addr(), prefix.Bits()
		next := addr.AsSlice()
		next[bits/8] |= byte(0x80 >> (bits % 8))
		upper, _ := netip.AddrFromSlice(next)
		if addr.Is4() {
			opts.Inet4RouteAddress = append(opts.Inet4RouteAddress, netip.PrefixFrom(addr, bits+1), netip.PrefixFrom(upper, bits+1))
		} else {
			opts.Inet6RouteAddress = append(opts.Inet6RouteAddress, netip.PrefixFrom(addr, bits+1), netip.PrefixFrom(upper, bits+1))
		}
	}
	if runtime.GOOS == "darwin" {
		opts.Inet4RouteAddress = append(opts.Inet4RouteAddress, netip.PrefixFrom(netip.MustParseAddr(sysdns.TUNDNSAddress), 32))
	}
	if runtime.GOOS == "windows" {
		opts.DNSMode = tun.DNSModeHijack
	}
	return opts, nil
}

// startTUNGuard opens a capture device with no userspace forwarding stack.
// It drops captured packets until the replacement installs its own routes.
func startTUNGuard() (io.Closer, error) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		return nil, errors.New("protected TUN replacement is unavailable on this platform")
	}
	opts, err := guardTUNOptions()
	if err != nil {
		return nil, err
	}
	if err := prepareTUNGuardRoutes(&opts); err != nil {
		return nil, err
	}
	opts.Name = tun.CalculateInterfaceName("pipe-guard")
	opts.Logger = log.NewNOPFactory().Logger()
	opts.InterfaceFinder = new(control.DefaultInterfaceFinder)
	opts.InterfaceMonitor, err = tun.NewDefaultInterfaceMonitor(nil, opts.Logger, tun.DefaultInterfaceMonitorOptions{
		InterfaceFinder: opts.InterfaceFinder,
	})
	if err != nil {
		return nil, err
	}
	guard, err := tun.New(opts)
	if err != nil {
		return nil, err
	}
	if err := guard.Start(); err != nil {
		return nil, errors.Join(err, guard.Close())
	}
	return guard, nil
}
