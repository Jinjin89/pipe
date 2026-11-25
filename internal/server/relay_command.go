// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"pipe/internal/relay"
)

// RelayCommand returns the public relay add command and its address source.
func RelayCommand(ctx context.Context, dir string) (line, hint string, err error) {
	settings, err := ReadSettings(dir)
	if err != nil {
		return "", "", err
	}
	return relayCommand(ctx, settings, relayInterfaceAddresses, net.DefaultResolver.LookupNetIP)
}

func relayCommand(ctx context.Context, settings Settings, local func() ([]netip.Addr, error),
	lookup func(context.Context, string, string) ([]netip.Addr, error)) (line, hint string, err error) {
	addresses, _ := local()
	preferred, literalErr := netip.ParseAddr(settings.Domain)
	targets := relayTargets(addresses, preferred)
	var sources []string
	if targets[0].IsValid() || targets[1].IsValid() {
		sources = append(sources, "public addresses on active server interfaces")
	}
	if !targets[0].IsValid() || !targets[1].IsValid() {
		source := "the configured server IP"
		addresses = []netip.Addr{preferred}
		if literalErr != nil {
			network := "ip"
			source = "the server name's A and AAAA records"
			switch {
			case targets[0].IsValid():
				network, source = "ip6", "the server name's AAAA records"
			case targets[1].IsValid():
				network, source = "ip4", "the server name's A records"
			}
			addresses, _ = lookup(ctx, network, settings.Domain)
		}
		usedFallback := false
		for i, address := range relayTargets(addresses, preferred) {
			if !targets[i].IsValid() && address.IsValid() {
				targets[i] = address
				usedFallback = true
			}
		}
		if usedFallback {
			sources = append(sources, source)
		}
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	var targetList []string
	for _, address := range targets {
		if address.IsValid() {
			targetList = append(targetList, address.String())
		}
	}
	if len(targetList) == 0 {
		return "", "No public server address found. Assign one or point the server name at its public address.", nil
	}
	var tcp, udp string
	if settings.realityTargetProblem() == nil &&
		(settings.HTTPSProxyListener == nil || settings.HTTPSProxyListener.Port != settings.stealthPort()) {
		tcp = strconv.Itoa(int(settings.stealthPort()))
	}
	// Only shared servers publish the Fast pin needed for relaying Fast.
	if settings.Mode == Shared {
		udp = strconv.Itoa(int(settings.fastPort()))
		if settings.FastHop != "" {
			udp += "," + settings.FastHop
		}
	}
	request, err := relay.ParseRequest(strings.Join(targetList, ","), tcp, udp)
	if err != nil {
		return "", "", err
	}
	return request.AddCommand(), "Using " + strings.Join(sources, " and ") + ".", nil
}

func relayTargets(addresses []netip.Addr, preferred netip.Addr) [2]netip.Addr {
	var targets [2]netip.Addr
	preferred = preferred.Unmap()
	for _, address := range addresses {
		if !relay.PublicTarget(address) {
			continue
		}
		address = address.Unmap()
		selected := &targets[0]
		if address.Is6() {
			selected = &targets[1]
		}
		if !selected.IsValid() || address == preferred {
			*selected = address
		}
	}
	return targets
}

func relayInterfaceAddresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	for _, device := range interfaces {
		if device.Flags&net.FlagUp == 0 {
			continue
		}
		assigned, err := device.Addrs()
		if err != nil {
			continue
		}
		for _, address := range assigned {
			if prefix, ok := address.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(prefix.IP); ok {
					addresses = append(addresses, ip)
				}
			}
		}
	}
	return addresses, nil
}
