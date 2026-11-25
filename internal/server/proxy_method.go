// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

func SelectProxyCertMethod(opts ProxyEnableOptions) (method, reason string, err error) {
	return selectProxyCertMethod(opts, probeProxyHTTP)
}

func selectProxyCertMethod(opts ProxyEnableOptions, probe func() (bool, bool, error)) (string, string, error) {
	const choices = "choose --cert-method http, nginx, dns or files"
	switch opts.CertMethod {
	case "http", "nginx", "dns", "files":
		return opts.CertMethod, "explicitly selected", nil
	case "", "auto":
	default:
		return "", "", errors.New(choices)
	}
	switch {
	case opts.CertFile != "" || opts.KeyFile != "":
		return "files", "certificate files supplied", nil
	case opts.DNS != "":
		return "dns", "DNS provider supplied", nil
	}
	occupied, web, err := probe()
	switch {
	case err != nil:
		return "", "", fmt.Errorf("cannot probe TCP 80: %w. %s", err, choices)
	case !occupied:
		return "http", "TCP 80 is free", nil
	case web:
		return "nginx", "an HTTP server owns TCP 80", nil
	default:
		return "", "", fmt.Errorf("TCP 80 is occupied by an unidentified service. %s", choices)
	}
}

func probeProxyHTTP() (bool, bool, error) {
	return probeHTTPPort(net.Listen, servesHTTPOn80)
}

func probeHTTPPort(listen func(string, string) (net.Listener, error), webProbe func() bool) (bool, bool, error) {
	var occupied bool
	var probeErr error
	for _, endpoint := range []struct{ network, address string }{
		{"tcp4", "0.0.0.0:80"}, {"tcp6", "[::]:80"},
	} {
		listener, err := listen(endpoint.network, endpoint.address)
		switch {
		case err == nil:
			_ = listener.Close()
		case portInUse(err):
			occupied = true
		case endpoint.network == "tcp6" && ipv6Unavailable(err):
		default:
			probeErr = err
		}
	}
	if occupied || errors.Is(probeErr, syscall.EACCES) || errors.Is(probeErr, syscall.EPERM) {
		if webProbe() {
			return true, true, nil
		}
	}
	return occupied, false, probeErr
}

func servesHTTPOn80() bool {
	hosts := []string{"127.0.0.1", "::1"}
	addresses, _ := net.InterfaceAddrs()
	for _, address := range addresses {
		if ip, ok := address.(*net.IPNet); ok && !ip.IP.IsLoopback() && !ip.IP.IsLinkLocalUnicast() {
			hosts = append(hosts, ip.IP.String())
		}
	}
	transport := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{
		Transport: transport, Timeout: 200 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, host := range hosts {
		response, err := client.Head("http://" + net.JoinHostPort(host, "80") + "/")
		if err == nil {
			_ = response.Body.Close()
			return true
		}
	}
	return false
}
