// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

const proxyHTTPBusy = "TCP 80 is busy. Choose the dns certificate method with DNS credentials or files with a certificate and key"

func selectProxyCertMethod(opts ProxyEnableOptions, probe func() (bool, error)) (string, string, error) {
	switch opts.CertMethod {
	case "dns", "files":
		return opts.CertMethod, "explicitly selected", nil
	case "http", "auto":
	case "":
		switch {
		case opts.CertFile != "" || opts.KeyFile != "":
			return "files", "certificate files supplied", nil
		case opts.DNS != "":
			return "dns", "DNS provider supplied", nil
		}
	default:
		return "", "", errors.New("choose --cert-method http, dns or files")
	}
	occupied, err := probe()
	if occupied {
		return "", "", errors.New(proxyHTTPBusy)
	}
	if err != nil {
		// Setup already checks this as root. An explicit selection can also
		// be saved by an unprivileged user. Run checks again before issuance.
		if opts.CertMethod == "http" && (errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)) {
			return "http", "TCP 80 will be checked when the server starts", nil
		}
		return "", "", fmt.Errorf("cannot probe TCP 80: %w. Choose --cert-method dns or files", err)
	}
	return "http", "TCP 80 is free", nil
}

func probeProxyHTTP() (bool, error) {
	return probeHTTPPort(net.Listen)
}

func probeHTTPPort(listen func(string, string) (net.Listener, error)) (bool, error) {
	var probeErr error
	for _, endpoint := range []struct{ network, address string }{
		{"tcp4", "0.0.0.0:80"}, {"tcp6", "[::]:80"},
	} {
		listener, err := listen(endpoint.network, endpoint.address)
		switch {
		case err == nil:
			_ = listener.Close()
		case portInUse(err):
			return true, nil
		case endpoint.network == "tcp6" && ipv6Unavailable(err):
		default:
			probeErr = err
		}
	}
	return false, probeErr
}
