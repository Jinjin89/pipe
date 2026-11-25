// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/caddyserver/certmagic"
)

func proxyCover(www string, fallback http.Handler) (http.Handler, error) {
	if www == "" {
		return fallback, nil
	}
	info, err := os.Stat(www)
	if err != nil {
		return nil, fmt.Errorf("open HTTPS proxy web directory: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("HTTPS proxy --www must point to a directory")
	}
	return http.FileServer(http.Dir(www)), nil
}

func strictProxyTLS(domain string, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: getCertificate,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// This also checks ClientHellos that try to resume a TLS session.
			if hello.ServerName == "" || !equalDNS(hello.ServerName, domain) {
				return nil, errors.New("unrecognized HTTPS proxy server name")
			}
			return nil, nil
		},
	}
}

// startSharedHTTPSProxy binds the HTTPS proxy's TCP listener and starts its
// certificates. It runs before the engine so that, with reality_dest self,
// REALITY's handshake target is always a socket this process owns. It returns
// a stop function. A missing certificate is not an error: handshakes fail.
func startSharedHTTPSProxy(ctx context.Context, dir, address string, cfg httpsProxyListenerConfig, proxy *httpsProxy, output io.Writer, warn func(string)) (func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	stops := []func(){cancel}
	stop := func() {
		for i := len(stops) - 1; i >= 0; i-- {
			stops[i]()
		}
	}
	var getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if cfg.method() == "files" {
		pem := newProxyPEMCertificates(cfg, warn)
		getCertificate = pem.getCertificate
	} else {
		var provider certmagic.DNSProvider
		if cfg.method() == "dns" {
			savedProvider, secret, err := readProxyDNSSecret(cfg.DNS, filepath.Join(dir, cfg.DNSSecret))
			clear(secret)
			if err != nil {
				stop()
				return nil, errors.New("HTTPS proxy could not load its saved DNS credentials")
			}
			provider = savedProvider
		}
		certificates, stopCertificates, err := proxyManagedCertificates(dir, cfg, provider, warn)
		if err != nil {
			stop()
			return nil, errors.New("HTTPS proxy could not initialize its certificate storage")
		}
		stops = append(stops, stopCertificates)
		if err := certificates.ManageAsync(ctx, []string{cfg.Domain}); err != nil {
			warn("HTTPS proxy could not start background certificate management")
		}
		getCertificate = certificates.GetCertificate
	}
	server := webServer(proxy, strictProxyTLS(cfg.Domain, getCertificate))
	failures := make(chan error, 1)
	listener, err := serve(server, address, cfg.Port, failures)
	if err != nil {
		stop()
		return nil, fmt.Errorf("HTTPS proxy could not bind TCP port %d: %v", cfg.Port, err)
	}
	stops = append(stops, func() { _ = listener.Close() })
	fmt.Fprintf(output, "HTTPS proxy listening on %s\n", listener.Addr())
	go func() {
		select {
		case <-ctx.Done():
		case <-failures:
			warn("HTTPS proxy listener stopped unexpectedly")
		}
	}()
	return stop, nil
}
