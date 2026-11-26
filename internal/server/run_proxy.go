// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"github.com/caddyserver/certmagic"
)

var errTLSName = errors.New("unrecognized TLS server name")

func proxyCover(www string, fallback http.Handler) (http.Handler, error) {
	if www == "" {
		return fallback, nil
	}
	cover, err := directoryCover(www)
	if err != nil {
		return nil, fmt.Errorf("open HTTPS proxy web directory: %w", err)
	}
	return cover, nil
}

func strictSiteTLS(domain string, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: getCertificate,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// This also checks ClientHellos that try to resume a TLS session.
			if hello.ServerName == "" || !equalDNS(hello.ServerName, domain) {
				return nil, errTLSName
			}
			return nil, nil
		},
	}
}

func strictProxyTLS(domain string, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	config := strictSiteTLS(domain, getCertificate)
	config.NextProtos = []string{"http/1.1"}
	return config
}

func proxyWebServer(proxy *httpsProxy, domain string, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *http.Server {
	// HTTP/1.1 absolute-form forwarding preserves the requested origin scheme.
	// Go's HTTP/2 handler cannot distinguish HTTP and HTTPS forwards.
	server := webServer(proxy, strictProxyTLS(domain, getCertificate))
	server.Protocols = new(http.Protocols)
	server.Protocols.SetHTTP1(true)
	return server
}

// startSharedHTTPSProxy binds the HTTPS proxy's TCP listener and starts its
// certificates. It runs before the engine so that, with reality_dest self,
// REALITY's handshake target is always a socket this process owns. It returns
// a stop function. A missing certificate is not an error: handshakes fail.
func startSharedHTTPSProxy(ctx context.Context, dir, address string, cfg httpsProxyListenerConfig, proxy *httpsProxy, output io.Writer, warn func(string), fatal chan<- error, stealth *sharedStealth) (func(), error) {
	if cfg.retired() {
		return nil, errors.New(retiredProxy)
	}
	if cfg.method() == "http" {
		busy, err := probeProxyHTTP()
		if busy {
			return nil, errors.New(proxyHTTPBusy)
		}
		if err != nil {
			return nil, fmt.Errorf("cannot probe TCP 80: %w", err)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	var stops []func()
	stop := func() {
		cancel()
		for i := len(stops) - 1; i >= 0; i-- {
			stops[i]()
		}
	}
	var getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if cfg.method() == "files" {
		pem := newProxyPEMCertificates(cfg, warn)
		getCertificate = pem.getCertificate
		if stealth != nil {
			stealth.load = pem.certificateAt
		}
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
		certificates, cache, err := proxyManagedCertificates(dir, cfg, provider, warn)
		if err != nil {
			stop()
			return nil, errors.New("HTTPS proxy could not initialize its certificate storage")
		}
		stops = append(stops, cache.Stop)
		if err := certificates.ManageAsync(ctx, []string{cfg.Domain}); err != nil {
			warn("HTTPS proxy could not start background certificate management")
		}
		getCertificate = certificates.GetCertificate
		if stealth != nil {
			stealth.load = func(time.Time) (*tls.Certificate, error) {
				return cachedCertificate(cache, stealth.verify.DNSName), nil
			}
		}
	}
	if stealth != nil {
		getCertificate = stealth.proxyCertificate(getCertificate)
	}
	server := proxyWebServer(proxy, cfg.Domain, getCertificate)
	failures := make(chan error, 1)
	listener, err := serve(server, address, cfg.Port, failures)
	if err != nil {
		stop()
		return nil, fmt.Errorf("HTTPS proxy could not bind TCP port %d: %v", cfg.Port, err)
	}
	stops = append(stops, func() { _ = listener.Close() })
	fmt.Fprintf(output, "HTTPS proxy listening on %s\n", listener.Addr())
	go watchSharedProxy(ctx, failures, fatal, warn)
	return stop, nil
}

func watchSharedProxy(ctx context.Context, failures <-chan error, fatal chan<- error, warn func(string)) {
	select {
	case <-ctx.Done():
	case err := <-failures:
		if fatal == nil {
			warn("HTTPS proxy listener stopped: " + err.Error())
			return
		}
		select {
		case fatal <- fmt.Errorf("HTTPS proxy listener used by Stealth stopped: %w", err):
		case <-ctx.Done():
		}
	}
}
