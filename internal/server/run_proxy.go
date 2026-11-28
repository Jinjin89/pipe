// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"pipe/internal/overload"

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

func proxyWebServer(handler http.Handler, domain string, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *http.Server {
	// HTTP/1.1 absolute-form forwarding preserves the requested origin scheme.
	// Go's HTTP/2 handler cannot distinguish HTTP and HTTPS forwards.
	server := webServer(handler, strictProxyTLS(domain, getCertificate))
	server.Protocols = new(http.Protocols)
	server.Protocols.SetHTTP1(true)
	return server
}

const stealthCoverLimit = 32

type sharedProxyListeners struct {
	stop        func()
	stealthPort uint16
}

// startSharedHTTPSProxy binds the public proxy and, when Stealth borrows its
// site, the private REALITY handshake target. It starts certificate management
// before the engine starts, with handshakes available once a certificate is ready.
func startSharedHTTPSProxy(ctx context.Context, dir, address string, cfg httpsProxyListenerConfig, proxy *httpsProxy, output io.Writer, warn func(string), fatal chan<- error, stealth *sharedStealth) (sharedProxyListeners, error) {
	if cfg.retired() {
		return sharedProxyListeners{}, errors.New(retiredProxy)
	}
	if cfg.method() == "http" {
		busy, err := probeProxyHTTP()
		if busy {
			return sharedProxyListeners{}, errors.New(proxyHTTPBusy)
		}
		if err != nil {
			return sharedProxyListeners{}, fmt.Errorf("cannot probe TCP 80: %w", err)
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
				return sharedProxyListeners{}, errors.New("HTTPS proxy could not load its saved DNS credentials")
			}
			provider = savedProvider
		}
		certificates, cache, err := proxyManagedCertificates(dir, cfg, provider, warn)
		if err != nil {
			stop()
			return sharedProxyListeners{}, errors.New("HTTPS proxy could not initialize its certificate storage")
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
	failures := make(chan error, 2)
	var guard *overload.Guard
	if proxy != nil {
		guard = proxy.guard
	}
	listener, err := serve(ctx, server, address, cfg.Port, failures, guard, true)
	if err != nil {
		stop()
		return sharedProxyListeners{}, fmt.Errorf("HTTPS proxy could not bind TCP port %d: %v", cfg.Port, err)
	}
	stops = append(stops, func() { _ = listener.Close() })
	var stealthPort uint16
	if stealth != nil {
		// REALITY's local handshake must still reach the cover during an emergency.
		raw, err := listenTCP("127.0.0.1", 0, net.Listen)
		if err != nil {
			stop()
			return sharedProxyListeners{}, fmt.Errorf("Stealth cover could not bind loopback: %w", err)
		}
		stealthPort = uint16(raw.Addr().(*net.TCPAddr).Port)
		limited := emergencyLimitListener(raw, guard, stealthCoverLimit)
		context.AfterFunc(ctx, func() { _ = limited.Close() })
		coverServer := proxyWebServer(proxy.site, cfg.Domain, getCertificate)
		coverServer.WriteTimeout = 10 * time.Second
		coverServer.IdleTimeout = 5 * time.Second
		coverServer.SetKeepAlivesEnabled(false)
		cover := serveOn(ctx, coverServer, limited, failures, nil)
		stops = append(stops, func() { _ = cover.Close() })
	}
	fmt.Fprintf(output, "HTTPS proxy listening on %s\n", listener.Addr())
	go watchSharedProxy(ctx, failures, fatal, warn)
	return sharedProxyListeners{stop: stop, stealthPort: stealthPort}, nil
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
