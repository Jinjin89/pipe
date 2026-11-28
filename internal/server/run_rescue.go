// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

const rescueCertificateRotation = "Run pipe server setup again with new rescue.cert and rescue.key."

func warnRescueOff(log io.Writer, err error) {
	fmt.Fprintf(log, "Warning: Rescue is OFF: %v\n", err)
}

func rescueCertificateProblem(domain string, cert *tls.Certificate) error {
	if cert == nil || cert.Leaf == nil {
		return fmt.Errorf("waiting for the TLS certificate for %s", domain)
	}
	return pemValidity(cert.Leaf, "Rescue", time.Now())
}

func standaloneRescueTLSConfig(domain string, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), originCA *x509.CertPool, checkCertificate func() error) *tls.Config {
	config := rescueTLSConfig(domain, getCertificate, originCA)
	checkName := config.GetConfigForClient
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if _, err := checkName(hello); err != nil {
			return nil, err
		}
		return nil, checkCertificate()
	}
	return config
}

func rescueExpiryWarning(expires, now time.Time) string {
	if expires.After(now.Add(30 * 24 * time.Hour)) {
		return ""
	}
	status := "expires"
	if !expires.After(now) {
		status = "expired"
	}
	return fmt.Sprintf("Rescue certificate %s at %s. %s", status, expires.UTC().Format(time.RFC3339), rescueCertificateRotation)
}

func startSharedRescue(ctx context.Context, settings Settings, options RunOptions, address string, handler http.Handler, log io.Writer, warn func(string)) (func(), error) {
	if settings.rescueMatchesFastName() {
		return nil, fmt.Errorf("%w. Set a distinct CDN name and certificate with pipe server rescue", errRescueFastName)
	}
	port := settings.sharedRescuePort()
	if port == 0 {
		return nil, errors.New(retiredRescue)
	}
	cert, err := loadRescuePEM(settings, time.Now())
	if err != nil {
		return nil, fmt.Errorf("%w. %s", err, rescueCertificateRotation)
	}
	var originCA *x509.CertPool
	if options.CFOriginCA != "" {
		originCA, err = loadCFOriginCA(options.CFOriginCA)
		if err != nil {
			return nil, err
		}
	}
	failures := make(chan error, 1)
	tcp, err := listenTCP(address, port, net.Listen)
	if err != nil {
		return nil, fmt.Errorf("bind TCP port %d: %w", port, err)
	}
	getCertificate := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }
	listener := serveOn(ctx, webServer(handler, rescueTLSConfig(settings.CDNDomain, getCertificate, originCA)),
		rescueListener{Listener: guardedListener(ctx, tcp, options.overload), allowLoopback: options.TestPorts}, failures, options.overload)
	fmt.Fprintf(log, "Rescue listening on %s\n", listener.Addr())
	checkExpiry := func(now time.Time) {
		if warning := rescueExpiryWarning(cert.Leaf.NotAfter, now); warning != "" {
			warn(warning)
		}
	}
	checkExpiry(time.Now())
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		daily := time.NewTicker(24 * time.Hour)
		defer daily.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-failures:
				warnRescueOff(log, err)
				return
			case now := <-daily.C:
				checkExpiry(now)
			}
		}
	}()
	return func() {
		cancel()
		_ = listener.Close()
	}, nil
}

type rescueListener struct {
	net.Listener
	allowLoopback bool
}

func (l rescueListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if peer, ok := conn.RemoteAddr().(*net.TCPAddr); ok && rescueSourceAllowed(peer.AddrPort().Addr(), l.allowLoopback) {
			return conn, nil
		}
		_ = conn.Close()
	}
}

func rescueSourceAllowed(ip netip.Addr, allowLoopback bool) bool {
	ip = ip.Unmap()
	if allowLoopback && ip.IsLoopback() {
		return true
	}
	for _, prefix := range cloudflareOriginRanges {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func rescueSourceCIDRs(allowLoopback bool) []string {
	prefixes := make([]string, 0, len(cloudflareOriginRanges)+2)
	for _, prefix := range cloudflareOriginRanges {
		prefixes = append(prefixes, prefix.String())
	}
	if allowLoopback {
		prefixes = append(prefixes, "127.0.0.0/8", "::1/128")
	}
	return prefixes
}
