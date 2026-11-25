// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"pipe/internal/engine"
)

func runShared(ctx context.Context, options RunOptions, settings Settings, devices []Device, address string, log io.Writer) error {
	if options.WWW != "" || options.WebUpstream != "" || options.CFOriginCA != "" {
		return errors.New("shared mode leaves website and Cloudflare origin settings to the existing web server. Set a proxy cover with server proxy enable --www")
	}
	page, err := generateCoverSite(settings.RealityPrivateKey)
	if err != nil {
		return err
	}
	initial, err := renewFastCertificate(options.Dir, time.Now())
	if err != nil {
		return err
	}
	serveErrors := make(chan error, 2)
	masquerade, err := serve(webServer(page, nil), "127.0.0.1", 0, serveErrors)
	if err != nil {
		return fmt.Errorf("internal decoy listener: %w", err)
	}
	defer masquerade.Close()
	masqueradePort := masquerade.Addr().(*net.TCPAddr).Port
	var certificate atomic.Pointer[tls.Certificate]
	certificate.Store(initial)
	getCertificate := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return certificate.Load(), nil }
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()
	log = &synchronizedServerLog{writer: log}
	warn := func(message string) { fmt.Fprintln(log, "Warning:", message) }
	workers.Go(func() {
		tick := time.NewTicker(time.Hour)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tick.C:
				pair, err := renewFastCertificate(options.Dir, now)
				if err != nil {
					if now.After(certificate.Load().Leaf.NotAfter) {
						serveErrors <- fmt.Errorf("renew expired Fast certificate: %w", err)
						return
					}
					fmt.Fprintf(log, "Warning: Fast certificate renewal delayed: %v\n", err)
					continue
				}
				certificate.Store(pair)
			}
		}
	})
	var update func([]Device) error
	if cfg := settings.HTTPSProxyListener; cfg != nil {
		var proxyErr error
		cover, err := proxyCover(cfg.WWW, page)
		if err == nil {
			proxy := newHTTPSProxy(cover, devices)
			defer proxy.update(nil)
			var stop func()
			if stop, err = startSharedHTTPSProxy(ctx, options.Dir, address, *cfg, proxy, log, warn); err == nil {
				defer stop()
				update = func(next []Device) error {
					proxy.update(next)
					return nil
				}
			}
		}
		if proxyErr = err; proxyErr != nil {
			warn(proxyErr.Error())
			// Stealth's fallback must be a socket this process owns, or nothing.
			settings.realityBlocked = "the HTTPS proxy that Stealth borrows did not start (" + proxyErr.Error() + ")"
		}
	}
	if err := settings.realityTargetProblem(); err != nil {
		still := "Fast, Rescue and the HTTPS proxy keep running"
		if settings.realityBlocked != "" {
			still = "Fast and Rescue keep running"
		}
		fmt.Fprintf(log, "Error: Stealth is OFF: %v. %s.\n", err, still)
	}
	makeConfig := func(address string, devices []Device) engine.Object {
		return serverConfig(settings, devices, address, masqueradePort, 0, options.TestHosts)
	}
	return runEngine(ctx, options.Dir, settings, address, devices, getCertificate, makeConfig, log, serveErrors, update)
}

type synchronizedServerLog struct {
	mu     sync.Mutex
	writer io.Writer
}

func (l *synchronizedServerLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.writer.Write(p)
}
