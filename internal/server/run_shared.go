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
	"sync"
	"sync/atomic"
	"time"

	"pipe/internal/engine"
)

func runShared(ctx context.Context, options RunOptions, settings Settings, devices []Device, address string, log io.Writer) error {
	if options.CFOriginCA != "" && settings.rescuePort() == 0 {
		fmt.Fprintln(log, "Warning: --cf-origin-ca is unused while shared Rescue is disabled")
	}
	if warning := webUpstreamWarning(options.WebUpstream); warning != "" {
		fmt.Fprintln(log, "Warning:", warning)
	}
	var rescue engine.RescueAuthenticator
	if err := rescue.SetUsers(rescueKeys(devices)); err != nil {
		return err
	}
	decoy, err := makeDecoy(settings, options, rescue.Authenticate)
	if err != nil {
		return err
	}
	initial, err := renewFastCertificate(options.Dir, time.Now())
	if err != nil {
		return err
	}
	serveErrors := make(chan error, 4)
	masquerade, err := serve(webServer(decoy.main, nil), "127.0.0.1", 0, serveErrors)
	if err != nil {
		return fmt.Errorf("internal decoy listener: %w", err)
	}
	defer masquerade.Close()
	listeners := serverListeners{masquerade: masquerade.Addr().(*net.TCPAddr).Port}
	var certificate atomic.Pointer[tls.Certificate]
	certificate.Store(initial)
	getCertificate := fastCertificateForName(settings.fastName(), func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certificate.Load(), nil
	})
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
	var rescueFailed func(error)
	if settings.CDNDomain != "" {
		if warning := RescuePortWarning(settings.sharedRescuePort()); warning != "" {
			warn(warning)
		}
		stop, err := startSharedRescue(ctx, settings, options, address, decoy, log, warn)
		if err != nil {
			warnRescueOff(log, err)
			settings.Rescue = nil
		} else {
			defer stop()
			rescueFailed = func(err error) {
				stop()
				settings.Rescue = nil
				warnRescueOff(log, err)
			}
		}
	}
	var proxy *httpsProxy
	var stealth *sharedStealth
	if cfg := settings.HTTPSProxyListener; cfg != nil {
		var err error
		if cfg.retired() {
			err = errors.New(retiredProxy)
		} else {
			var cover http.Handler
			cover, err = proxyCover(cfg.WWW, decoy.main)
			if err == nil {
				proxy = newHTTPSProxy(cover, devices)
			}
		}
		if proxy != nil {
			var fatal chan<- error
			if settings.realityTargetProblem() == nil {
				fatal = serveErrors
				stealth = newSharedStealth(settings.stealthName(), options.TestCA)
			}
			var stop func()
			stop, err = startSharedHTTPSProxy(ctx, options.Dir, address, *cfg, proxy, log, warn, fatal, stealth)
			if err == nil {
				listeners.borrowProxy = stealth != nil
				defer proxy.update(nil)
				defer stop()
			} else {
				proxy.update(nil)
				proxy = nil
				stealth = nil
			}
		}
		if err != nil {
			warn("HTTPS proxy is OFF: " + err.Error())
			// A failed bind must keep the proxy socket out of the Stealth configuration.
			settings.realityBlocked = "the HTTPS proxy that Stealth borrows did not start (" + err.Error() + ")"
		}
	}
	if err := settings.realityTargetProblem(); err != nil {
		warn("Stealth is OFF: " + err.Error())
	}
	update := func(next []Device) error {
		if proxy != nil {
			proxy.update(next)
		}
		return rescue.SetUsers(rescueKeys(next))
	}
	makeConfig := func(address string, devices []Device) engine.Object {
		return serverConfig(settings, devices, address, listeners, options.TestHosts)
	}
	instance, boundAddress, err := startServerEngine(ctx, address, devices, getCertificate, makeConfig, listeners.borrowProxy, rescueFailed)
	if err != nil {
		return err
	}
	return runEngine(ctx, instance, options.Dir, settings, boundAddress, devices, makeConfig, log, serveErrors, update, stealth)
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
