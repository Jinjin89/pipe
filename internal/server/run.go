// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"pipe/internal/engine"
)

type RunOptions struct {
	Dir         string
	TestCA      string
	TestPorts   bool
	TestListen  string
	TestHosts   map[string]netip.Addr
	WWW         string
	WebUpstream string
	CFOriginCA  string
	Log         io.Writer
}

func Run(ctx context.Context, options RunOptions) error {
	if len(options.TestHosts) != 0 && options.TestCA == "" {
		return errors.New("--test-hosts requires --test-ca")
	}
	if (options.TestCA != "") != options.TestPorts {
		return errors.New("--test-ca and --test-ports must be used together")
	}
	if options.TestListen != "" && !options.TestPorts {
		return errors.New("--test-listen requires --test-ports")
	}
	settings, err := ReadSettings(options.Dir)
	if err != nil {
		return err
	}
	devices, err := ReadDevices(options.Dir)
	if err != nil {
		return err
	}
	address := "::"
	if options.TestPorts {
		if settings.Mode == Standalone {
			settings.Ports = TestPorts()
		}
		address, err = testListenAddress(options.TestListen)
		if err != nil {
			return err
		}
	}
	log := options.Log
	if log == nil {
		log = io.Discard
	}
	if settings.Mode == Shared {
		return runShared(ctx, options, settings, devices, address, log)
	}
	var originCA *x509.CertPool
	if options.CFOriginCA != "" {
		if settings.CDNDomain == "" {
			return errors.New("--cf-origin-ca requires a configured CDN domain")
		}
		originCA, err = loadCFOriginCA(options.CFOriginCA)
		if err != nil {
			return err
		}
	}
	var rescue engine.RescueAuthenticator
	if settings.CDNDomain != "" {
		if err := rescue.SetUsers(rescueKeys(devices)); err != nil {
			return err
		}
	}
	if warning := webUpstreamWarning(options.WebUpstream); warning != "" {
		fmt.Fprintln(log, "Warning:", warning)
	}
	decoy, err := makeDecoy(settings, options, rescue.Authenticate)
	if err != nil {
		return err
	}
	var getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	var httpHandler = redirectHTTPS(settings)
	var obtain = func(context.Context) error { return nil }
	if options.TestPorts {
		certificate, err := testCertificate(options.TestCA, settings)
		if err != nil {
			return err
		}
		getCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return certificate, nil }
	} else {
		config, issuer, stop, err := managedCertificates(options.Dir, settings)
		if err != nil {
			return err
		}
		defer stop()
		getCertificate = config.GetCertificate
		httpHandler = issuer.HTTPChallengeHandler(httpHandler)
		obtain = func(ctx context.Context) error { return config.ManageSync(ctx, settings.names()) }
	}
	serveErrors := make(chan error, 4)
	redirect, err := serve(webServer(httpHandler, nil), address, settings.Ports.HTTP, serveErrors)
	if err != nil {
		return fmt.Errorf("HTTP redirect listener: %w", err)
	}
	defer redirect.Close()
	if err := obtain(ctx); err != nil {
		return fmt.Errorf("obtain HTTPS certificates: %w", err)
	}
	var proxy *httpsProxy
	tlsSite := decoy
	if settings.proxyEnabled() {
		proxy = newHTTPSProxy(decoy, devices)
		defer proxy.update(nil)
		tlsSite = proxy
	}
	decoyServer := webServer(tlsSite, decoyTLSConfig(settings, getCertificate, originCA))
	website, err := serve(decoyServer, "127.0.0.1", settings.Ports.Decoy, serveErrors)
	if err != nil {
		return fmt.Errorf("decoy HTTPS listener: %w", err)
	}
	defer website.Close()
	masquerade, err := serve(webServer(decoy, nil), "127.0.0.1", 0, serveErrors)
	if err != nil {
		return fmt.Errorf("internal decoy listener: %w", err)
	}
	defer masquerade.Close()
	probe, err := serve(webServer(http.HandlerFunc(serveProbe), nil), "127.0.0.1", 0, serveErrors)
	if err != nil {
		return fmt.Errorf("internal probe listener: %w", err)
	}
	defer probe.Close()
	makeConfig := func(address string, devices []Device) engine.Object {
		return serverConfig(settings, devices, address, masquerade.Addr().(*net.TCPAddr).Port, probe.Addr().(*net.TCPAddr).Port, options.TestHosts)
	}
	update := func(next []Device) error {
		if proxy != nil {
			proxy.update(next)
		}
		if settings.CDNDomain != "" {
			return rescue.SetUsers(rescueKeys(next))
		}
		return nil
	}
	return runEngine(ctx, options.Dir, settings, address, devices, getCertificate, makeConfig, log, serveErrors, update)
}

func runEngine(ctx context.Context, dir string, settings Settings, address string, devices []Device,
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error),
	makeConfig func(string, []Device) engine.Object, log io.Writer, serveErrors <-chan error,
	update func([]Device) error,
) error {
	instance, httpsAddress, err := bindWithIPv4Fallback(address, func(address string) (*engine.Instance, error) {
		instance, err := engine.New(ctx, engine.Options{
			Config: makeConfig(address, devices), GetCertificate: getCertificate, Server: true,
			DeviceIDs: deviceIDs(devices),
		})
		if err != nil {
			return nil, fmt.Errorf("configure server engine: %w", err)
		}
		// The engine closes all partially started listeners if Start fails.
		if err := instance.Start(); err != nil {
			return nil, fmt.Errorf("start server engine: %w", err)
		}
		return instance, nil
	})
	if err != nil {
		return err
	}
	defer instance.Close()
	if settings.Mode == Shared && settings.realityTargetProblem() != nil {
		fmt.Fprintf(log, "Server listening on %s (UDP Fast). Stealth is off\n", addrPort(httpsAddress, settings.fastPort()))
	} else if settings.Mode != Shared && settings.fastPort() == settings.stealthPort() {
		fmt.Fprintf(log, "Server listening on %s (TCP and UDP)\n", addrPort(httpsAddress, settings.fastPort()))
	} else {
		fmt.Fprintf(log, "Server listening on %s (UDP Fast) and %s (TCP Stealth)\n",
			addrPort(httpsAddress, settings.fastPort()), addrPort(httpsAddress, settings.stealthPort()))
	}
	changes := time.NewTicker(500 * time.Millisecond)
	defer changes.Stop()
	var lastWarning string
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-serveErrors:
			return err
		case <-changes.C:
			next, err := ReadDevices(dir)
			if err != nil {
				if message := err.Error(); message != lastWarning {
					fmt.Fprintf(log, "Warning: device reload delayed: %s\n", message)
					lastWarning = message
				}
				continue
			}
			lastWarning = ""
			if slices.Equal(next, devices) {
				continue
			}
			if update != nil {
				if err := update(next); err != nil {
					return fmt.Errorf("reload web authentication: %w", err)
				}
			}
			if err := instance.ReloadInbounds(makeConfig(httpsAddress, next), deviceIDs(next)); err != nil {
				return fmt.Errorf("reload server credentials: %w", err)
			}
			devices = next
			fmt.Fprintf(log, "Reloaded %d device credentials\n", len(devices))
		}
	}
}

func deviceIDs(devices []Device) []string {
	ids := make([]string, len(devices))
	for i, device := range devices {
		ids[i] = device.DeviceID
	}
	return ids
}

func rescueKeys(devices []Device) []string {
	keys := make([]string, len(devices))
	for i, device := range devices {
		keys[i] = device.VMessUUID
	}
	return keys
}

func testListenAddress(raw string) (string, error) {
	if raw == "" {
		return "127.0.0.1", nil
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.Is4() || (!ip.IsLoopback() && !ip.IsPrivate()) {
		return "", errors.New("test listener requires a loopback IPv4 address or a private network namespace address")
	}
	if !ip.IsLoopback() {
		self, selfErr := os.Stat("/proc/self/ns/net")
		initial, initialErr := os.Stat("/proc/1/ns/net")
		if selfErr != nil || initialErr != nil || os.SameFile(self, initial) {
			return "", errors.New("a non-loopback test listener requires a separate Linux network namespace")
		}
	}
	return ip.String(), nil
}

func redirectHTTPS(settings Settings) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := settings.webName()
		if settings.CDNDomain != "" && strings.EqualFold(requestHost(r.Host), settings.CDNDomain) {
			host = settings.CDNDomain
		}
		if settings.stealthPort() != 443 {
			host = addrPort(host, settings.stealthPort())
		}
		target := url.URL{Scheme: "https", Host: host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
		http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
	})
}

func addrPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func loopback(port uint16) string { return addrPort("127.0.0.1", port) }

func serve(server *http.Server, host string, port uint16, failures chan<- error) (net.Listener, error) {
	listener, err := listenTCP(host, port, net.Listen)
	if err != nil {
		return nil, err
	}
	go func() {
		var err error
		if server.TLSConfig != nil {
			err = server.ServeTLS(listener, "", "")
		} else {
			err = server.Serve(listener)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			failures <- fmt.Errorf("web listener %s: %w", listener.Addr(), err)
		}
	}()
	return &webListener{Listener: listener, server: server}, nil
}

type webListener struct {
	net.Listener
	server *http.Server
}

func (l *webListener) Close() error {
	// Close both sides in case shutdown races the Serve goroutine's startup.
	err := l.server.Close()
	_ = l.Listener.Close()
	return err
}

func serverConfig(settings Settings, devices []Device, address string, masqueradePort, probePort int, testHosts map[string]netip.Addr) engine.Object {
	vlessUsers := make([]engine.Object, 0, len(devices))
	fastUsers := make([]engine.Object, 0, len(devices))
	rescueUsers := make([]engine.Object, 0, len(devices))
	shortIDs := make([]string, 0, len(devices))
	for _, device := range devices {
		vlessUsers = append(vlessUsers, engine.Object{"name": device.DeviceID, "uuid": device.VLESSUUID, "flow": "xtls-rprx-vision"})
		fastUsers = append(fastUsers, engine.Object{"name": device.DeviceID, "password": device.HY2Password})
		rescueUsers = append(rescueUsers, engine.Object{"name": device.DeviceID, "uuid": device.VMessUUID, "alterId": 0})
		shortIDs = append(shortIDs, device.RealitySID)
	}
	if len(shortIDs) == 0 {
		// An empty list enables the all-zero short ID in sing-box.
		emptySID := sha256.Sum256([]byte("pipe/empty/reality-sid/" + settings.RealityPrivateKey))
		shortIDs = []string{hex.EncodeToString(emptySID[:8])}
	}
	realityHandshake := engine.Object{"server": "127.0.0.1", "server_port": settings.Ports.Decoy}
	if settings.HTTPSProxyListener != nil {
		// Shared mode: always our own HTTPS proxy site, whatever the saved address
		// says, reached where it listens (loopback when it listens on every address).
		proxyHost := "127.0.0.1"
		if ip, err := netip.ParseAddr(address); err == nil && !ip.IsUnspecified() {
			proxyHost = ip.String()
		}
		realityHandshake = engine.Object{"server": proxyHost, "server_port": settings.HTTPSProxyListener.Port}
	}
	realityInbound := func(name, tag, listen string, port uint16) engine.Object {
		return engine.Object{
			"type": "vless", "tag": tag, "listen": listen, "listen_port": port, "users": vlessUsers,
			"tls": engine.Object{
				"enabled": true, "server_name": name,
				"reality": engine.Object{
					"enabled": true, "private_key": settings.RealityPrivateKey, "short_id": shortIDs,
					"max_time_difference": "1m",
					"handshake":           realityHandshake,
				},
			},
		}
	}
	masquerade := engine.Object{"type": "proxy", "url": "http://127.0.0.1:" + strconv.Itoa(masqueradePort), "rewrite_host": false}
	inbounds := []engine.Object{{
		"type": "hysteria2", "tag": "fast", "listen": address, "listen_port": settings.fastPort(), "users": fastUsers,
		"bbr_profile": "standard", "ignore_client_bandwidth": true,
		"tls":        engine.Object{"enabled": true, "certificate_provider": engine.Object{"type": engine.SharedCertificate}},
		"masquerade": masquerade,
	}}
	outbounds := []engine.Object{{"type": "direct", "tag": "direct"}, {"type": "direct", "tag": "probe-direct"}}
	var routeRules []engine.Object
	switch {
	case settings.Mode == Shared && settings.realityTargetProblem() != nil:
		// Stealth stays off. Fast, Rescue and the HTTPS proxy are unaffected.
	case settings.Mode == Shared:
		// The fallback is our own HTTPS proxy site, so any SNI gets that site's strict answer.
		inbounds = append(inbounds, realityInbound(strings.ToLower(settings.RealitySNI), "stealth", address, settings.stealthPort()))
	case settings.CDNDomain == "":
		inbounds = append(inbounds, realityInbound(settings.webName(), "stealth", address, settings.stealthPort()))
	default:
		// The pinned REALITY inlet accepts one server name. Use sing-box's
		// TLS sniffer to forward the original bytes to the corresponding inlet.
		inbounds = append(inbounds,
			realityInbound(settings.webName(), "stealth", "127.0.0.1", settings.Ports.RealityOrigin),
			realityInbound(settings.CDNDomain, "stealth-cdn", "127.0.0.1", settings.Ports.RealityCDN),
			engine.Object{"type": "direct", "tag": engine.RealityFrontTag, "listen": address, "listen_port": settings.stealthPort(), "network": "tcp"},
		)
		outbounds = append(outbounds, engine.Object{"type": "direct", "tag": "front-direct"})
		routeRules = append(routeRules,
			engine.Object{"inbound": engine.RealityFrontTag, "action": "sniff", "sniffer": "tls", "timeout": "500ms"},
			engine.Object{"inbound": engine.RealityFrontTag, "protocol": "tls", "domain": settings.CDNDomain, "outbound": "front-direct", "override_address": "127.0.0.1", "override_port": settings.Ports.RealityCDN},
			engine.Object{"inbound": engine.RealityFrontTag, "protocol": "tls", "domain": settings.webName(), "outbound": "front-direct", "override_address": "127.0.0.1", "override_port": settings.Ports.RealityOrigin},
			// sing-box replays the buffered bytes, including partial ClientHellos.
			engine.Object{"inbound": engine.RealityFrontTag, "outbound": "front-direct", "override_address": "127.0.0.1", "override_port": settings.Ports.Decoy},
		)
	}
	if settings.CDNDomain != "" && settings.Mode == Shared {
		inbounds = append(inbounds, engine.Object{
			"type": engine.SharedRescue, "tag": "rescue", "listen": settings.RescueListen,
			"host": settings.CDNDomain, "path": settings.WSPath, "users": rescueUsers,
		})
	} else if settings.CDNDomain != "" {
		inbounds = append(inbounds, engine.Object{
			"type": "vmess", "tag": "rescue", "listen": "127.0.0.1", "listen_port": settings.Ports.VMess, "users": rescueUsers,
			"transport": engine.Object{
				"type": "ws", "path": settings.WSPath, "max_early_data": engine.WebSocketEarlyDataLimit, "early_data_header_name": engine.WebSocketEarlyDataHeader,
			},
		})
	}
	probe := engine.Object{
		"domain": engine.ProbeDomain, "network": "tcp", "port": 80,
		"outbound": "probe-direct", "override_address": "127.0.0.1", "override_port": probePort,
	}
	if settings.Mode == Shared {
		outbounds[1]["type"] = engine.InMemoryProbe
		delete(probe, "override_address")
		delete(probe, "override_port")
	}
	routeRules = append(routeRules, probe)
	dnsServers := []engine.Object{{"type": "local", "tag": "local"}}
	localResolve := engine.Object{"action": "resolve", "server": "local"}
	if len(testHosts) != 0 {
		names := slices.Sorted(maps.Keys(testHosts))
		dnsServers = append(dnsServers, engine.Object{"type": "hosts", "tag": engine.TestHostsTag, "predefined": testHosts})
		routeRules = append(routeRules, engine.Object{"domain": names, "action": "resolve", "server": engine.TestHostsTag})
		localResolve["domain"] = names
		localResolve["invert"] = true
	}
	routeRules = append(routeRules, localResolve)
	return engine.Object{
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"dns":       engine.Object{"servers": dnsServers, "final": "local"},
		"route": engine.Object{
			"rules": routeRules,
			"final": "direct", "default_domain_resolver": "local",
		},
	}
}
