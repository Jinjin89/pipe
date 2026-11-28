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
	"sync"
	"sync/atomic"
	"time"

	"pipe/internal/engine"
	"pipe/internal/overload"
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
	FastCert    string
	BlockEgress []netip.Addr
	Log         io.Writer

	egress   *engine.EgressPolicy
	overload *overload.Guard
}

type serverListeners struct {
	masquerade         int
	mainTLS, rescueTLS uint16
	stealthCover       uint16
	borrowProxy        bool
	allowLoopback      bool
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
	options.egress = newServerEgressPolicy(settings, options.BlockEgress)
	ctx = engine.WithEgressPolicy(ctx, options.egress)
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
	overload.ConfigureMemoryLimit()
	if options.overload == nil {
		options.overload = overload.New(overload.Options{})
		options.overload.Start(ctx)
		defer options.overload.Close()
	}
	if settings.Mode == Shared {
		return runShared(ctx, options, settings, devices, address, log)
	}
	if options.FastCert != "" {
		return errors.New("--fast-cert requires shared mode")
	}
	return runStandalone(ctx, options, settings, devices, address, log)
}

func newServerEgressPolicy(settings Settings, extra []netip.Addr) *engine.EgressPolicy {
	blocked := slices.Concat(settings.BlockEgressIPs, extra)
	if literal, err := netip.ParseAddr(settings.Domain); err == nil {
		blocked = append(blocked, literal)
	}
	return engine.NewEgressPolicy(blocked...)
}

func runStandalone(ctx context.Context, options RunOptions, settings Settings, devices []Device, address string, log io.Writer) error {
	disableRescue := func(err error) {
		settings.CDNDomain = ""
		warnRescueOff(log, err)
	}
	if settings.rescueMatchesFastName() {
		disableRescue(fmt.Errorf("%w. Set a distinct rescue.sni in setup JSON", errRescueFastName))
	}
	if !options.TestPorts {
		if warning := RescuePortWarning(settings.rescuePort()); warning != "" {
			fmt.Fprintln(log, "Warning:", warning)
		}
	}
	var originCA *x509.CertPool
	if options.CFOriginCA != "" {
		if settings.rescuePort() == 0 {
			fmt.Fprintln(log, "Warning: --cf-origin-ca is unused while standalone Rescue is disabled")
		} else {
			var err error
			originCA, err = loadCFOriginCA(options.CFOriginCA)
			if err != nil {
				disableRescue(fmt.Errorf("load --cf-origin-ca: %w", err))
			}
		}
	}
	var rescue engine.RescueAuthenticator
	if settings.rescuePort() != 0 {
		if err := rescue.SetUsers(rescueKeys(devices)); err != nil {
			disableRescue(fmt.Errorf("configure Rescue authentication: %w", err))
		}
	}
	if warning := webUpstreamWarning(options.WebUpstream); warning != "" {
		fmt.Fprintln(log, "Warning:", warning)
	}
	decoy, err := makeDecoy(settings, options, rescue.Authenticate)
	if err != nil {
		return err
	}
	defer decoy.Close()
	var getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	var currentCertificate func(string) *tls.Certificate
	var httpHandler = redirectHTTPS(settings)
	var obtain = func(context.Context) error { return nil }
	if options.TestPorts {
		certificates, err := testCertificates(options.TestCA, settings.mainNames())
		if err != nil {
			return err
		}
		if name := strings.ToLower(settings.CDNDomain); name != "" && certificates[name] == nil {
			cdn, err := testCertificates(options.TestCA, []string{name})
			if err != nil {
				disableRescue(fmt.Errorf("prepare Rescue test certificate: %w", err))
			} else {
				certificates[name] = cdn[name]
			}
		}
		currentCertificate = func(name string) *tls.Certificate { return certificates[strings.ToLower(name)] }
		getCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if cert := currentCertificate(hello.ServerName); cert != nil {
				return cert, nil
			}
			return nil, errTLSName
		}
	} else {
		config, issuer, cache, err := managedCertificates(options.Dir, settings)
		if err != nil {
			return err
		}
		defer cache.Stop()
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		getCertificate = config.GetCertificate
		currentCertificate = func(name string) *tls.Certificate { return cachedCertificate(cache, name) }
		httpHandler = issuer.HTTPChallengeHandler(httpHandler)
		obtain = func(ctx context.Context) error { return manageStandaloneCertificates(ctx, config, settings, log) }
	}
	serveErrors := make(chan error, 4)
	redirect, err := serve(ctx, webServer(httpHandler, nil), address, settings.Ports.HTTP, serveErrors, options.overload, true)
	if err != nil {
		return fmt.Errorf("HTTP redirect listener: %w", err)
	}
	defer redirect.Close()
	if err := obtain(ctx); err != nil {
		return fmt.Errorf("obtain HTTPS certificates: %w", err)
	}
	var proxy *httpsProxy
	decoyServer := webServer(decoy.main, strictSiteTLS(settings.webName(), getCertificate))
	if settings.proxyEnabled() {
		proxy = newHTTPSProxy(decoy.main, devices)
		proxy.policy, proxy.guard = options.egress, options.overload
		defer proxy.update(nil)
		decoyServer = proxyWebServer(proxy, settings.webName(), getCertificate)
	}
	website, err := serve(ctx, decoyServer, "127.0.0.1", settings.Ports.Decoy, serveErrors, options.overload, false)
	if err != nil {
		return fmt.Errorf("decoy HTTPS listener: %w", err)
	}
	defer website.Close()
	listeners := serverListeners{mainTLS: settings.Ports.Decoy, allowLoopback: options.TestPorts}
	var rescueFailed func(error)
	var checkRescueCertificate func() error
	if settings.rescuePort() != 0 {
		// Only the source-restricted CDN front route can reach this private TLS site.
		domain := settings.CDNDomain
		checkRescueCertificate = func() error {
			return rescueCertificateProblem(domain, currentCertificate(domain))
		}
		cdnTLS := standaloneRescueTLSConfig(domain, getCertificate, originCA, checkRescueCertificate)
		cdn, err := serve(ctx, webServer(decoy, cdnTLS), "127.0.0.1", 0, serveErrors, options.overload, false)
		if err != nil {
			disableRescue(fmt.Errorf("internal Rescue TLS listener: %w", err))
		} else {
			defer cdn.Close()
			listeners.rescueTLS = uint16(cdn.Addr().(*net.TCPAddr).Port)
			rescueFailed = func(err error) {
				_ = cdn.Close()
				disableRescue(err)
			}
		}
	}
	masquerade, err := serve(ctx, webServer(decoy.main, nil), "127.0.0.1", 0, serveErrors, options.overload, false)
	if err != nil {
		return fmt.Errorf("internal decoy listener: %w", err)
	}
	defer masquerade.Close()
	listeners.masquerade = masquerade.Addr().(*net.TCPAddr).Port
	makeConfig := func(address string, devices []Device) engine.Object {
		return serverConfig(settings, devices, address, listeners, options.TestHosts)
	}
	update := func(next []Device) error {
		if proxy != nil {
			proxy.update(next)
		}
		if settings.rescuePort() != 0 {
			return rescue.SetUsers(rescueKeys(next))
		}
		return nil
	}
	instance, boundAddress, err := startServerEngine(ctx, address, devices, fastCertificateForName(settings.fastName(), getCertificate), makeConfig, false, rescueFailed, options.overload)
	if err != nil {
		return err
	}
	if settings.rescuePort() != 0 {
		if err := checkRescueCertificate(); err != nil {
			warnRescueOff(log, err)
		}
	}
	return runEngine(ctx, instance, options.Dir, settings, boundAddress, devices, makeConfig, log, serveErrors, update, nil)
}

func startServerEngine(ctx context.Context, address string, devices []Device,
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error),
	makeConfig func(string, []Device) engine.Object,
	pauseStealth bool,
	rescueFailed func(error),
	guard *overload.Guard,
) (*engine.Instance, string, error) {
	start := func(address string) (*engine.Instance, error) {
		instance, err := engine.New(ctx, engine.Options{
			Config: makeConfig(address, devices), GetCertificate: getCertificate, Server: true,
			DeviceIDs: deviceIDs(devices), Overload: guard,
		})
		if err != nil {
			return nil, fmt.Errorf("configure server engine: %w", err)
		}
		if pauseStealth {
			// Keep the inbound configured for credential reloads while its socket stays closed.
			if err := instance.SetInboundEnabled("stealth", false); err != nil {
				instance.Close()
				return nil, err
			}
		}
		// The engine closes all partially started listeners if Start fails.
		if err := instance.Start(); err != nil {
			return nil, fmt.Errorf("start server engine: %w", err)
		}
		return instance, nil
	}
	instance, boundAddress, err := bindWithIPv4Fallback(address, start)
	if err == nil || rescueFailed == nil || ctx.Err() != nil {
		return instance, boundAddress, err
	}
	rescueFailed(err)
	instance, boundAddress, retryErr := bindWithIPv4Fallback(address, start)
	if retryErr != nil {
		return nil, boundAddress, errors.Join(err, fmt.Errorf("start without Rescue: %w", retryErr))
	}
	return instance, boundAddress, nil
}

func runEngine(ctx context.Context, instance *engine.Instance, dir string, settings Settings, address string, devices []Device,
	makeConfig func(string, []Device) engine.Object, log io.Writer, serveErrors <-chan error,
	update func([]Device) error, stealth *sharedStealth,
) error {
	defer instance.Close()
	warn := func(message string) { fmt.Fprintln(log, "Warning:", message) }
	stealthListening := settings.Mode != Shared
	if stealth != nil {
		var err error
		stealthListening, err = stealth.refresh(instance, warn)
		if err != nil {
			return err
		}
	}
	switch {
	case !stealthListening:
		fmt.Fprintf(log, "Server listening on %s (UDP Fast)\n", addrPort(address, settings.fastPort()))
	case settings.Mode != Shared && settings.fastPort() == settings.stealthPort():
		fmt.Fprintf(log, "Server listening on %s (TCP and UDP)\n", addrPort(address, settings.fastPort()))
	default:
		fmt.Fprintf(log, "Server listening on %s (UDP Fast) and %s (TCP Stealth)\n",
			addrPort(address, settings.fastPort()), addrPort(address, settings.stealthPort()))
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
			if stealth != nil {
				active, err := stealth.refresh(instance, warn)
				if err != nil {
					return err
				}
				if active && !stealthListening {
					fmt.Fprintf(log, "Stealth listening on %s\n", addrPort(address, settings.stealthPort()))
				}
				stealthListening = active
			}
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
			if err := instance.ReloadInbounds(makeConfig(address, next), deviceIDs(next)); err != nil {
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
		if !equalDNS(requestHost(r.Host), host) {
			http.NotFound(w, r)
			return
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

func serve(ctx context.Context, server *http.Server, host string, port uint16, failures chan<- error, guard *overload.Guard, public bool) (net.Listener, error) {
	listener, err := listenTCP(host, port, net.Listen)
	if err != nil {
		return nil, err
	}
	if public {
		listener = guardedListener(ctx, listener, guard)
	}
	return serveOn(ctx, server, listener, failures, guard), nil
}

func serveOn(ctx context.Context, server *http.Server, listener net.Listener, failures chan<- error, guard *overload.Guard) net.Listener {
	web := &webListener{Listener: listener, server: server}
	if guard != nil {
		var mu sync.Mutex
		mu.Lock()
		var pressured bool
		web.stopPressure = guard.OnPressure(func(next bool) {
			mu.Lock()
			defer mu.Unlock()
			if next != pressured && !web.closing.Load() {
				pressured = next
				server.SetKeepAlivesEnabled(!next)
			}
		})
		if pressured = guard.Diagnostics().Pressured; pressured {
			server.SetKeepAlivesEnabled(false)
		}
		mu.Unlock()
	}
	go func() {
		if web.stopPressure != nil {
			defer web.stopPressure()
		}
		var err error
		if server.TLSConfig != nil {
			err = server.ServeTLS(listener, "", "")
		} else {
			err = server.Serve(listener)
		}
		if err != nil && !web.closing.Load() && ctx.Err() == nil {
			select {
			case failures <- fmt.Errorf("web listener %s: %w", listener.Addr(), err):
			case <-ctx.Done():
			}
		}
	}()
	return web
}

type webListener struct {
	net.Listener
	server       *http.Server
	closing      atomic.Bool
	stopPressure func()
}

func (l *webListener) Close() error {
	// Close both sides in case shutdown races the Serve goroutine's startup.
	l.closing.Store(true)
	if l.stopPressure != nil {
		l.stopPressure()
	}
	err := l.server.Close()
	_ = l.Listener.Close()
	return err
}

func serverConfig(settings Settings, devices []Device, address string, listeners serverListeners, testHosts map[string]netip.Addr) engine.Object {
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
	realityHandshake := engine.Object{"server": "127.0.0.1", "server_port": listeners.mainTLS}
	realityInbound := func(name, tag, listen string, port uint16, handshake engine.Object) engine.Object {
		return engine.Object{
			"type": "vless", "tag": tag, "listen": listen, "listen_port": port, "users": vlessUsers,
			"tls": engine.Object{
				"enabled": true, "server_name": name,
				"reality": engine.Object{
					"enabled": true, "private_key": settings.RealityPrivateKey, "short_id": shortIDs,
					"max_time_difference": "1m",
					"handshake":           handshake,
				},
			},
		}
	}
	masquerade := engine.Object{"type": "proxy", "url": "http://127.0.0.1:" + strconv.Itoa(listeners.masquerade), "rewrite_host": false}
	inbounds := []engine.Object{{
		"type": "hysteria2", "tag": "fast", "listen": address, "listen_port": settings.fastPort(), "users": fastUsers,
		"bbr_profile": "standard", "ignore_client_bandwidth": true,
		"tls":        engine.Object{"enabled": true, "certificate_provider": engine.Object{"type": engine.SharedCertificate}},
		"masquerade": masquerade,
	}}
	outbounds := []engine.Object{{"type": "direct", "tag": "direct"}, {"type": engine.InMemoryProbe, "tag": "probe-direct"}}
	var routeRules []engine.Object
	switch {
	case settings.Mode == Shared && listeners.borrowProxy:
		host, port := "127.0.0.1", listeners.stealthCover
		if port == 0 {
			port = settings.HTTPSProxyListener.Port
			if ip, err := netip.ParseAddr(address); err == nil && !ip.IsUnspecified() {
				host = ip.String()
			}
		}
		handshake := engine.Object{"server": host, "server_port": port}
		inbounds = append(inbounds, realityInbound(settings.stealthName(), "stealth", address, settings.stealthPort(), handshake))
	case settings.Mode == Shared:
		// Stealth requires a running HTTPS proxy.
	case settings.rescuePort() == 0:
		inbounds = append(inbounds, realityInbound(settings.webName(), "stealth", address, settings.stealthPort(), realityHandshake))
	default:
		// The pinned REALITY inlet accepts one server name. Use sing-box's
		// TLS sniffer to forward the original bytes to the corresponding inlet.
		inbounds = append(inbounds,
			realityInbound(settings.webName(), "stealth", "127.0.0.1", settings.Ports.RealityOrigin, realityHandshake),
			realityInbound(settings.CDNDomain, "stealth-cdn", "127.0.0.1", settings.Ports.RealityCDN,
				engine.Object{"server": "127.0.0.1", "server_port": listeners.rescueTLS}),
			engine.Object{"type": "direct", "tag": engine.RealityFrontTag, "listen": address, "listen_port": settings.stealthPort(), "network": "tcp"},
		)
		outbounds = append(outbounds, engine.Object{"type": "direct", "tag": "front-direct"})
		routeRules = append(routeRules,
			engine.Object{"inbound": engine.RealityFrontTag, "action": "sniff", "sniffer": "tls", "timeout": "500ms"},
			engine.Object{"inbound": engine.RealityFrontTag, "protocol": "tls", "domain": settings.CDNDomain,
				"source_ip_cidr": rescueSourceCIDRs(listeners.allowLoopback), "outbound": "front-direct",
				"override_address": "127.0.0.1", "override_port": settings.Ports.RealityCDN},
			engine.Object{"inbound": engine.RealityFrontTag, "protocol": "tls", "domain": settings.webName(), "outbound": "front-direct", "override_address": "127.0.0.1", "override_port": settings.Ports.RealityOrigin},
			// The fallback accepts the main name only, including if sniffing timed out.
			engine.Object{"inbound": engine.RealityFrontTag, "outbound": "front-direct", "override_address": "127.0.0.1", "override_port": listeners.mainTLS},
		)
	}
	if settings.rescuePort() != 0 {
		inbounds = append(inbounds, engine.Object{
			"type": "vmess", "tag": "rescue", "listen": "127.0.0.1", "listen_port": settings.Ports.VMess, "users": rescueUsers,
			"transport": engine.Object{
				"type": "ws", "path": settings.WSPath, "max_early_data": engine.WebSocketEarlyDataLimit, "early_data_header_name": engine.WebSocketEarlyDataHeader,
			},
		})
	}
	routeRules = append(routeRules, engine.Object{
		"domain": engine.ProbeDomain, "network": "tcp", "port": 80, "outbound": "probe-direct",
	})
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
