// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"pipe/internal/engine"
	"pipe/internal/localfile"
)

type decoySite struct {
	main   http.Handler
	static *staticCover
	http.Handler
}

func (s *decoySite) Close() {
	if s.static != nil {
		s.static.dir.Close()
	}
}

func makeDecoy(settings Settings, options RunOptions, authenticate func(context.Context, string) bool) (*decoySite, error) {
	var main, rescue http.Handler
	var static *staticCover
	www, upstream := options.WWW, options.WebUpstream
	switch {
	case www != "" && upstream != "":
		return nil, errors.New("choose either --www or --web-upstream")
	case www != "":
		opened, err := directoryCover(www)
		if err != nil {
			return nil, errors.Join(errors.New("open --www directory"), err)
		}
		main, static = opened, opened
	case upstream != "":
		target, err := url.Parse(upstream)
		if err != nil || target.Host == "" || target.User != nil || target.Fragment != "" ||
			(target.Scheme != "http" && target.Scheme != "https") {
			return nil, errors.New("--web-upstream requires an HTTP or HTTPS URL without credentials or a fragment")
		}
		proxy := reverseProxy(target)
		rewrite := proxy.Rewrite
		proxy.Rewrite = func(r *httputil.ProxyRequest) {
			rewrite(r)
			r.Out.Header.Del(engine.WebSocketEarlyDataHeader)
			r.Out.Header.Del("Hysteria-CC-RX")
			r.Out.Header.Del("Hysteria-Padding")
		}
		main = proxy
	default:
		page, err := generateCoverSite(settings.RealityPrivateKey, mainCoverLabel)
		if err != nil {
			return nil, err
		}
		main = page
	}
	if settings.CDNDomain != "" {
		page, err := generateCoverSite(settings.RealityPrivateKey, rescueCoverLabel)
		if err != nil {
			if static != nil {
				static.dir.Close()
			}
			return nil, err
		}
		rescue = page
	}
	cover := main
	main = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Failed Fast authentication falls through to this HTTP handler.
		// Keep its credential and the reserved Rescue path at this origin.
		if len(r.Header.Values("Hysteria-Auth")) != 0 ||
			(r.Method == http.MethodPost && r.URL.Path == "/auth" && equalDNS(requestHost(r.Host), "hysteria")) ||
			(settings.CDNDomain != "" && r.URL.Path == settings.WSPath) {
			http.NotFound(w, r)
			return
		}
		cover.ServeHTTP(w, r)
	})
	serveSite := func(w http.ResponseWriter, r *http.Request) {
		if rescue != nil && r.TLS != nil && equalDNS(r.TLS.ServerName, settings.CDNDomain) {
			rescue.ServeHTTP(w, r)
		} else {
			main.ServeHTTP(w, r)
		}
	}
	ws := reverseProxy(&url.URL{Scheme: "http", Host: loopback(settings.Ports.VMess)})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if settings.CDNDomain != "" && r.URL.Path == settings.WSPath {
			if r.TLS == nil || !equalDNS(r.TLS.ServerName, settings.CDNDomain) || !equalDNS(requestHost(r.Host), settings.CDNDomain) ||
				!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
				(options.CFOriginCA != "" && len(r.TLS.VerifiedChains) == 0) ||
				authenticate == nil || !authenticate(r.Context(), r.Header.Get(engine.WebSocketEarlyDataHeader)) {
				http.NotFound(w, r)
				return
			}
			ws.ServeHTTP(w, r)
			return
		}
		serveSite(w, r)
	})
	return &decoySite{main: main, static: static, Handler: handler}, nil
}

type staticCover struct {
	dir *os.Root
	http.Handler
}

// directoryCover confines lookup, including symlinks, to the original root.
func directoryCover(path string) (*staticCover, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &staticCover{dir: root, Handler: http.FileServerFS(root.FS())}, nil
}

// webUpstreamWarning explains the cost of a public --web-upstream. Standalone
// shows it to every unauthenticated visitor.
func webUpstreamWarning(upstream string) string {
	target, err := url.Parse(upstream)
	if upstream == "" || err != nil {
		return ""
	}
	host := strings.ToLower(target.Hostname())
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip = ip.Unmap(); ip.IsLoopback() || ip.IsPrivate() {
			return ""
		}
	} else if host == "localhost" {
		return ""
	}
	return "--web-upstream " + host + " is not a loopback or private address. Unauthenticated visitors will be proxied to that site with this server's bandwidth"
}

func loadCFOriginCA(path string) (*x509.CertPool, error) {
	data, err := localfile.Read(path, localfile.MaxConfigBytes, false)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("--cf-origin-ca contains no PEM certificates")
	}
	return pool, nil
}

func reverseProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(target) },
		ModifyResponse: func(r *http.Response) error {
			r.Header.Del("Server")
			r.Header.Del("Alt-Svc")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		},
	}
}

func requestHost(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}

func webServer(handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout: 60 * time.Second, ErrorLog: log.New(io.Discard, "", 0),
	}
}
