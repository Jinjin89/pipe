// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"pipe/internal/engine"
	"pipe/internal/link"
	"pipe/internal/overload"
)

const (
	proxyIdleTimeout  = 60 * time.Second
	proxyFailureLimit = 4096
)

type httpsProxy struct {
	site   http.Handler
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	now    func() time.Time
	policy interface{ AllowsFresh(netip.Addr) bool }
	guard  *overload.Guard

	mu       sync.Mutex
	devices  map[string]*proxyDevice
	failures map[netip.Addr]proxyFailure
}

type proxyDevice struct {
	id     string
	key    [sha256.Size]byte
	active map[uint64]context.CancelFunc
	serial uint64
}

type proxyFailure struct {
	last, until time.Time
	count       int
}

func newHTTPSProxy(site http.Handler, devices []Device) *httpsProxy {
	p := &httpsProxy{
		site: site, now: time.Now, lookup: net.DefaultResolver.LookupNetIP,
		dial:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		policy:   engine.NewEgressPolicy(),
		failures: make(map[netip.Addr]proxyFailure),
	}
	p.update(devices)
	return p
}

func (p *httpsProxy) update(next []Device) {
	p.mu.Lock()
	defer p.mu.Unlock()
	devices := make(map[string]*proxyDevice, len(next))
	for _, d := range next {
		if d.HTTPSProxyPassword == "" {
			continue
		}
		key := sha256.Sum256([]byte(d.HTTPSProxyPassword))
		current := p.devices[d.Name]
		if current != nil && current.key == key && current.id == d.DeviceID {
			devices[d.Name] = current
		} else {
			devices[d.Name] = &proxyDevice{id: d.DeviceID, key: key, active: make(map[uint64]context.CancelFunc)}
		}
	}
	for name, d := range p.devices {
		if d != devices[name] {
			for _, cancel := range d.active {
				cancel()
			}
		}
	}
	p.devices = devices
}

func (p *httpsProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Proxy-Authorization")
	r.Header.Del("Proxy-Authorization")
	if header == "" {
		p.site.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodConnect && !r.URL.IsAbs() && r.ProtoMajor < 2 {
		p.site.ServeHTTP(w, r)
		return
	}
	peer, _ := netip.ParseAddrPort(r.RemoteAddr)
	name, password := proxyCredentials(header)
	ctx, finish, accepted := p.acquire(r.Context(), peer.Addr(), name, password)
	if !accepted {
		p.site.ServeHTTP(w, r)
		return
	}
	var lease *overload.Lease
	defer func() {
		finish()
		lease.Release()
	}()
	var err error
	if p.guard != nil {
		lease, err = p.guard.Acquire(ctx, overload.ClassFlow)
	}
	if err != nil || ctx.Err() != nil {
		if r.Context().Err() != nil {
			return
		}
		if errors.Is(err, overload.ErrOverloaded) {
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(p.guard.RetryAfter().Seconds()))))
		}
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if lease != nil {
		ctx = overload.WithLease(ctx, lease)
	}
	r = r.WithContext(ctx)
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	// Go may expose only the authority and path of an HTTP/2 request. An
	// authenticated forward needs an explicit origin scheme to select TLS.
	if !r.URL.IsAbs() {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	p.forward(w, r)
}

func proxyCredentials(header string) (string, string) {
	scheme, body, _ := strings.Cut(header, " ")
	if !strings.EqualFold(scheme, "Basic") || len(body) > 256 {
		return "", ""
	}
	data, err := base64.StdEncoding.Strict().DecodeString(body)
	if err != nil {
		return "", ""
	}
	separator := strings.LastIndexByte(string(data), ':')
	if separator < 1 {
		return "", ""
	}
	return string(data[:separator]), string(data[separator+1:])
}

func (p *httpsProxy) acquire(ctx context.Context, peer netip.Addr, name, password string) (context.Context, func(), bool) {
	presented := sha256.Sum256([]byte(password))
	peer = peer.Unmap()
	// REALITY opens a loopback connection for every fallback client.
	trackFailures := peer.IsValid() && !peer.IsLoopback()
	p.mu.Lock()
	defer p.mu.Unlock()
	var now time.Time
	var failure proxyFailure
	if trackFailures {
		now = p.now()
		failure = p.failures[peer]
		if now.Before(failure.until) {
			return nil, nil, false
		}
	}
	device := p.devices[name]
	var expected [sha256.Size]byte
	if device != nil {
		expected = device.key
	}
	if subtle.ConstantTimeCompare(presented[:], expected[:]) != 1 || device == nil {
		if trackFailures {
			p.recordFailure(peer, now, failure)
		}
		return nil, nil, false
	}
	delete(p.failures, peer)
	device.serial++
	id := device.serial
	ctx, cancel := context.WithCancel(ctx)
	device.active[id] = cancel
	return ctx, func() {
		cancel()
		p.mu.Lock()
		delete(device.active, id)
		p.mu.Unlock()
	}, true
}

func (p *httpsProxy) recordFailure(peer netip.Addr, now time.Time, entry proxyFailure) {
	if len(p.failures) >= proxyFailureLimit && entry.last.IsZero() {
		var oldest netip.Addr
		var first time.Time
		for address, failure := range p.failures {
			if now.Sub(failure.last) >= 2*time.Minute {
				delete(p.failures, address)
			} else if first.IsZero() || failure.last.Before(first) {
				first, oldest = failure.last, address
			}
		}
		if len(p.failures) >= proxyFailureLimit {
			delete(p.failures, oldest)
		}
	}
	if now.Sub(entry.last) >= 2*time.Minute {
		entry.count = 0
	}
	entry.last = now
	entry.count = min(entry.count+1, 9)
	if entry.count >= 3 {
		entry.until = now.Add(time.Second << (entry.count - 3))
	}
	p.failures[peer] = entry
}

func (p *httpsProxy) dialPublic(ctx context.Context, network, address string) (conn net.Conn, err error) {
	defer func() {
		if lease := overload.LeaseFromContext(ctx); lease != nil {
			lease.DialDone(conn != nil && err == nil)
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("proxy requires TCP")
	}
	host, port, err := net.SplitHostPort(address)
	n, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || n == 0 || !link.ValidHost(host) {
		return nil, errors.New("invalid proxy destination")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ip, err := netip.ParseAddr(host)
	addresses := []netip.Addr{ip}
	if err != nil {
		addresses, err = p.lookup(ctx, "ip", host)
		if err != nil || len(addresses) == 0 {
			if p.guard != nil {
				p.guard.ObserveError(err)
			}
			return nil, errors.New("proxy destination DNS lookup failed")
		}
	}
	check := p.policy.AllowsFresh
	if fresh, ok := p.policy.(interface{ NewFreshCheck() func(netip.Addr) bool }); ok {
		check = fresh.NewFreshCheck()
	}
	for _, ip := range addresses {
		if !check(ip) {
			return nil, errors.New("restricted proxy destination")
		}
	}
	for i, ip := range dialOrder(addresses) {
		if i > 0 && !p.policy.AllowsFresh(ip) {
			return nil, errors.New("restricted proxy destination")
		}
		// Give each address its own short budget so a black-holed family
		// (for example broken IPv6 on the server) cannot use up the whole
		// timeout before the other family is tried.
		attempt, stop := context.WithTimeout(ctx, proxyDialAttempt)
		if err := attempt.Err(); err != nil {
			stop()
			return nil, err
		}
		conn, err = p.dial(attempt, network, net.JoinHostPort(ip.Unmap().String(), port))
		stop()
		if err == nil {
			return conn, nil
		}
		if p.guard != nil {
			p.guard.ObserveError(err)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.New("proxy destination connection failed")
}

const proxyDialAttempt = 2500 * time.Millisecond

// dialOrder interleaves address families, IPv4 first, so one working family
// is reached quickly even when the other is unreachable from the server.
func dialOrder(addresses []netip.Addr) []netip.Addr {
	var v4, v6 []netip.Addr
	for _, ip := range addresses {
		if ip.Unmap().Is4() {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	ordered := make([]netip.Addr, 0, len(addresses))
	for i := 0; i < len(v4) || i < len(v6); i++ {
		if i < len(v4) {
			ordered = append(ordered, v4[i])
		}
		if i < len(v6) {
			ordered = append(ordered, v6[i])
		}
	}
	return ordered
}

func proxyError(w http.ResponseWriter, _ *http.Request, _ error) {
	http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
}

func (p *httpsProxy) connect(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" || r.URL.User != nil || r.URL.Path != "" || r.URL.RawQuery != "" {
		proxyError(w, r, nil)
		return
	}
	upstream, err := p.dialPublic(r.Context(), "tcp", r.URL.Host)
	if err != nil {
		proxyError(w, r, err)
		return
	}
	defer upstream.Close()
	if r.ProtoMajor >= 2 {
		proxyStreamResponse(w, r, upstream)
		return
	}
	downstream, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		proxyError(w, r, err)
		return
	}
	defer downstream.Close()
	stop := context.AfterFunc(r.Context(), func() {
		_ = upstream.Close()
		_ = downstream.Close()
	})
	defer stop()
	refresh := func() {
		deadline := time.Now().Add(proxyIdleTimeout)
		_ = upstream.SetDeadline(deadline)
		_ = downstream.SetDeadline(deadline)
	}
	refresh()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	relayTunnel(upstream, buffered.Reader, downstream, upstream, refresh)
}

func proxyStreamResponse(w http.ResponseWriter, r *http.Request, upstream net.Conn) {
	control := http.NewResponseController(w)
	canceled := make(chan struct{})
	stop := context.AfterFunc(r.Context(), func() {
		defer close(canceled)
		expired := time.Now().Add(-time.Second)
		_ = control.SetReadDeadline(expired)
		_ = control.SetWriteDeadline(expired)
		_ = upstream.Close()
		_ = r.Body.Close()
	})
	defer func() {
		// Wait for cancellation to finish using the ResponseWriter.
		if !stop() {
			<-canceled
		}
	}()
	refresh := func() {
		if r.Context().Err() != nil {
			return
		}
		deadline := time.Now().Add(proxyIdleTimeout)
		_ = upstream.SetDeadline(deadline)
		_ = control.SetReadDeadline(deadline)
		_ = control.SetWriteDeadline(deadline)
	}
	refresh()
	w.WriteHeader(http.StatusOK)
	if err := control.Flush(); err != nil {
		return
	}
	uploaded := make(chan struct{})
	go func() {
		defer close(uploaded)
		copyTunnel(upstream, r.Body, refresh)
	}()
	copyTunnel(flushingWriter{w, control}, upstream, refresh)
	// HTTP/2 sends END_STREAM when the handler returns. Stop the upload even
	// if the client is still waiting for that before closing its request body.
	_ = upstream.Close()
	_ = r.Body.Close()
	<-uploaded
}

type flushingWriter struct {
	writer  io.Writer
	control *http.ResponseController
}

func (w flushingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if err == nil {
		err = w.control.Flush()
	}
	return n, err
}

func relayTunnel(upstream io.Writer, incoming io.Reader, downstream io.Writer, outgoing io.Reader, refresh func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyTunnel(upstream, incoming, refresh)
	}()
	copyTunnel(downstream, outgoing, refresh)
	<-done
}

func copyTunnel(dst io.Writer, src io.Reader, refresh func()) {
	_, _ = io.Copy(refreshWriter{Writer: dst, refresh: refresh}, src)
	if half, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	}
}

type refreshWriter struct {
	io.Writer
	refresh func()
}

func (w refreshWriter) Write(data []byte) (int, error) {
	n, err := w.Writer.Write(data)
	if n > 0 {
		w.refresh()
	}
	return n, err
}

type proxyDeadlineConn struct{ net.Conn }

func (c proxyDeadlineConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(proxyIdleTimeout))
	return c.Conn.Read(p)
}

func (c proxyDeadlineConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(proxyIdleTimeout))
	return c.Conn.Write(p)
}

type proxyRequestBody struct {
	io.ReadCloser
	control *http.ResponseController
}

func (r proxyRequestBody) Read(p []byte) (int, error) {
	_ = r.control.SetReadDeadline(time.Now().Add(proxyIdleTimeout))
	return r.ReadCloser.Read(p)
}

type proxyResponse struct {
	http.ResponseWriter
	control *http.ResponseController
}

func (w proxyResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w proxyResponse) Write(p []byte) (int, error) {
	_ = w.control.SetWriteDeadline(time.Now().Add(proxyIdleTimeout))
	return w.ResponseWriter.Write(p)
}

func (p *httpsProxy) forward(w http.ResponseWriter, r *http.Request) {
	if (r.URL.Scheme != "http" && r.URL.Scheme != "https") || r.URL.Host == "" || r.URL.User != nil || r.URL.Opaque != "" {
		proxyError(w, r, nil)
		return
	}
	transport := &http.Transport{
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			// The transport may keep a dial alive past the HTTP request's
			// cancellation. Bind it to this credential's request instead.
			conn, err := p.dialPublic(r.Context(), network, address)
			if err != nil {
				return nil, err
			}
			return proxyDeadlineConn{Conn: conn}, nil
		},
		DisableKeepAlives: true, ForceAttemptHTTP2: true,
		ResponseHeaderTimeout: 15 * time.Second, TLSHandshakeTimeout: 8 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer transport.CloseIdleConnections()
	reverse := &httputil.ReverseProxy{
		Transport: transport, ErrorLog: log.New(io.Discard, "", 0), ErrorHandler: proxyError,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.Host = r.Out.URL.Host
			r.Out.Header.Del("Upgrade")
			r.Out.Header.Del("Connection")
		},
	}
	control := http.NewResponseController(w)
	_ = control.SetReadDeadline(time.Now().Add(proxyIdleTimeout))
	_ = control.SetWriteDeadline(time.Now().Add(proxyIdleTimeout))
	defer control.SetReadDeadline(time.Time{})
	defer control.SetWriteDeadline(time.Time{})
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = proxyRequestBody{r.Body, control}
	}
	reverse.ServeHTTP(proxyResponse{w, control}, r)
}
