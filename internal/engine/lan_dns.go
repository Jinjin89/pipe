// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"pipe/internal/sysdns"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	singDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	LANDNSType     = "pipe-lan-dns"
	lanDNSCacheAge = 5 * time.Second
	lanDNSDeadline = 4 * time.Second
)

type lanDNS struct {
	singDNS.TransportAdapter
	dialer   N.Dialer
	provider func() []netip.AddrPort
	exclude  []netip.Prefix

	mu         sync.Mutex
	servers    []netip.AddrPort
	serversAt  time.Time
	hasServers bool
	refreshing chan struct{}
	generation uint64
}

func newLANDNS(ctx context.Context, _ log.ContextLogger, tag string, provider func() []netip.AddrPort, exclude []netip.Prefix) (adapter.DNSTransport, error) {
	dialer, err := singDNS.NewLocalDialer(ctx, option.LocalDNSServerOptions{})
	if err != nil {
		return nil, err
	}
	return newLANDNSWithDialer(tag, provider, exclude, dialer), nil
}

func newLANDNSWithDialer(tag string, provider func() []netip.AddrPort, exclude []netip.Prefix, dialer N.Dialer) *lanDNS {
	return &lanDNS{
		TransportAdapter: singDNS.NewTransportAdapter(LANDNSType, tag, nil),
		dialer:           dialer,
		provider:         provider,
		exclude:          append([]netip.Prefix(nil), exclude...),
	}
}

func (l *lanDNS) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (l *lanDNS) Close() error                                   { return nil }

func (l *lanDNS) Reset() {
	l.mu.Lock()
	l.generation++
	l.hasServers = false
	l.servers = nil
	if l.refreshing != nil {
		close(l.refreshing)
		l.refreshing = nil
	}
	l.mu.Unlock()
}

// Environment changes with every network reset, so sing-box's DNS cache never
// serves one network's local answers on the next (it adds the network itself).
func (l *lanDNS) Environment() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return []string{strconv.FormatUint(l.generation, 10)}
}

func (l *lanDNS) serverList(ctx context.Context) ([]netip.AddrPort, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l.mu.Lock()
		if l.hasServers && time.Since(l.serversAt) < lanDNSCacheAge {
			servers := append([]netip.AddrPort(nil), l.servers...)
			l.mu.Unlock()
			return servers, nil
		}
		if wait := l.refreshing; wait != nil {
			l.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-wait:
				continue
			}
		}
		wait := make(chan struct{})
		l.refreshing = wait
		generation := l.generation
		l.mu.Unlock()

		var servers []netip.AddrPort
		if l.provider != nil {
			servers = filterLANDNSServers(l.provider(), l.exclude)
		}

		l.mu.Lock()
		current := generation == l.generation
		if current {
			l.servers, l.serversAt, l.hasServers = servers, time.Now(), true
		}
		if l.refreshing == wait {
			l.refreshing = nil
			close(wait)
		}
		l.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if current {
			return append([]netip.AddrPort(nil), servers...), nil
		}
	}
}

func filterLANDNSServers(servers []netip.AddrPort, exclude []netip.Prefix) []netip.AddrPort {
	tunnelDNS := netip.MustParseAddr(sysdns.TUNDNSAddress)
	blocked := make([]netip.Prefix, 0, len(exclude)+1)
	blocked = append(blocked, netip.PrefixFrom(tunnelDNS, tunnelDNS.BitLen()))
	for _, prefix := range exclude {
		if prefix.IsValid() {
			blocked = append(blocked, prefix.Masked())
		}
	}
	seen := make(map[netip.AddrPort]struct{}, len(servers))
	result := make([]netip.AddrPort, 0, len(servers))
	for _, server := range servers {
		if !server.IsValid() || server.Port() == 0 {
			continue
		}
		addr := compareIP(server.Addr())
		insideTunnel := false
		for _, prefix := range blocked {
			if prefix.Contains(addr) {
				insideTunnel = true
				break
			}
		}
		if insideTunnel {
			continue
		}
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		result = append(result, server)
	}
	return result
}

func compareIP(addr netip.Addr) netip.Addr {
	return addr.WithZone("").Unmap()
}

func (l *lanDNS) Exchange(ctx context.Context, query *mDNS.Msg) (*mDNS.Msg, error) {
	servers, err := l.serverList(ctx)
	if err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		return new(mDNS.Msg).SetRcode(query, mDNS.RcodeServerFailure), nil
	}
	var lastErr error
	for _, server := range servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		response, err := l.exchangeUDP(ctx, server, query)
		if err == nil && response.Truncated {
			response, err = l.exchangeTCP(ctx, server, query)
		}
		if err == nil {
			return response, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (l *lanDNS) ExchangeAsync(ctx context.Context, query *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { callback(l.Exchange(ctx, query)) }()
}

func (l *lanDNS) dial(ctx context.Context, network string, server netip.AddrPort) (net.Conn, func(), error) {
	conn, err := l.dialer.DialContext(ctx, network, M.SocksaddrFromNetIP(server))
	if err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(lanDNSDeadline)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return conn, func() { stop(); _ = conn.Close() }, nil
}

func (l *lanDNS) exchangeUDP(ctx context.Context, server netip.AddrPort, query *mDNS.Msg) (*mDNS.Msg, error) {
	conn, closeConn, err := l.dial(ctx, N.NetworkUDP, server)
	if err != nil {
		return nil, err
	}
	defer closeConn()
	packet, err := query.Pack()
	if err != nil {
		return nil, err
	}
	n, err := conn.Write(packet)
	if err != nil {
		return nil, err
	}
	if n != len(packet) {
		return nil, io.ErrShortWrite
	}
	buffer := make([]byte, 65535)
	readN, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	var response mDNS.Msg
	if err := response.Unpack(buffer[:readN]); err != nil {
		return nil, err
	}
	if response.Id != query.Id {
		return nil, errors.New("LAN DNS response id did not match")
	}
	return &response, nil
}

func (l *lanDNS) exchangeTCP(ctx context.Context, server netip.AddrPort, query *mDNS.Msg) (*mDNS.Msg, error) {
	conn, closeConn, err := l.dial(ctx, N.NetworkTCP, server)
	if err != nil {
		return nil, err
	}
	defer closeConn()
	packet, err := query.Pack()
	if err != nil {
		return nil, err
	}
	if len(packet) > 65535 {
		return nil, errors.New("LAN DNS request is too large")
	}
	framed := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(framed, uint16(len(packet)))
	copy(framed[2:], packet)
	if err := writeDNSFrame(conn, framed); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	if length < 12 {
		return nil, mDNS.ErrShortRead
	}
	packet = make([]byte, length)
	if _, err := io.ReadFull(conn, packet); err != nil {
		return nil, err
	}
	var response mDNS.Msg
	if err := response.Unpack(packet); err != nil {
		return nil, err
	}
	if response.Id != query.Id {
		return nil, errors.New("LAN DNS response id did not match")
	}
	return &response, nil
}

func writeDNSFrame(writer io.Writer, frame []byte) error {
	for len(frame) > 0 {
		n, err := writer.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func tunAddresses(config Object) []netip.Prefix {
	var result []netip.Prefix
	for _, inbound := range objectList(config["inbounds"]) {
		if inbound["type"] != "tun" {
			continue
		}
		for _, value := range stringList(inbound["address"]) {
			prefix, err := netip.ParsePrefix(value)
			if err == nil {
				result = append(result, prefix.Masked())
				continue
			}
			addr, err := netip.ParseAddr(value)
			if err == nil {
				result = append(result, netip.PrefixFrom(addr, addr.BitLen()))
			}
		}
	}
	return result
}

func objectList(value any) []Object {
	switch list := value.(type) {
	case []Object:
		return list
	case []any:
		result := make([]Object, 0, len(list))
		for _, item := range list {
			switch object := item.(type) {
			case Object:
				result = append(result, object)
			case map[string]any:
				result = append(result, Object(object))
			}
		}
		return result
	default:
		return nil
	}
}

func stringList(value any) []string {
	switch list := value.(type) {
	case []string:
		return list
	case []any:
		result := make([]string, 0, len(list))
		for _, item := range list {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	case string:
		return []string{list}
	default:
		return nil
	}
}

var _ adapter.DNSTransport = (*lanDNS)(nil)
var _ adapter.DNSTransportWithEnvironment = (*lanDNS)(nil)
