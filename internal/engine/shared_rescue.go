// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"errors"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/uot"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2raywebsocket"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const SharedRescue = "pipe-rescue"

type sharedRescueOptions struct {
	Listen string             `json:"listen"`
	Host   string             `json:"host"`
	Path   string             `json:"path"`
	Users  []option.VMessUser `json:"users"`
}

type sharedRescue struct {
	inbound.Adapter
	listen  string
	log     log.ContextLogger
	router  adapter.ConnectionRouterEx
	service *vmess.Service[string]
	handler http.Handler
}

func newSharedRescue(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, opts sharedRescueOptions) (adapter.Inbound, error) {
	bind, err := netip.ParseAddrPort(opts.Listen)
	ip := bind.Addr().Unmap()
	if err != nil || bind.Port() == 0 || bind.Addr().Zone() != "" || !(ip.IsLoopback() || ip.IsPrivate()) {
		return nil, errors.New("shared Rescue listener requires a private IP:port")
	}
	r := &sharedRescue{
		Adapter: inbound.NewAdapter(SharedRescue, tag), listen: netip.AddrPortFrom(ip, bind.Port()).String(),
		log: logger, router: uot.NewRouter(router, logger),
	}
	r.service = vmess.NewService[string](adapter.NewUpstreamContextHandler(r.routeTCP, r.routeUDP), vmess.ServiceWithDisableHeaderProtection())
	names, uuids := make([]string, 0, len(opts.Users)), make([]string, 0, len(opts.Users))
	for _, user := range opts.Users {
		names, uuids = append(names, user.Name), append(uuids, user.UUID)
	}
	if err := r.service.UpdateUsers(names, uuids, make([]int, len(names))); err != nil {
		return nil, err
	}
	a := new(RescueAuthenticator)
	if err := a.SetUsers(uuids); err != nil {
		return nil, err
	}
	ws, err := v2raywebsocket.NewServer(ctx, logger, option.V2RayWebsocketOptions{
		Path: opts.Path, MaxEarlyData: WebSocketEarlyDataLimit, EarlyDataHeaderName: WebSocketEarlyDataHeader,
	}, nil, r)
	if err != nil {
		return nil, err
	}
	r.handler = rescueGate(opts.Host, opts.Path, a.Authenticate, ws)
	return r, nil
}

func rescueGate(host, path string, authenticate func(context.Context, string) bool, websocket http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			name = r.Host
		}
		if !strings.EqualFold(name, host) || r.Method != http.MethodGet || r.URL.EscapedPath() != path ||
			r.URL.RawQuery != "" || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
			!authenticate(r.Context(), r.Header.Get(WebSocketEarlyDataHeader)) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		websocket.ServeHTTP(w, r)
	})
}

func (r *sharedRescue) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := r.service.Start(); err != nil {
		return err
	}
	scope.Add(r.service.Close)
	listener, err := net.Listen("tcp", r.listen)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler: r.handler, ErrorLog: stdlog.New(io.Discard, "", 0),
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	scope.Add(func() error {
		err := server.Close()
		_ = listener.Close()
		return err
	})
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			r.log.Error("shared Rescue listener stopped")
		}
	}()
	return nil
}

func (r *sharedRescue) NewConnectionEx(ctx context.Context, conn net.Conn, source, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := r.service.NewConnection(ctx, conn, source, onClose); err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
	}
}

func (r *sharedRescue) identify(ctx context.Context, metadata *adapter.InboundContext) bool {
	user, ok := auth.UserFromContext[string](ctx)
	metadata.User, metadata.Inbound, metadata.InboundType = user, r.Tag(), "vmess"
	return ok
}

func (r *sharedRescue) routeTCP(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if !r.identify(ctx, &metadata) {
		N.CloseOnHandshakeFailure(conn, onClose, errors.New("unknown Rescue device"))
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	r.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (r *sharedRescue) routeUDP(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if !r.identify(ctx, &metadata) {
		N.CloseOnHandshakeFailure(conn, onClose, errors.New("unknown Rescue device"))
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if metadata.Destination.Fqdn == packetaddr.SeqPacketMagicAddress {
		metadata.Destination = M.Socksaddr{}
		conn = packetaddr.NewConn(bufio.NewNetPacketConn(conn), metadata.Destination)
	}
	r.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}
