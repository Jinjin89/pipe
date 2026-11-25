// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

const InMemoryProbe = "pipe-probe"

var probeBurstBody = strings.Repeat("0", ProbeBurstSize)

func ProbeResponse(r *http.Request) (int, string) {
	if r.Host != ProbeDomain || r.URL.Path != ProbePath {
		return http.StatusNotFound, "404 page not found\n"
	}
	if r.URL.Query().Get("burst") == "1" {
		return http.StatusOK, probeBurstBody
	}
	return http.StatusOK, "OK"
}

type probeOutbound struct{ outbound.Adapter }

func newProbeOutbound(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Outbound, error) {
	return &probeOutbound{outbound.NewAdapter(InMemoryProbe, tag, []string{"tcp"}, nil)}, nil
}

func (o *probeOutbound) DialContext(ctx context.Context, network string, target M.Socksaddr) (net.Conn, error) {
	if network != "tcp" || target.Fqdn != ProbeDomain || target.Port != 80 {
		return nil, errors.New("invalid probe destination")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(6 * time.Second))
		req, err := http.ReadRequest(bufio.NewReader(io.LimitReader(server, 4096)))
		if err != nil {
			return
		}
		defer req.Body.Close()
		status, body := ProbeResponse(req)
		res := &http.Response{
			StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Close: true,
			Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
			ContentLength: int64(len(body)), Body: io.NopCloser(strings.NewReader(body)),
		}
		_ = res.Write(server)
	}()
	return client, nil
}

func (o *probeOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("probe requires TCP")
}
