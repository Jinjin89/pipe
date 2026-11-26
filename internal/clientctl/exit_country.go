// SPDX-License-Identifier: GPL-3.0-or-later

package clientctl

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

const (
	exitTraceHost  = "www.cloudflare.com"
	exitTraceURL   = "https://" + exitTraceHost + "/cdn-cgi/trace"
	traceBodyLimit = 4 << 10
)

func lookupExitCountry(ctx context.Context, tier string) string {
	outbounds := service.FromContext[adapter.OutboundManager](ctx)
	if outbounds == nil {
		return ""
	}
	outbound, ok := outbounds.Outbound(tier)
	if !ok {
		return ""
	}
	conn, err := outbound.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort(exitTraceHost, 443))
	if err != nil {
		return ""
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	// Use the system roots and verify the fixed hostname. Writing one request
	// on this connection also prevents redirects, retries, and a direct dial.
	tlsConn := tls.Client(conn, &tls.Config{ServerName: exitTraceHost})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, exitTraceURL, nil)
	if err != nil {
		return ""
	}
	req.Close = true
	if err := req.Write(tlsConn); err != nil {
		return ""
	}
	return readExitCountryResponse(tlsConn, req)
}

func readExitCountryResponse(r io.Reader, req *http.Request) string {
	// Bound the header as well as the body. The caller closes the connection
	// without draining the rest of the response.
	raw := &io.LimitedReader{R: r, N: 2 * traceBodyLimit}
	resp, err := http.ReadResponse(bufio.NewReader(raw), req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	country := parseExitCountry(resp.Body)
	if raw.N == 0 {
		return "" // The overall limit may have cut a line short.
	}
	return country
}

func parseExitCountry(body io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(body, traceBodyLimit+1))
	defer clear(data)
	if err != nil || len(data) > traceBodyLimit {
		return ""
	}
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		if value, ok := bytes.CutPrefix(line, []byte("loc=")); ok {
			return NormalizeExitCountry(string(bytes.TrimSuffix(value, []byte("\r"))))
		}
	}
	return ""
}

// NormalizeExitCountry accepts a two-letter trace country code.
func NormalizeExitCountry(code string) string {
	if len(code) != 2 {
		return ""
	}
	for _, letter := range code {
		if (letter < 'A' || letter > 'Z') && (letter < 'a' || letter > 'z') {
			return ""
		}
	}
	code = strings.ToUpper(code)
	if code == "XX" {
		return ""
	}
	return code
}
