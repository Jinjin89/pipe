// SPDX-License-Identifier: GPL-3.0-or-later

package clientctl

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestParseExitCountry(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"ip=192.0.2.1\ncolo=NRT\nloc=jp\n", "JP"},
		{"loc=dE\r\nip=2001:db8::1\r\n", "DE"},
		{"loc=US", "US"},
		{"colo=YYZ\nip=192.0.2.1\n", ""},
		{"sub_loc=US\n", ""},
		{"loc=xX\n", ""},
		{"loc=T1\n", ""},
		{"loc=é\n", ""},
		{"loc=JPN\n", ""},
		{"loc=JP \n", ""},
		{"loc=JP\n" + strings.Repeat("x", traceBodyLimit), ""},
	} {
		if got := parseExitCountry(strings.NewReader(tc.body)); got != tc.want {
			t.Errorf("country = %q, want %q for %q", got, tc.want, tc.body[:min(30, len(tc.body))])
		}
	}
}

func TestReadExitCountryResponse(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, exitTraceURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "HTTP/1.1 200 OK\r\nConnection: close\r\nX-Padding: "
	suffix := "\r\n\r\nloc=JP"
	truncated := prefix + strings.Repeat("x", 2*traceBodyLimit-len(prefix)-len(suffix)) + suffix + "N"
	for _, tc := range []struct{ name, response, want string }{
		{"valid", "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nloc=jp\n", "JP"},
		{"redirect", "HTTP/1.1 302 Found\r\nLocation: https://redirect.example\r\nContent-Length: 7\r\n\r\nloc=jp\n", ""},
		{"truncated", truncated, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := readExitCountryResponse(strings.NewReader(tc.response), req); got != tc.want {
				t.Errorf("country = %q, want %q", got, tc.want)
			}
		})
	}
}

type traceTestOutbounds struct {
	adapter.OutboundManager
	selectTier func(string) (adapter.Outbound, bool)
}

func (o traceTestOutbounds) Outbound(tag string) (adapter.Outbound, bool) {
	return o.selectTier(tag)
}

type traceTestOutbound struct {
	adapter.Outbound
	dial func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (o traceTestOutbound) DialContext(ctx context.Context, network string, addr M.Socksaddr) (net.Conn, error) {
	return o.dial(ctx, network, addr)
}

func TestExitCountryDialsOnlyTheChosenOutbound(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(t.Context())
	calls := 0
	service.MustRegister[adapter.OutboundManager](ctx, traceTestOutbounds{
		selectTier: func(tag string) (adapter.Outbound, bool) {
			if tag != "rescue" {
				t.Errorf("lookup selected outbound %q", tag)
			}
			return traceTestOutbound{dial: func(gotCtx context.Context, network string, addr M.Socksaddr) (net.Conn, error) {
				calls++
				if gotCtx != ctx || network != "tcp" || addr != M.ParseSocksaddrHostPort("www.cloudflare.com", 443) {
					t.Errorf("lookup dial = %q, %s, context passed = %t", network, addr, gotCtx == ctx)
				}
				return nil, errors.New("test dial failure")
			}}, true
		},
	})
	if got := lookupExitCountry(ctx, "rescue"); got != "" || calls != 1 {
		t.Fatalf("failed lookup = %q after %d dials", got, calls)
	}
}
