// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestMeasureProbeRTTCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name       string
		replies    int
		closeFirst bool
		body       string
		want       time.Duration
	}{
		{name: "median", replies: 4, body: "OK", want: 34 * time.Millisecond},
		{name: "legacy reply", replies: 1, closeFirst: true, body: "OK"},
		{name: "incomplete", replies: 2, body: "OK"},
		{name: "malformed", replies: 1, closeFirst: true, body: "NO"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					reader := bufio.NewReader(server)
					delays := []time.Duration{800 * time.Millisecond, 67 * time.Millisecond, 11 * time.Millisecond, 34 * time.Millisecond}
					for n := range tc.replies {
						req, err := http.ReadRequest(reader)
						if err != nil {
							t.Error(err)
							return
						}
						if req.URL.Path != ProbePath || req.Host != ProbeDomain || req.Close != (n == 3) {
							t.Errorf("unexpected probe request %s %s, close %t", req.Host, req.URL.Path, req.Close)
						}
						time.Sleep(delays[n])
						reply := &http.Response{
							StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1, Close: tc.closeFirst || req.Close,
							ContentLength: int64(len(tc.body)), Body: io.NopCloser(strings.NewReader(tc.body)),
						}
						if err := reply.Write(server); err != nil {
							t.Error(err)
							return
						}
					}
				}()
				rtt, err := measureProbeRTT(t.Context(), client)
				wantErr := tc.body != "OK" || (!tc.closeFirst && tc.replies != 4)
				if (err != nil) != wantErr || rtt != tc.want {
					t.Fatalf("RTT %v, %v, want %v, error %t", rtt, err, tc.want, wantErr)
				}
			})
		})
	}
}

func TestProbeOutboundSupportsBothClientVersions(t *testing.T) {
	target := M.ParseSocksaddrHostPort(ProbeDomain, 80)
	for _, legacy := range []bool{false, true} {
		conn, err := (&probeOutbound{}).DialContext(t.Context(), "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		if legacy {
			if stalled, err := probeHTTP(t.Context(), conn, true); stalled || err != nil {
				t.Fatalf("legacy burst probe failed: %v", err)
			}
		} else if latency, err := measureProbeRTT(t.Context(), conn); err != nil || latency <= 0 {
			t.Fatalf("RTT on the new server = %v, %v", latency, err)
		}
	}
}
