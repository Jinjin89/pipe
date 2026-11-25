// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"errors"
	"net"
	"os"
	"slices"
	"syscall"
	"testing"
)

func TestListenTCPUsesIPv4OnlyWhenIPv6IsUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		host     string
		bindErr  error
		fallback bool
	}{
		{name: "dual stack", host: "::"},
		{name: "unsupported family", host: "::", bindErr: syscall.EAFNOSUPPORT, fallback: true},
		{name: "unavailable address", host: "::", bindErr: syscall.EADDRNOTAVAIL, fallback: true},
		{name: "port in use", host: "::", bindErr: syscall.EADDRINUSE},
		{name: "permission denied", host: "::", bindErr: syscall.EACCES},
		{name: "loopback only", host: "127.0.0.1", bindErr: syscall.EADDRNOTAVAIL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := &net.TCPListener{}
			var calls []string
			ln, err := listenTCP(tc.host, 80, func(network, address string) (net.Listener, error) {
				calls = append(calls, network+" "+address)
				if len(calls) == 1 && tc.bindErr != nil {
					return nil, &net.OpError{Op: "listen", Net: network, Err: os.NewSyscallError("bind", tc.bindErr)}
				}
				return want, nil
			})
			wantCalls := []string{"tcp " + addrPort(tc.host, 80)}
			if tc.fallback {
				wantCalls = append(wantCalls, "tcp4 0.0.0.0:80")
			}
			if !slices.Equal(calls, wantCalls) {
				t.Fatalf("listen calls = %v, want %v", calls, wantCalls)
			}
			if tc.fallback || tc.bindErr == nil {
				if ln != want || err != nil {
					t.Fatalf("bind returned %v, %v", ln, err)
				}
			} else if ln != nil || !errors.Is(err, tc.bindErr) {
				t.Fatalf("bind returned %v, %v, want %v", ln, err, tc.bindErr)
			}
		})
	}
}

func TestBindWithIPv4FallbackReturnsTheEffectiveHost(t *testing.T) {
	var hosts []string
	errBusy := syscall.EADDRINUSE
	_, host, err := bindWithIPv4Fallback("::", func(host string) (string, error) {
		hosts = append(hosts, host)
		if host == "::" {
			return "", syscall.EAFNOSUPPORT
		}
		return "", errBusy
	})
	if host != "0.0.0.0" || !errors.Is(err, errBusy) || !slices.Equal(hosts, []string{"::", "0.0.0.0"}) {
		t.Fatalf("attempts = %v, final host = %q, error = %v", hosts, host, err)
	}
}
