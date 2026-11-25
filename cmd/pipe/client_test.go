// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/config"
	"pipe/internal/failover"
	"pipe/internal/link"
)

func TestRunClientOptions(t *testing.T) {
	dir := t.TempDir()
	profile := link.Profile{Host: "origin.example", CDN: "cdn.example", Name: "laptop",
		Seed: [32]byte{1}, PublicKey: [32]byte{2}}
	raw, err := profile.Encode()
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("laptop.link", raw+"\n")
	write("default.link", raw+"\n")
	yaml := write("pipe.yaml", "server: laptop\nmode: global\ntun: true\nipv6: false\nrules:\n  - remote.example -> proxy\n")
	direct := write("direct.yaml", "mode: direct\nrules:\n  - blocked.example -> block\n")
	directWithProxy := write("proxy.yaml", "mode: direct\nrules:\n  - remote.example -> proxy\n")
	t.Setenv("PIPE_PROFILE_DIR", dir)

	for _, tc := range []struct {
		name string
		args []string
		want clientctl.Options
	}{
		{"link and flags", []string{"--mode", "global", raw, "--listen", "[::1]:9876", "--system-proxy",
			"--tier", "rescue", "--relay", "relay.example", "--log", "debug", "--test-ca", dir, "--test-address", "10.20.30.40",
			"--test-hosts", "EXAMPLE.COM.=::ffff:192.0.2.1", "--test-hosts", "example.net=2001:db8::1"},
			clientctl.Options{Profile: profile, Relay: "relay.example", Mode: config.Global, IPv6: true, Listen: "[::1]:9876",
				SystemProxy: true, Tier: failover.Rescue, LogLevel: "debug", TestCAFile: filepath.Join(dir, "ca.pem"),
				TestAddress: netip.MustParseAddr("10.20.30.40"), TestHosts: map[string]netip.Addr{
					"example.com": netip.MustParseAddr("192.0.2.1"), "example.net": netip.MustParseAddr("2001:db8::1"),
				}}},
		{"YAML preferences", []string{yaml, "--profile-dir", dir},
			clientctl.Options{Profile: profile, Mode: config.Global, TUN: true, Tier: failover.Auto,
				Listen: config.DefaultListen, LogLevel: "warn", Rules: []config.Rule{{Field: "domain", Match: "remote.example", Action: "proxy"}}}},
		{"flags override YAML", []string{yaml, "--mode", "direct", "--tun=false", "--relay="},
			clientctl.Options{Profile: profile, Mode: config.Direct, Tier: failover.Auto, Listen: config.DefaultListen,
				LogLevel: "warn", Rules: []config.Rule{{Field: "domain", Match: "remote.example", Action: "proxy"}}}},
		{"direct with no profile", []string{direct},
			clientctl.Options{Mode: config.Direct, IPv6: true, Tier: failover.Auto, Listen: config.DefaultListen,
				LogLevel: "warn", Rules: []config.Rule{{Field: "domain", Match: "blocked.example", Action: "block"}}}},
		{"direct with a proxy rule loads the default profile", []string{directWithProxy},
			clientctl.Options{Profile: profile, Mode: config.Direct, IPv6: true, Tier: failover.Auto, Listen: config.DefaultListen,
				LogLevel: "warn", Rules: []config.Rule{{Field: "domain", Match: "remote.example", Action: "proxy"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseClientOptions(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			tc.want.TUNOnly, tc.want.RulesInDirect = true, true
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("options %+v, want %+v", got, tc.want)
			}
		})
	}
	if _, err := parseClientOptions([]string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("--help: %v", err)
	}
	if _, err := parseClientOptions([]string{raw, "--test-address", "bad"}); err == nil {
		t.Fatal("accepted a malformed test address")
	}
}

func TestRunClientPrintsRelayChanges(t *testing.T) {
	var stderr bytes.Buffer
	report := printRelayChanges(&stderr)
	report("", "")
	for _, state := range []string{"", "pending", "pending", "via", "via", "pending", "via", "direct", "direct", "", "direct"} {
		report("relay.example", state)
	}
	report("", "")
	want := "Relay relay.example: in use\n" +
		"Relay relay.example: in use\n" +
		"Relay relay.example: not reachable, going direct\n" +
		"Relay relay.example: not reachable, going direct\n"
	if got := stderr.String(); got != want {
		t.Fatalf("stderr %q, want %q", got, want)
	}
}

func TestRunClientReportsFlagErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct.yaml")
	if err := os.WriteFile(path, []byte("mode: direct\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		flag, value, want string
	}{
		{"--test-address", "127.0.0.1", "--test-address requires --test-ca and a loopback or private IP address"},
		{"--test-hosts", "example.test=127.0.0.1", "--test-hosts requires --test-ca"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			err := runClient(ctx, []string{path, tc.flag, tc.value})
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

type fakeClientSession struct {
	calls      *[]string
	startErr   error
	lastError  string
	listen     string
	servers    func() []netip.AddrPort
	onStopped  func()
	afterReady func()
	open       bool
}

func (s *fakeClientSession) StartWithReady(_ clientctl.Options, ready func() error) error {
	*s.calls = append(*s.calls, "start")
	if s.startErr != nil {
		return s.startErr
	}
	s.open = true
	if err := ready(); err != nil {
		s.closeEngine()
		return err
	}
	s.afterReady()
	return nil
}

func (s *fakeClientSession) closeEngine() {
	*s.calls = append(*s.calls, "close engine")
	s.open = false
}

func (s *fakeClientSession) Stop() error {
	*s.calls = append(*s.calls, "stop")
	if s.open {
		s.closeEngine()
	}
	return nil
}

func (s *fakeClientSession) Status() clientctl.Status {
	return clientctl.Status{LastError: s.lastError, Listen: s.listen}
}

func (s *fakeClientSession) SetLANDNSServers(servers func() []netip.AddrPort) {
	*s.calls = append(*s.calls, "provide LAN DNS")
	s.servers = servers
}

func (s *fakeClientSession) SetOnStopped(stopped func()) { s.onStopped = stopped }

type fakeClientDNS struct {
	calls                         *[]string
	repairErr, setErr, restoreErr error
}

func (d *fakeClientDNS) Repair() error {
	*d.calls = append(*d.calls, "repair DNS")
	return d.repairErr
}
func (d *fakeClientDNS) Set() error {
	*d.calls = append(*d.calls, "set DNS")
	return d.setErr
}
func (d *fakeClientDNS) Restore() error {
	*d.calls = append(*d.calls, "restore DNS")
	return d.restoreErr
}
func (d *fakeClientDNS) Servers() []netip.AddrPort {
	return []netip.AddrPort{netip.MustParseAddrPort("[fe80::1%en0]:53")}
}

func TestRunClientDNSLifecycle(t *testing.T) {
	failure := errors.New("test failure")
	for _, tc := range []struct {
		name         string
		startErr     error
		dns          fakeClientDNS
		endsOnItsOwn bool
		failoverErr  error
		want         []string
		wantErr      string
		ready        bool
	}{
		{name: "cancellation", ready: true,
			want: []string{"repair DNS", "provide LAN DNS", "start", "set DNS", "stop", "close engine", "restore DNS"}},
		{name: "failed rebuild", endsOnItsOwn: true, ready: true, wantErr: "rebuild failed",
			want: []string{"repair DNS", "provide LAN DNS", "start", "set DNS", "close engine", "restore DNS", "stop"}},
		{name: "failed failover", failoverErr: failure, ready: true, wantErr: "test failure",
			want: []string{"repair DNS", "provide LAN DNS", "start", "set DNS", "stop", "close engine", "restore DNS"}},
		{name: "failed set", dns: fakeClientDNS{setErr: failure}, wantErr: "set system DNS",
			want: []string{"repair DNS", "provide LAN DNS", "start", "set DNS", "close engine", "stop", "restore DNS"}},
		{name: "failed restore", dns: fakeClientDNS{restoreErr: failure}, ready: true, wantErr: "restore system DNS",
			want: []string{"repair DNS", "provide LAN DNS", "start", "set DNS", "stop", "close engine", "restore DNS"}},
		{name: "failed start", startErr: failure, wantErr: "test failure",
			want: []string{"repair DNS", "provide LAN DNS", "start", "stop"}},
		{name: "failed repair", dns: fakeClientDNS{repairErr: failure}, wantErr: "repair system DNS",
			want: []string{"repair DNS"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			var stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ctl := &fakeClientSession{calls: &calls, startErr: tc.startErr}
			failoverErrors := make(chan error, 1)
			ctl.afterReady = func() {
				switch {
				case tc.endsOnItsOwn:
					ctl.closeEngine()
					ctl.lastError = "rebuild failed"
					ctl.onStopped()
				case tc.failoverErr != nil:
					failoverErrors <- tc.failoverErr
				default:
					cancel()
				}
			}
			tc.dns.calls = &calls
			err := runClientSession(ctx, ctl, clientctl.Options{TUN: true}, &tc.dns, failoverErrors, &stderr)
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error %v, want %q", err, tc.wantErr)
			}
			if !slices.Equal(calls, tc.want) || ctl.open {
				t.Fatalf("lifecycle %v, want %v", calls, tc.want)
			}
			if tc.dns.repairErr == nil && (ctl.servers == nil || !slices.Equal(ctl.servers(), tc.dns.Servers())) {
				t.Fatal("LAN DNS provider was lost")
			}
			var wantOutput string
			if tc.ready {
				wantOutput = "Client started in TUN mode\n"
			}
			if stderr.String() != wantOutput {
				t.Fatalf("stderr %q, want %q", stderr.String(), wantOutput)
			}
		})
	}
}

func TestRunClientStopsOnCancel(t *testing.T) {
	for _, tc := range []struct {
		name, listen, actual string
	}{
		{"explicit listen address", "127.0.0.1:9000", "127.0.0.1:9000"},
		{"empty listen address", "", config.DefaultListen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var calls []string
			var stderr bytes.Buffer
			ctl := &fakeClientSession{calls: &calls, afterReady: cancel, listen: tc.actual}
			if err := runClientSession(ctx, ctl, clientctl.Options{Listen: tc.listen}, nil, nil, &stderr); err != nil {
				t.Fatal(err)
			}
			if want := []string{"start", "stop", "close engine"}; !slices.Equal(calls, want) || ctl.open {
				t.Fatalf("lifecycle %v, want %v", calls, want)
			}
			if got, want := stderr.String(), "Client listening on "+tc.actual+"\n"; got != want {
				t.Fatalf("stderr %q, want %q", got, want)
			}
		})
	}
}
