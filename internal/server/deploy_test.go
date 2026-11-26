// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"pipe/internal/config"
	"pipe/internal/engine"
	"pipe/internal/link"
)

type bindProbeTCP struct{ net.Listener }
type bindProbeUDP struct{ net.PacketConn }
type dialProbeTCP struct{ net.Conn }

func (bindProbeTCP) Close() error { return nil }
func (bindProbeUDP) Close() error { return nil }
func (dialProbeTCP) Close() error { return nil }

func TestAutoDetectDeployment(t *testing.T) {
	for _, test := range []struct {
		name      string
		tcp       map[string]error
		udp       error
		reachable string
		wantDials []string
		want      DeployMode
	}{
		{name: "free", want: Standalone},
		{name: "HTTP occupied", tcp: map[string]error{"[::]:80": syscall.EADDRINUSE}, want: Shared},
		{name: "HTTPS occupied", tcp: map[string]error{"[::]:443": syscall.EADDRINUSE}, want: Shared},
		{name: "HTTP3 occupied", udp: syscall.EADDRINUSE, want: Shared},
		{
			name: "permission denied with no listener", want: Standalone,
			tcp: map[string]error{"[::]:80": syscall.EACCES, "[::]:443": syscall.EPERM}, udp: syscall.EACCES,
			wantDials: []string{"127.0.0.1:80", "[::1]:80", "127.0.0.1:443", "[::1]:443"},
		},
		{
			name: "IPv4 HTTP reachable after refused bind", want: Shared,
			tcp: map[string]error{"[::]:80": syscall.EACCES}, reachable: "127.0.0.1:80",
			wantDials: []string{"127.0.0.1:80"},
		},
		{
			name: "IPv6 HTTPS reachable after refused bind", want: Shared,
			tcp: map[string]error{"[::]:443": syscall.EPERM}, reachable: "[::1]:443",
			wantDials: []string{"127.0.0.1:443", "[::1]:443"},
		},
		{
			name: "IPv4 occupied", want: Shared,
			tcp: map[string]error{"[::]:80": syscall.EAFNOSUPPORT, "0.0.0.0:80": syscall.EADDRINUSE},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			listen := func(_, addr string) (net.Listener, error) { return bindProbeTCP{}, test.tcp[addr] }
			udpChecked := false
			packet := func(_, _ string) (net.PacketConn, error) {
				udpChecked = true
				return bindProbeUDP{}, test.udp
			}
			var dialed []string
			dial := func(network, addr string, timeout time.Duration) (net.Conn, error) {
				if network != "tcp" || timeout <= 0 || timeout > time.Second {
					t.Fatalf("unexpected loopback dial %s %s with timeout %s", network, addr, timeout)
				}
				dialed = append(dialed, addr)
				if addr == test.reachable {
					return dialProbeTCP{}, nil
				}
				return nil, syscall.ECONNREFUSED
			}
			mode, occupied, err := detectMode(80, 443, 443, listen, packet, dial)
			if err != nil || mode != test.want || !udpChecked || occupied != (test.udp == syscall.EADDRINUSE) {
				t.Fatalf("wanted %s, got %s: %v", test.want, mode, err)
			}
			if !slices.Equal(dialed, test.wantDials) {
				t.Fatalf("unexpected loopback dials %v, wanted %v", dialed, test.wantDials)
			}
		})
	}
}

func TestSharedStateEndpointsAndFastRenewal(t *testing.T) {
	dir := t.TempDir()
	const cdn = "static.example"
	cert, key := writeProxyTestPair(t, cdn, t.TempDir())
	options := InitOptions{
		Mode: Shared, Ports: Ports{Fast: 14443},
		FastSNI: "fast.example", FastHop: "20000-20010",
		Rescue: RescueConfig{Cert: cert, Key: key},
	}
	if err := InitWithOptions(dir, "11.0.0.80", cdn, options); err != nil {
		t.Fatal(err)
	}
	s, err := ReadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Rescue == nil || s.Rescue.Port != DefaultRescuePort || s.Ports.VMess == 0 ||
		filepath.Dir(s.Rescue.Cert) != dir || filepath.Dir(s.Rescue.Key) != dir {
		t.Fatalf("unexpected saved Rescue configuration: %+v", s.Rescue)
	}
	raw, _, proxy, err := AddWithProxy(dir, "shared", false)
	if err != nil || proxy != "" {
		t.Fatalf("shared enrollment returned a proxy credential or failed: %v", err)
	}
	profile, err := link.Parse(raw)
	if err != nil || profile.FastEndpointPort() != 14443 || profile.StealthEndpointPort() != 8443 ||
		profile.FastServerName() != "fast.example" || profile.StealthServerName() != "fast.example" ||
		profile.FastHop != "20000-20010" || profile.FastPin == "" || profile.CDN != cdn || profile.CDNPort != DefaultRescuePort {
		t.Fatalf("shared link has wrong endpoint metadata: %v", err)
	}
	before, err := s.fastKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cover, err := generateCoverSite(s.RealityPrivateKey, mainCoverLabel)
	if err != nil {
		t.Fatal(err)
	}
	now := before.Leaf.NotBefore.Add(fastCertSkew)
	still, err := renewFastCertificate(dir, now.Add(fastCertRotation-time.Second))
	if err != nil || !bytes.Equal(before.Certificate[0], still.Certificate[0]) {
		t.Fatalf("Fast certificate renewed before day 60: %v", err)
	}
	after, err := renewFastCertificate(dir, now.Add(fastCertRotation))
	if err != nil || bytes.Equal(before.Certificate[0], after.Certificate[0]) ||
		!bytes.Equal(before.Leaf.RawSubjectPublicKeyInfo, after.Leaf.RawSubjectPublicKeyInfo) ||
		after.Leaf.NotAfter.Sub(now.Add(fastCertRotation)) != fastCertLifetime {
		t.Fatalf("renewal did not preserve the pin or issue a fresh 90-day certificate: %v", err)
	}
	again, err := ReadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := again.fastPin()
	if err != nil || pin != profile.FastPin || !bytes.Equal(s.FastPrivateKey, again.FastPrivateKey) {
		t.Fatalf("persisted Fast key changed after renewal: %v", err)
	}
	afterCover, err := generateCoverSite(again.RealityPrivateKey, mainCoverLabel)
	if err != nil || !bytes.Equal(cover, afterCover) {
		t.Fatalf("cover should survive Fast certificate renewal: %v", err)
	}
	config := serverConfig(s, nil, "127.0.0.1", serverListeners{masquerade: 12345}, nil)
	inbounds := config["inbounds"].([]engine.Object)
	if len(inbounds) != 2 || inbounds[0]["tag"] != "fast" || inbounds[0]["masquerade"].(engine.Object)["url"] != "http://127.0.0.1:12345" ||
		inbounds[1]["type"] != "vmess" || inbounds[1]["listen"] != "127.0.0.1" || inbounds[1]["listen_port"] != s.Ports.VMess {
		t.Fatalf("expected Fast and loopback VMess: %+v", inbounds)
	}
	outbounds := config["outbounds"].([]engine.Object)
	if outbounds[1]["type"] != engine.InMemoryProbe {
		t.Fatal("shared health probes need a socket-free outbound")
	}
	installDir := filepath.Join(dir, "install")
	must(t, os.Mkdir(installDir, 0750))
	stale := []string{"pipe-rescue.nginx", "pipe-nginx.conf"}
	for _, name := range stale {
		must(t, os.WriteFile(filepath.Join(installDir, name), []byte("old include"), 0600))
	}
	_, err = GenerateInstall(dir, "/tmp/pipe")
	if err != nil {
		t.Fatal(err)
	}
	service, err := os.ReadFile(filepath.Join(installDir, "pipe.service"))
	if err != nil || !bytes.Contains(service, []byte("RestartSec=5s\n")) ||
		!bytes.Contains(service, []byte("StartLimitIntervalSec=0\n")) {
		t.Fatalf("missing service restart settings: %v", err)
	}
	hopService, err := os.ReadFile(filepath.Join(installDir, "pipe-hop.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"Wants=network-online.target", "After=network-online.target nftables.service",
		"Before=pipe.service", "Type=oneshot", "User=root", "RemainAfterExit=yes",
		"CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE", "NoNewPrivileges=yes",
		"ExecStart=\"/tmp/pipe\" server hop-apply --fast-hop 20000-20010 --fast-port 14443", "WantedBy=multi-user.target"} {
		if !bytes.Contains(hopService, []byte(line+"\n")) {
			t.Errorf("hopping service is missing %q", line)
		}
	}
	if bytes.Contains(hopService, []byte(dir)) || bytes.Contains(hopService, []byte("--dir")) ||
		bytes.Contains(hopService, []byte("AmbientCapabilities=")) {
		t.Fatal("the root hopping service must not use the state directory or ambient capabilities")
	}
	for _, name := range stale {
		if _, err := os.Stat(filepath.Join(installDir, name)); !os.IsNotExist(err) {
			t.Errorf("stale %s was kept: %v", name, err)
		}
	}
	firewall, err := os.ReadFile(filepath.Join(installDir, "pipe.nft"))
	if err != nil || strings.Contains(string(firewall), "tcp dport 2053") {
		t.Fatalf("unexpected Rescue firewall rule: %v\n%s", err, firewall)
	}
	if runtime.GOOS != "windows" {
		for path, mode := range map[string]os.FileMode{installDir: 0700, s.Rescue.Cert: 0600, s.Rescue.Key: 0600} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != mode {
				t.Errorf("expected mode %o for %s: %v", mode, filepath.Base(path), err)
			}
		}
	}
}

func TestFastHopRequiresExplicitParameters(t *testing.T) {
	for _, test := range []struct {
		ports string
		fast  uint16
	}{
		{"", 443},
		{"20000-20010", 0},
		{"20010-20000", 443},
	} {
		if err := ApplyFastHop(t.Context(), test.ports, test.fast); err == nil {
			t.Errorf("accepted invalid hopping range %q or port %d", test.ports, test.fast)
		}
	}
}

func TestStandaloneProductionRescueUsesStealthPort(t *testing.T) {
	const cdn = "cdn.example"
	for _, tc := range []struct {
		name     string
		port     uint16
		linkPort uint16
		warning  bool
	}{
		{"default port", 443, 0, false},
		{"Cloudflare port", 2053, 2053, false},
		{"non-Cloudflare port", 12053, 12053, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var warnings []string
			must(t, InitWithOptions(dir, "origin.example", cdn, InitOptions{
				Mode: Standalone, Ports: Ports{Stealth: tc.port},
				Warn: func(warning string) { warnings = append(warnings, warning) },
			}))
			if (len(warnings) > 0) != tc.warning || tc.warning && !strings.Contains(warnings[0], "Cloudflare") {
				t.Fatalf("unexpected warnings for TCP %d: %v", tc.port, warnings)
			}
			raw, _, _, err := AddWithProxy(dir, "phone", false)
			must(t, err)
			profile, err := link.Parse(raw)
			must(t, err)
			if profile.CDN != cdn || profile.WSPath == "" || profile.CDNPort != tc.linkPort {
				t.Fatalf("production link has CDN port %d, want %d", profile.CDNPort, tc.linkPort)
			}
			client, err := config.BuildClient(config.ClientOptions{
				Preferences: config.Preferences{Mode: config.Global}, Profile: &profile,
			})
			must(t, err)
			for _, outbound := range client.Config["outbounds"].([]engine.Object) {
				if outbound["tag"] == "rescue" && outbound["server"] == cdn && outbound["server_port"] == tc.port {
					return
				}
			}
			t.Fatalf("production client is missing a Rescue outbound on TCP %d", tc.port)
		})
	}
}

func TestDeviceProxyExportAndLegacyCredentials(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "origin.example", ""); err != nil {
		t.Fatal(err)
	}
	name := "phone: $&'📱"
	raw, _, export, err := AddWithProxy(dir, name, false)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(export)
	if err != nil || u.User.Username() != name || u.Host != "origin.example:443" ||
		u.Scheme != "https" || strings.ContainsAny(export, " $&'") {
		t.Fatalf("invalid or shell-unsafe proxy export: %v", err)
	}
	profile, err := link.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if password, ok := u.User.Password(); !ok || password != link.Derive(profile.Seed).HTTPSProxyPassword {
		t.Fatal("proxy password is not derived from the enrolled device")
	}
	if fromLink, ok := link.ProxyURL(profile); !ok || fromLink != export {
		t.Fatalf("link.ProxyURL = (%q, %v), want (%q, true)", fromLink, ok, export)
	}
	devices, err := ReadDevices(dir)
	if err != nil {
		t.Fatal(err)
	}
	devices[0].HTTPSProxyPassword = ""
	if err := writeJSON(dir, devicesFile, devices); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDevices(dir); err != nil {
		t.Fatalf("M1 device state no longer loads: %v", err)
	}
	disabled := t.TempDir()
	if err := InitWithOptions(disabled, "origin.example", "", InitOptions{Mode: Standalone, NoHTTPSProxy: true}); err != nil {
		t.Fatal(err)
	}
	disabledRaw, _, proxy, err := AddWithProxy(disabled, name, false)
	if err != nil || proxy != "" {
		t.Fatalf("failed to add without printing a proxy: %v", err)
	}
	if disabledProfile, err := link.Parse(disabledRaw); err != nil || disabledProfile.HTTPSProxy != "" {
		t.Fatalf("disabled proxy link must not set hp: %q %v", disabledProfile.HTTPSProxy, err)
	} else if got, ok := link.ProxyURL(disabledProfile); ok || got != "" {
		t.Fatalf("disabled proxy link must not derive a proxy URL: %q %v", got, ok)
	}
}

func TestHopTableOwnership(t *testing.T) {
	const list = "table inet unrelated\ntable inet pipe\n"
	owned := false
	var applied string
	nft := func(input string, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "list tables":
			return list, nil
		case "list table inet pipe":
			if owned {
				return "table inet pipe {\n comment \"pipe Fast port hopping\"\n}\n", nil
			}
			return "table inet pipe {\n}\n", nil
		case "-f -":
			applied = input
			return "", nil
		default:
			return "", errors.New("unexpected nft invocation")
		}
	}
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.8"), netip.MustParseAddr("2001:db8::8")}
	if err := reconcileHopTable("20000-20001", 443, addresses, nft); err == nil || applied != "" {
		t.Fatal("installer took ownership of an unrelated table")
	}
	owned = true
	if err := reconcileHopTable("20000-20001", 443, addresses, nft); err != nil ||
		!strings.Contains(applied, "ip daddr 192.0.2.8 fib daddr type local udp dport 20000-20001 redirect to :443") ||
		!strings.Contains(applied, "ip6 daddr 2001:db8::8 fib daddr type local udp dport 20000-20001 redirect to :443") || strings.Contains(applied, "unrelated") {
		t.Fatalf("unexpected hopping transaction: %v", err)
	}
	for _, scope := range []string{"ip daddr 192.0.2.8", "ip6 daddr 2001:db8::8"} {
		match := scope + " fib daddr type local udp dport 20000-20001"
		exempt := strings.Index(applied, match+" socket wildcard { 0, 1 } return")
		redirect := strings.Index(applied, match+" redirect to :443")
		if exempt < 0 || exempt > redirect {
			t.Fatalf("%s needs a live bound-socket check before redirect", scope)
		}
	}
	if err := reconcileHopTable("", 0, nil, nft); err != nil || applied != "delete table inet pipe\n" {
		t.Fatalf("unexpected removal transaction: %v", err)
	}
}
