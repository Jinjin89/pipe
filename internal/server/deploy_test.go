// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

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

func TestPrivateRescueListener(t *testing.T) {
	for _, address := range []string{"0.0.0.0:10001", "[::]:10001", "11.0.0.80:10001", "169.254.1.1:10001",
		"[fe80::1]:10001", "localhost:10001", "127.0.0.1:0", "[fc00::1%somewhere]:10001"} {
		if _, err := privateRescueAddress(address); err == nil {
			t.Errorf("accepted restricted bind %s", address)
		}
	}
	for _, address := range []string{"127.0.0.1:10001", "172.16.1.3:10001", "[::1]:10001", "[fd00::1]:10001"} {
		if _, err := privateRescueAddress(address); err != nil {
			t.Errorf("refused private bind %s: %v", address, err)
		}
	}
}

func TestSharedStateEndpointsAndFastRenewal(t *testing.T) {
	dir := t.TempDir()
	const rescueListen = "172.16.0.1:10001"
	options := InitOptions{
		Mode: Shared, Ports: Ports{Fast: 14443},
		FastSNI: "fast.example", FastHop: "20000-20010",
		RescueListen: "[::ffff:172.16.0.1]:10001",
	}
	if err := InitWithOptions(dir, "11.0.0.80", "static.example", options); err != nil {
		t.Fatal(err)
	}
	s, err := ReadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	var saved Settings
	if err := readJSON(filepath.Join(dir, settingsFile), &saved); err != nil || saved.RescueListen != rescueListen {
		t.Fatalf("private Rescue address was not saved in canonical form: %v", err)
	}
	raw, _, proxy, err := AddWithProxy(dir, "shared", false)
	if err != nil || proxy != "" {
		t.Fatalf("shared enrollment returned a proxy credential or failed: %v", err)
	}
	profile, err := link.Parse(raw)
	if err != nil || profile.FastEndpointPort() != 14443 || profile.StealthEndpointPort() != 8443 ||
		profile.FastServerName() != "fast.example" || profile.StealthServerName() != "fast.example" ||
		profile.FastHop != "20000-20010" || profile.FastPin == "" || profile.CDN != "static.example" {
		t.Fatalf("shared link has wrong endpoint metadata: %v", err)
	}
	before, err := s.fastKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cover, err := generateCoverSite(s.RealityPrivateKey)
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
	afterCover, err := generateCoverSite(again.RealityPrivateKey)
	if err != nil || !bytes.Equal(cover, afterCover) {
		t.Fatalf("cover should survive Fast certificate renewal: %v", err)
	}
	config := serverConfig(s, nil, "127.0.0.1", 12345, 0, nil)
	inbounds := config["inbounds"].([]engine.Object)
	if len(inbounds) != 2 || inbounds[0]["masquerade"].(engine.Object)["url"] != "http://127.0.0.1:12345" ||
		inbounds[1]["type"] != engine.SharedRescue || inbounds[1]["listen"] != rescueListen {
		t.Fatal("shared config without the HTTPS proxy should bind only Fast and private Rescue")
	}
	outbounds := config["outbounds"].([]engine.Object)
	if outbounds[1]["type"] != engine.InMemoryProbe {
		t.Fatal("shared health probes need a socket-free outbound")
	}
	installDir := filepath.Join(dir, "install")
	includePath := filepath.Join(installDir, "pipe-rescue.nginx")
	if err := os.Mkdir(installDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(includePath, []byte("old include"), 0644); err != nil {
		t.Fatal(err)
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
	for _, line := range []string{"Before=pipe.service", "Type=oneshot", "User=root", "RemainAfterExit=yes",
		"CapabilityBoundingSet=CAP_NET_ADMIN", "NoNewPrivileges=yes",
		"ExecStart=\"/tmp/pipe\" server hop-apply --fast-hop 20000-20010 --fast-port 14443", "WantedBy=multi-user.target"} {
		if !bytes.Contains(hopService, []byte(line+"\n")) {
			t.Errorf("hopping service is missing %q", line)
		}
	}
	if bytes.Contains(hopService, []byte(dir)) || bytes.Contains(hopService, []byte("--dir")) ||
		bytes.Contains(hopService, []byte("AmbientCapabilities=")) {
		t.Fatal("the root hopping service must not use the state directory or ambient capabilities")
	}
	include, err := os.ReadFile(includePath)
	if err != nil || !strings.Contains(string(include), "location = "+s.WSPath) ||
		!strings.Contains(string(include), "proxy_pass http://"+rescueListen+";") ||
		!strings.Contains(string(include), "proxy_set_header Host $http_host;") ||
		!strings.Contains(string(include), "access_log off;") {
		t.Fatalf("incomplete nginx location: %v", err)
	}
	if runtime.GOOS != "windows" {
		for path, mode := range map[string]os.FileMode{installDir: 0700, includePath: 0600} {
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
	if err := reconcileHopTable("20000-20001", 443, nft); err == nil || applied != "" {
		t.Fatal("installer took ownership of an unrelated table")
	}
	owned = true
	if err := reconcileHopTable("20000-20001", 443, nft); err != nil ||
		!strings.Contains(applied, "udp dport 20000-20001 redirect to :443") || strings.Contains(applied, "unrelated") {
		t.Fatalf("unexpected hopping transaction: %v", err)
	}
	if err := reconcileHopTable("", 0, nft); err != nil || applied != "delete table inet pipe\n" {
		t.Fatalf("unexpected removal transaction: %v", err)
	}
}
