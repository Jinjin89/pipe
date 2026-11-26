// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"testing/synctest"

	"pipe/internal/link"
	"pipe/internal/localfile"

	"github.com/caddyserver/certmagic"
)

type setupHarness struct {
	env         SetupEnv
	cmds        []SetupCommand
	updates     []setupUpdate
	issueErr    error
	issuedFresh []bool
	out         strings.Builder
	exists      bool // pipe user exists
	ifaces      []SetupInterface
	busy        map[int]bool
}

func newSetupHarness(t *testing.T, input string) *setupHarness {
	t.Helper()
	root := t.TempDir()
	h := &setupHarness{busy: map[int]bool{}}
	exe := filepath.Join(t.TempDir(), "pipe-src")
	if err := os.WriteFile(exe, []byte("binary-v1"), 0755); err != nil {
		t.Fatal(err)
	}
	h.ifaces = []SetupInterface{
		{Name: "lo", Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		{Name: "eth0", Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("100.64.1.1")}},
		{Name: "docker0", Addrs: []netip.Addr{netip.MustParseAddr("172.17.0.1")}},
		{Name: "br-abc", Addrs: []netip.Addr{netip.MustParseAddr("172.18.0.1"), netip.MustParseAddr("fd00::1")}},
	}
	suffix := 123
	h.env = SetupEnv{
		Root: root, GOOS: "linux", EUID: 0, Executable: exe,
		Run: func(ctx context.Context, c SetupCommand) error {
			h.cmds = append(h.cmds, c)
			if c.Argv[0] == "useradd" {
				h.exists = true
			}
			return h.fakeChild(ctx, c)
		},
		LookupPipeUser:  func() (uint32, uint32, bool, error) { return 990, 990, h.exists, nil },
		Chown:           func(string, uint32, uint32) error { return nil },
		chownStagedFile: func(*os.File, uint32, uint32) error { return nil },
		Interfaces:      func() ([]SetupInterface, error) { return h.ifaces, nil },
		probeBinding: func(b setupBinding) error {
			if b.network == "tcp" && !b.loopback && h.busy[int(b.port)] {
				return syscall.EADDRINUSE
			}
			return nil
		},
		occupiedUDPPorts: func() ([]uint16, error) { return nil, nil },
		Suffix: func() string {
			name := fmt.Sprintf("abc%d", suffix)
			suffix++
			return name
		},
		In: strings.NewReader(input), Out: &h.out,
	}
	return h
}

// fakeChild runs the same state transaction against the fixture without ACME.
func (h *setupHarness) fakeChild(ctx context.Context, c SetupCommand) error {
	if len(c.Argv) < 3 || c.Argv[0] != setupBinary {
		return nil
	}
	dir := h.env.path(c.Argv[len(c.Argv)-1])
	switch c.Argv[2] {
	case "setup":
		if c.Argv[3] == EnrollSetupDeviceCommand {
			return EnrollSetupDevice(h.env.path(c.Argv[4]), c.Argv[5], c.enrollmentFile)
		}
		var u setupUpdate
		if err := json.Unmarshal([]byte(c.Argv[5]), &u); err != nil {
			return err
		}
		h.updates = append(h.updates, u)
		path := func(value string) string {
			if value == "" || strings.HasPrefix(value, h.env.Root+string(filepath.Separator)) {
				return value
			}
			return h.env.path(value)
		}
		if u.Rescue != nil {
			cfg := *u.Rescue
			cfg.Cert, cfg.Key = path(cfg.Cert), path(cfg.Key)
			u.Rescue = &cfg
		}
		if u.Proxy != nil && u.Proxy.Listener != nil {
			change, cfg := *u.Proxy, *u.Proxy.Listener
			cfg.Cert, cfg.Key, cfg.WWW = path(cfg.Cert), path(cfg.Key), path(cfg.WWW)
			change.Listener, change.DNSFile = &cfg, path(change.DNSFile)
			u.Proxy = &change
		}
		hooks := proxySetup{
			lookup: func(context.Context, string, string) ([]netip.Addr, error) { return nil, nil },
			issue: func(_ context.Context, _, _ string, _ certmagic.DNSProvider, fresh bool) error {
				h.issuedFresh = append(h.issuedFresh, fresh)
				return h.issueErr
			},
		}
		return applySetupUpdate(ctx, h.env.path(c.Argv[4]), u, hooks, func(warning string) {
			fmt.Fprintln(&h.out, "Warning:", warning)
		})
	case "install":
		_, err := GenerateInstall(dir, setupBinary)
		return err
	case "add":
		_, _, _, err := AddWithProxy(dir, c.Argv[3], false)
		return err
	}
	return nil
}

func (h *setupHarness) argvs() []string {
	var out []string
	for _, c := range h.cmds {
		who := "root"
		if c.AsPipe {
			who = "pipe"
		}
		args := c.Argv
		if len(args) == 6 && args[3] == ApplySetupUpdateCommand {
			args = args[:5]
		}
		out = append(out, who+": "+strings.Join(args, " "))
	}
	return out
}

func (h *setupHarness) run(opts SetupOptions) error {
	return Setup(context.Background(), h.env, opts)
}

func wantCommands(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestSetupNeedsRoot(t *testing.T) {
	h := newSetupHarness(t, "")
	h.env.EUID = 1000
	err := h.run(SetupOptions{Yes: true})
	if err == nil || err.Error() != "run as root: sudo pipe server setup" {
		t.Fatalf("got %v", err)
	}
	h.env.EUID, h.env.GOOS = 0, "darwin"
	if err := h.run(SetupOptions{Yes: true}); err == nil {
		t.Fatal("expected error on non-Linux")
	}
	if len(h.cmds) != 0 {
		t.Fatal("no command may run")
	}
}

func TestSetupFreshStandalone(t *testing.T) {
	h := newSetupHarness(t, "")
	err := h.run(setupConfigOptions(t, `{"sni":"example.com","fast":{"hop":"20000-40000"},"proxy":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	d := "/var/lib/pipe"
	wantCommands(t, h.argvs(), []string{
		"root: useradd --system --home-dir /var/lib/pipe --shell /usr/sbin/nologin pipe",
		"pipe: " + setupBinary + " server setup --apply-setup " + d,
		"pipe: " + setupBinary + " server install --dir " + d,
		"pipe: " + setupBinary + " server setup --enroll-device " + d + " phone",
		"root: sysctl -p /etc/sysctl.d/90-pipe.conf",
		"root: systemctl daemon-reload",
		"root: systemctl enable pipe-hop",
		"root: systemctl restart pipe-hop",
		"root: systemctl enable pipe",
		"root: systemctl restart pipe",
	})
	for _, p := range []string{"/etc/systemd/system/pipe.service", "/etc/systemd/system/pipe-hop.service", "/etc/sysctl.d/90-pipe.conf", "/usr/local/bin/pipe"} {
		if _, err := os.Stat(filepath.Join(h.env.Root, p)); err != nil {
			t.Fatal(err)
		}
	}
	for _, line := range []string{"TCP 80 and 443 are free, so Pipe uses the standalone layout", "Point the DNS-only name example.com to 203.0.113.7."} {
		if !strings.Contains(h.out.String(), line) {
			t.Fatalf("missing %q:\n%s", line, h.out.String())
		}
	}
}

func TestSetupStandaloneNotesAllUnusedOverrides(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	must(t, h.run(setupConfigOptions(t, `{
		"ip":"203.0.113.4","sni":"origin.example",
		"cert":{"file":"/unused.pem","key":"/unused.key"}, "fast":{"port":2443},
		"stealth":{"port":8443},"proxy":{"port":9443},
		"rescue":{"sni":"rescue.example","port":2053,"cert":"/unused-rescue.pem","key":"/unused-rescue.key"}
	}`)))
	settings, err := ReadSettings(h.env.path(setupStateDir))
	must(t, err)
	if settings.Mode != Standalone || settings.Domain != "203.0.113.4" ||
		settings.fastName() != "origin.example" || settings.fastPort() != 2443 ||
		settings.webName() != "origin.example" || settings.stealthPort() != 443 ||
		!settings.proxyEnabled() || settings.rescuePort() != 443 || settings.Rescue != nil {
		t.Fatal("standalone setup did not use its built-in TCP layout and the requested Fast settings")
	}
	if !strings.Contains(h.out.String(), "Ignoring cert, stealth.port, proxy.port, rescue.port, rescue certificate files because the standalone layout uses automatic certificates and shares TCP 443.") {
		t.Fatalf("missing standalone note:\n%s", h.out.String())
	}
}

func setupRescueTestFiles(t *testing.T, h *setupHarness, domain string) {
	t.Helper()
	cert, key := writeProxyTestPair(t, domain, h.env.Root)
	must(t, os.Rename(cert, h.env.path("/rescue.pem")))
	must(t, os.Rename(key, h.env.path("/rescue-key.pem")))
}

func TestSetupFreshSharedYes(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	h.busy[443] = true
	probe := h.env.probeBinding
	binds := make(map[setupBinding]bool)
	h.env.probeBinding = func(b setupBinding) error {
		key := setupBinding{network: b.network, port: b.port, loopback: b.loopback}
		if binds[key] {
			t.Errorf("setup repeated a bind for %s port %d", b.network, b.port)
		}
		binds[key] = true
		if b.loopback && b.port == 10002 {
			return syscall.EADDRINUSE
		}
		return probe(b)
	}
	setupRescueTestFiles(t, h, "cdn.example.com")
	err := h.run(setupConfigOptions(t, `{
		"ip":"203.0.113.7","sni":"proxy.example.com",
		"fast":{"port":10443},"stealth":{"port":18443},"proxy":{"port":10001},
		"rescue":{"sni":"cdn.example.com","port":12053,"cert":"/rescue.pem","key":"/rescue-key.pem"},
		"device":"laptop"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	d := "/var/lib/pipe"
	wantCommands(t, h.argvs(), []string{
		"pipe: " + setupBinary + " server setup --apply-setup " + d,
		"pipe: " + setupBinary + " server install --dir " + d,
		"pipe: " + setupBinary + " server setup --enroll-device " + d + " laptop",
		"root: sysctl -p /etc/sysctl.d/90-pipe.conf",
		"root: systemctl daemon-reload",
		"root: systemctl enable pipe",
		"root: systemctl restart pipe",
	})
	if !strings.Contains(h.out.String(), RescuePortWarning(12053)) {
		t.Fatalf("missing the Cloudflare port warning:\n%s", h.out.String())
	}
	if got := h.updates[0].VMess; got != 10003 {
		t.Fatalf("VMess did not skip the proxy port and the occupied loopback port: %d", got)
	}
	if !strings.Contains(h.out.String(), "TCP 443 is in use, so Pipe uses the shared layout") {
		t.Fatal("shared setup did not explain its layout")
	}
	settings, err := ReadSettings(h.env.path(d))
	must(t, err)
	if settings.fastName() != "proxy.example.com" || settings.RealitySNI != settings.fastName() ||
		settings.HTTPSProxyListener.Domain != settings.fastName() || settings.RealityAddress != "127.0.0.1:10001" {
		t.Fatal("Fast, Stealth and the proxy do not share the intended server name and local target")
	}
	firewall, err := os.ReadFile(h.env.path(filepath.Join(d, "install", "pipe.nft")))
	must(t, err)
	if !strings.Contains(string(firewall), "tcp dport 18443 accept") {
		t.Fatal("firewall is missing the active Stealth port")
	}
	if strings.Contains(string(firewall), "tcp dport 12053") || strings.Contains(string(firewall), " drop") {
		t.Fatalf("unsafe Rescue firewall rules:\n%s", firewall)
	}
	if !strings.Contains(h.out.String(), "Open Rescue TCP 12053 in the firewall. Only Cloudflare needs it.") {
		t.Fatal("setup did not list the Rescue port")
	}
	for _, b := range setupBindings(settings) {
		if !binds[setupBinding{network: b.network, port: b.port, loopback: b.loopback}] {
			t.Errorf("setup did not bind-test %s port %d", b.name, b.port)
		}
	}
}

func TestSetupRejectsInvalidOptionsBeforeInstalling(t *testing.T) {
	for _, tc := range []struct {
		body, message string
		busy          int
	}{
		{`{"ip":"203.0.113.7"}`, "requires sni", 0},
		{`{"sni":"203.0.113.7"}`, "sni must be", 80},
		{`{"sni":"origin.example","ip":"other.example"}`, "ip must be", 0},
		{`{"sni":"origin.example","rescue":{"sni":"ORIGIN.example"}}`, "rescue.sni must differ", 0},
		{`{"sni":"origin.example","rescue":{"sni":"origin.EXAMPLE"}}`, "rescue.sni must differ", 443},
		{`{"sni":"origin.example","rescue":{}}`, "rescue.sni must be", 0},
		{`{"sni":"origin.example","rescue":{"sni":"rescue.example"}}`, "requires rescue.cert and rescue.key", 443},
		{`{"sni":"origin.example","proxy":{}}`, "TCP 80 is in use", 80},
		{`{"sni":"origin.example","proxy":{},"cert":{"dns":"cloudflare","key_file":"wrong.key"}}`, "cert requires", 80},
	} {
		h := newSetupHarness(t, "")
		h.busy[tc.busy] = true
		err := h.run(setupConfigOptions(t, tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.message) || len(h.cmds) != 0 {
			t.Errorf("%s got %v and commands %v, want %q and no commands", tc.body, err, h.argvs(), tc.message)
		}
	}
}

func TestSetupExistingInstall(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	state := filepath.Join(h.env.Root, setupStateDir)
	units := filepath.Join(h.env.Root, "/etc/systemd/system")
	for _, p := range []string{state, units, filepath.Join(h.env.Root, "/etc/sysctl.d")} {
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := InitWithOptions(state, "example.com", "", InitOptions{Mode: Standalone}); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := AddWithProxy(state, "phone", false)
	must(t, err)
	devices, err := os.ReadFile(filepath.Join(state, devicesFile))
	must(t, err)
	settings, err := ReadSettings(state)
	must(t, err)
	for _, file := range installArtifacts(settings, setupStateDir, setupBinary) {
		switch file.name {
		case "pipe.service":
			must(t, os.WriteFile(filepath.Join(units, file.name), []byte(file.contents), file.mode))
		case "90-pipe.conf":
			must(t, os.WriteFile(h.env.path(filepath.Join(setupSysctlDir, file.name)), []byte(file.contents), file.mode))
		}
	}
	h.busy[80], h.busy[443] = true, true
	h.env.probeBinding = func(b setupBinding) error {
		t.Errorf("setup probed saved %s port %d", b.network, b.port)
		return syscall.EADDRINUSE
	}
	if err := h.run(setupConfigOptions(t, `{"sni":"example.com","proxy":{},"device":"phone"}`)); err != nil {
		t.Fatal(err)
	}
	for _, a := range h.argvs() {
		if strings.Contains(a, " init ") || strings.Contains(a, " add ") {
			t.Fatalf("unexpected %s", a)
		}
	}
	if os.Geteuid() == 0 && strings.Contains(h.out.String(), "Wrote ") {
		t.Fatalf("unchanged units must not be rewritten:\n%s", h.out.String())
	}
	if !strings.Contains(h.out.String(), "Keeping the saved standalone layout") {
		t.Fatal("missing summary")
	}
	if !strings.Contains(h.out.String(), "Its existing link stays valid") {
		t.Fatal("missing retained device message")
	}
	gotDevices, err := os.ReadFile(filepath.Join(state, devicesFile))
	must(t, err)
	if string(gotDevices) != string(devices) {
		t.Fatal("existing device credentials changed")
	}
	if _, _, _, err := AddWithProxy(state, "phone", false); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("explicit duplicate enrollment: %v", err)
	}
	// A stale unit is rewritten.
	_ = os.WriteFile(filepath.Join(units, "pipe.service"), []byte("ExecStart=/tmp/pipe\n"), 0644)
	h.out.Reset()
	h.cmds = nil
	if err := h.run(SetupOptions{Yes: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.out.String(), "Wrote /etc/systemd/system/pipe.service") {
		t.Fatalf("stale unit not rewritten:\n%s", h.out.String())
	}
}

func TestSetupRequiresAuthorizationForSavedHopping(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	must(t, h.run(SetupOptions{Yes: true, SetupConfig: SetupConfig{SNI: "origin.example"}}))
	dir := h.env.path(setupStateDir)
	saved, err := ReadSettings(dir)
	must(t, err)
	saved.FastHop, saved.Ports.Fast = "20000-20010", 2443
	must(t, writeJSON(dir, settingsFile, saved))
	h.cmds = nil

	path := h.env.path(filepath.Join(setupUnitDir, hopServiceUnit))
	err = h.run(SetupOptions{Yes: true})
	if err == nil || !strings.Contains(err.Error(), "authorized setup values") || len(h.cmds) != 0 {
		t.Fatalf("setup accepted hopping from saved state alone: %v, commands %v", err, h.argvs())
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("setup wrote a hop unit without authorization: %v", err)
	}

	fast := SetupFast{Hop: "20000-20010"}
	if err := h.run(SetupOptions{Yes: true, SetupConfig: SetupConfig{Fast: fast}}); err == nil || len(h.cmds) != 0 {
		t.Fatalf("setup accepted a range without an authorized target: %v, commands %v", err, h.argvs())
	}
	fast.Port = 2443
	must(t, h.run(SetupOptions{Yes: true, SetupConfig: SetupConfig{Fast: fast}}))
	data, err := os.ReadFile(path)
	must(t, err)
	if !strings.Contains(string(data), "server hop-apply --fast-hop 20000-20010 --fast-port 2443") ||
		!slices.Contains(h.argvs(), "root: systemctl restart pipe-hop") {
		t.Fatal("explicitly authorized hopping was not installed and applied")
	}
}

func TestSetupReusesRootOwnedHopSettings(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires a root-owned fixture")
	}
	h := newSetupHarness(t, "")
	h.exists = true
	must(t, h.run(setupConfigOptions(t, `{"sni":"origin.example","fast":{"port":2443,"hop":"20000-20010"}}`)))
	path := h.env.path(filepath.Join(setupUnitDir, hopServiceUnit))
	before, err := os.ReadFile(path)
	must(t, err)

	must(t, os.Chmod(path, 0664))
	h.cmds = nil
	if err := h.run(SetupOptions{Yes: true}); err == nil || len(h.cmds) != 0 {
		t.Fatalf("setup accepted a writable hop unit: %v, commands %v", err, h.argvs())
	}
	must(t, os.Chmod(path, 0644))
	must(t, h.run(SetupOptions{Yes: true}))
	after, err := os.ReadFile(path)
	must(t, err)
	if !slices.Equal(before, after) || !slices.Contains(h.argvs(), "root: systemctl restart pipe-hop") {
		t.Fatal("rerun did not preserve and apply the installed root-owned hop settings")
	}

	dir := h.env.path(setupStateDir)
	saved, err := ReadSettings(dir)
	must(t, err)
	saved.Ports.Fast = 25443
	must(t, writeJSON(dir, settingsFile, saved))
	h.cmds = nil
	if err := h.run(SetupOptions{Yes: true}); err == nil || len(h.cmds) != 0 {
		t.Fatalf("setup accepted an unauthorized hop target: %v, commands %v", err, h.argvs())
	}
	must(t, h.run(SetupOptions{Yes: true, SetupConfig: SetupConfig{Fast: SetupFast{Port: 25443}}}))
	after, err = os.ReadFile(path)
	must(t, err)
	if !strings.Contains(string(after), "server hop-apply --fast-hop 20000-20010 --fast-port 25443") ||
		!slices.Contains(h.argvs(), "root: systemctl restart pipe-hop") {
		t.Fatal("setup did not apply the requested port with the installed range")
	}
}

func TestSetupChecksHopSettingsAfterChildCommits(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	dir := h.env.path(setupStateDir)
	run := h.env.Run
	h.env.Run = func(ctx context.Context, c SetupCommand) error {
		if err := run(ctx, c); err != nil {
			return err
		}
		if c.AsPipe && c.Argv[2] == "setup" && c.Argv[3] == ApplySetupUpdateCommand {
			saved, err := ReadSettings(dir)
			must(t, err)
			saved.Ports.Fast = 2444
			return writeJSON(dir, settingsFile, saved)
		}
		return nil
	}

	err := h.run(setupConfigOptions(t, `{"sni":"origin.example","fast":{"port":2443,"hop":"20000-20010"}}`))
	if err == nil || !strings.Contains(err.Error(), "authorized setup values") {
		t.Fatalf("setup accepted a changed hop target after the child committed: %v", err)
	}
	if len(h.cmds) != 1 || !h.cmds[0].AsPipe {
		t.Fatalf("commands after the child changed the hop target: %v", h.argvs())
	}
	if _, err := os.Lstat(h.env.path(filepath.Join(setupUnitDir, hopServiceUnit))); !os.IsNotExist(err) {
		t.Fatalf("setup installed a hop unit after the child changed the target: %v", err)
	}
}

func TestSetupBinaryCopySkippedWhenIdentical(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	dest := filepath.Join(h.env.Root, setupBinary)
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("binary-v1"), 0755); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(dest)
	if err := h.run(setupConfigOptions(t, `{"sni":"example.com","proxy":{}}`)); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(dest)
	if !os.SameFile(before, after) || strings.Contains(h.out.String(), "Installed ") {
		t.Fatal("identical binary must not be copied")
	}
}

func TestSetupDNSKeyFileStagedAndRemoved(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	if err := os.WriteFile(filepath.Join(h.env.Root, "ali.key"), []byte("access_key_id=fixture\naccess_key_secret=value"), 0600); err != nil {
		t.Fatal(err)
	}
	var seen string
	var stagedDescriptor os.FileInfo
	h.env.Chown = func(path string, _, _ uint32) error {
		if strings.HasPrefix(filepath.Base(path), ".setup-") {
			t.Error("setup changed a staged file by pathname")
		}
		return nil
	}
	h.env.chownStagedFile = func(f *os.File, uid, gid uint32) error {
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || uid != 990 || gid != 990 {
			t.Errorf("unexpected staged file mode or ownership request: %v, %d:%d", info.Mode(), uid, gid)
		}
		stagedDescriptor = info
		return nil
	}
	run := h.env.Run
	h.env.Run = func(ctx context.Context, c SetupCommand) error {
		staged, _ := filepath.Glob(filepath.Join(h.env.Root, setupStateDir, ".setup-*"))
		if c.AsPipe && c.Argv[2] == "setup" && c.Argv[3] == ApplySetupUpdateCommand {
			var update setupUpdate
			must(t, json.Unmarshal([]byte(c.Argv[5]), &update))
			seen = update.Proxy.DNSFile
			info, err := os.Lstat(h.env.path(seen))
			must(t, err)
			if stagedDescriptor == nil || !os.SameFile(stagedDescriptor, info) {
				t.Error("setup staged the input outside its state directory descriptor")
			}
			data, err := os.ReadFile(h.env.path(seen))
			if err != nil || string(data) != "access_key_id=fixture\naccess_key_secret=value" {
				t.Errorf("staged key unreadable: %v", err)
			}
		} else if len(staged) != 0 {
			t.Errorf("secret copy exists outside its child: %v", staged)
		}
		return run(ctx, c)
	}
	h.busy[80] = true
	err := h.run(setupConfigOptions(t, `{"sni":"proxy.example.com","proxy":{},"cert":{"dns":"alidns","key_file":"/ali.key"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if seen != "/var/lib/pipe/.setup-abc123" || stagedDescriptor == nil {
		t.Fatalf("staged path %q, descriptor %v", seen, stagedDescriptor)
	}
	if _, err := os.Stat(filepath.Join(h.env.Root, seen)); !os.IsNotExist(err) {
		t.Fatal("staged key must be removed")
	}
}

func TestSetupPassesManagedDNSFileToPipe(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	state := h.env.path(setupStateDir)
	s := initSharedSetupState(t, state)
	name := proxyDNSSecretPrefix + strings.Repeat("a", 32)
	s.HTTPSProxyListener = &httpsProxyListenerConfig{Domain: "proxy.example", Port: 9443, CertMethod: "dns", DNS: "cloudflare", DNSSecret: name}
	must(t, writeJSON(state, settingsFile, s))
	// A managed credential is read by the child, not staged by root.
	must(t, os.WriteFile(filepath.Join(state, name), []byte("fixture-token"), 0600))
	h.env.chownStagedFile = func(*os.File, uint32, uint32) error {
		t.Error("setup staged a managed credential")
		return nil
	}
	must(t, h.run(SetupOptions{Yes: true, SetupConfig: SetupConfig{Proxy: &SetupPort{Port: 9943}}}))
	if len(h.updates) != 1 || h.updates[0].Proxy.DNSFile != "" || h.updates[0].Proxy.Listener.DNSSecret != name {
		t.Fatal("the update did not keep the managed DNS credential")
	}
}

func TestSetupRejectsSymlinkCredential(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	must(t, os.WriteFile(h.env.path("/operator-key"), []byte("fixture"), 0600))
	must(t, os.Symlink(h.env.path("/operator-key"), h.env.path("/key-link")))
	h.busy[80] = true
	err := h.run(setupConfigOptions(t, `{"sni":"proxy.example","proxy":{},"cert":{"dns":"cloudflare","token_file":"/key-link"}}`))
	if err == nil {
		t.Fatal("setup accepted a symlink credential")
	}
	for _, cmd := range h.argvs() {
		if strings.Contains(cmd, " --apply-setup ") {
			t.Fatalf("setup forwarded a symlink credential: %s", cmd)
		}
	}
}

func TestSetupRendersPrivilegedFilesIndependentlyOfInstallOutput(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	state := h.env.path(setupStateDir)
	run := h.env.Run
	h.env.Run = func(ctx context.Context, c SetupCommand) error {
		if err := run(ctx, c); err != nil {
			return err
		}
		if c.AsPipe && c.Argv[2] == "install" {
			if !c.installFromSetup {
				t.Fatal("the setup installer child must suppress its manual setup hints")
			}
			for _, name := range []string{"pipe.service", "pipe-hop.service"} {
				must(t, os.WriteFile(filepath.Join(state, "install", name), []byte("fixture artifact\n"), 0644))
			}
			// Even a matching file must be installed directly by setup.
			must(t, os.MkdirAll(h.env.path(setupSysctlDir), 0755))
			must(t, os.Symlink(filepath.Join(state, "install", "90-pipe.conf"), h.env.path(filepath.Join(setupSysctlDir, "90-pipe.conf"))))
		}
		return nil
	}
	must(t, h.run(setupConfigOptions(t, `{"sni":"origin.example","proxy":{}}`)))
	s, err := ReadSettings(state)
	must(t, err)
	for _, f := range installArtifacts(s, setupStateDir, setupBinary) {
		dir := setupUnitDir
		switch f.name {
		case "90-pipe.conf":
			dir = setupSysctlDir
		case "pipe.nft":
			continue
		}
		path := h.env.path(filepath.Join(dir, f.name))
		info, err := os.Lstat(path)
		must(t, err)
		if !info.Mode().IsRegular() {
			t.Errorf("installed %s is not a regular file", f.name)
		}
		installed, err := os.ReadFile(path)
		must(t, err)
		if string(installed) != f.contents {
			t.Errorf("installed %s differs from root rendering", f.name)
		}
	}
	if _, err := os.Stat(h.env.path(filepath.Join(setupUnitDir, "pipe-hop.service"))); !os.IsNotExist(err) {
		t.Fatalf("setup installed an unconfigured hop service: %v", err)
	}
	for _, argv := range h.argvs() {
		if strings.HasPrefix(argv, "root: systemctl ") && strings.HasSuffix(argv, " pipe-hop") {
			t.Fatal("setup activated an unconfigured hop service")
		}
	}
}

func TestSetupInteractiveShared(t *testing.T) {
	input := strings.Join([]string{
		"proxy.example.com", "203.0.113.7", "", "", "y", "", "", "cloudflare", "/cf-token",
		"cdn.example.com", "", "/rescue.pem", "/rescue-key.pem", "tablet",
	}, "\n") + "\n"
	h := newSetupHarness(t, input)
	h.exists = true
	setupRescueTestFiles(t, h, "cdn.example.com")
	must(t, os.WriteFile(h.env.path("/cf-token"), []byte("fixture"), 0600))
	h.busy[80] = true
	if err := h.run(SetupOptions{}); err != nil {
		t.Fatal(err)
	}
	d := "/var/lib/pipe"
	wantCommands(t, h.argvs()[:3], []string{
		"pipe: " + setupBinary + " server setup --apply-setup " + d,
		"pipe: " + setupBinary + " server install --dir " + d,
		"pipe: " + setupBinary + " server add tablet --dir " + d,
	})
	u := h.updates[0]
	if u.Initial.Domain != "203.0.113.7" || u.Initial.FastSNI != "proxy.example.com" ||
		u.Rescue.Port != 2053 || u.Proxy.Listener.DNS != "cloudflare" || u.Proxy.DNSFile == "" {
		t.Fatal("interactive setup did not use the entered choices")
	}
	if !strings.Contains(h.out.String(), "TCP 80 is in use, so Pipe uses the shared layout") {
		t.Fatal("expected a reason for the shared layout")
	}
	if strings.Count(h.out.String(), "(SNI)") != 1 || strings.Contains(h.out.String(), "Mode (") {
		t.Fatal("setup should prompt for one SNI and derive the layout")
	}
}

func TestSetupInteractiveSharedWithoutProxy(t *testing.T) {
	h := newSetupHarness(t, "fast.example.com\n203.0.113.7\n\n\nn\n\nphone\n")
	h.exists = true
	h.busy[443] = true
	must(t, h.run(SetupOptions{}))
	settings, err := ReadSettings(h.env.path(setupStateDir))
	must(t, err)
	if settings.fastName() != "fast.example.com" || settings.Domain != "203.0.113.7" || settings.HTTPSProxyListener != nil {
		t.Fatal("shared setup did not keep the Fast name or omit the HTTPS proxy")
	}
	if strings.Contains(h.out.String(), "Stealth TCP port [") {
		t.Fatal("setup asked for a Stealth port after the proxy was declined")
	}
	assertSetupStealthOff(t, h, settings.stealthPort())
}

func TestSetupSharedStealthPortWithoutProxy(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	h.busy[443] = true
	const port = 17443
	h.busy[port] = true

	must(t, h.run(setupConfigOptions(t, fmt.Sprintf(`{"sni":"fast.example","stealth":{"port":%d}}`, port))))
	state := h.env.path(setupStateDir)
	settings, err := ReadSettings(state)
	must(t, err)
	if settings.stealthPort() != uint16(port) {
		t.Fatal("setup did not save the configured Stealth port")
	}
	assertSetupStealthOff(t, h, uint16(port))
	_, hints, err := Install(t.Context(), state, setupBinary, Shared, nil)
	must(t, err)
	for _, hint := range hints {
		if strings.Contains(hint, fmt.Sprintf("Stealth TCP %d", port)) {
			t.Fatalf("install advertised an inactive port: %s", hint)
		}
	}
}

func assertSetupStealthOff(t *testing.T, h *setupHarness, port uint16) {
	t.Helper()
	if !strings.Contains(h.out.String(), "Stealth is off in the shared layout. Add a proxy section") {
		t.Fatalf("setup did not explain why Stealth is off:\n%s", h.out.String())
	}
	nft, err := os.ReadFile(h.env.path(filepath.Join(setupStateDir, "install", "pipe.nft")))
	must(t, err)
	if strings.Contains(string(nft), fmt.Sprintf("tcp dport %d ", port)) {
		t.Fatalf("firewall includes inactive Stealth port %d", port)
	}
}

func TestSetupDetect(t *testing.T) {
	h := newSetupHarness(t, "")
	h.busy[443] = true
	run := &setupRun{SetupEnv: h.env}
	d, err := run.detect(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.PublicIPs) != 1 || d.PublicIPs[0].String() != "203.0.113.7" {
		t.Fatalf("public IPs %v", d.PublicIPs)
	}
	if d.suggestedMode() != Shared || d.Port80Busy || !d.Port443Busy {
		t.Fatalf("%+v", d)
	}
	h.busy = map[int]bool{}
	run.portChecks = nil
	if d, _ = run.detect(true); d.suggestedMode() != Standalone {
		t.Fatal("free ports suggest standalone")
	}
}

func TestSetupAutoMethodResolvedAsRoot(t *testing.T) {
	for name, tc := range map[string]struct {
		busy   bool
		cert   *SetupCertificate
		method string
	}{
		"free 80":  {method: "http"},
		"dns flag": {busy: true, cert: &SetupCertificate{DNS: "cloudflare", TokenFile: "/token"}, method: "dns"},
	} {
		h := newSetupHarness(t, "")
		h.exists = true
		h.busy[80], h.busy[443] = tc.busy, true
		must(t, os.WriteFile(h.env.path("/token"), []byte("fixture"), 0600))
		o := SetupOptions{Yes: true, SetupConfig: SetupConfig{SNI: "proxy.example.com", Cert: tc.cert}}
		if err := h.run(o); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(h.updates) != 1 || h.updates[0].Proxy.Listener.method() != tc.method {
			t.Errorf("%s: expected %s for the certificate", name, tc.method)
		}
	}
}

func TestSetupRefusesOpenSecretFile(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	key := filepath.Join(h.env.Root, "ali.key")
	if err := os.WriteFile(key, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	h.busy[80] = true
	err := h.run(setupConfigOptions(t, `{"sni":"proxy.example","proxy":{},"cert":{"dns":"alidns","key_file":"/ali.key"}}`))
	if err == nil {
		t.Fatal("group/world-readable key must be refused")
	}
}

func TestSetupChownsExistingStateWithoutSymlinks(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	state := filepath.Join(h.env.Root, setupStateDir)
	if err := InitWithOptions(state, "example.com", "", InitOptions{Mode: Standalone}); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(h.env.Root, "outside")
	_ = os.WriteFile(outside, nil, 0600)
	_ = os.Symlink(outside, filepath.Join(state, "link"))
	got := map[string]bool{}
	h.env.Chown = func(p string, uid, _ uint32) error { got[p] = uid == 990; return nil }
	if err := h.run(SetupOptions{Yes: true}); err != nil {
		t.Fatal(err)
	}
	if !got[filepath.Join(state, "server.json")] || got[filepath.Join(state, "link")] || got[outside] {
		t.Fatalf("chown set: %v", got)
	}
}

func TestSetupRejectsUnsafeStatePath(t *testing.T) {
	for _, kind := range []string{"symlink", "writable parent", "sticky writable parent", "service-owned parent"} {
		t.Run(kind, func(t *testing.T) {
			h := newSetupHarness(t, "")
			h.exists = true
			parent := h.env.path("/custom")
			outside := h.env.path("/outside")
			must(t, os.Mkdir(parent, 0755))
			must(t, InitWithOptions(outside, "origin.example", "", InitOptions{Mode: Standalone}))
			must(t, os.Chmod(outside, 0755))
			switch kind {
			case "symlink":
				must(t, os.Symlink(outside, filepath.Join(parent, "state")))
			case "writable parent":
				must(t, os.Chmod(parent, 0777))
			case "sticky writable parent":
				must(t, os.Chmod(parent, 0777|os.ModeSticky))
			case "service-owned parent":
				if os.Geteuid() != 0 {
					t.Skip("changing the fixture owner requires root")
				}
				must(t, os.Chown(parent, 990, 990))
			}
			h.env.Chown = func(path string, _, _ uint32) error {
				t.Errorf("changed ownership of %s", path)
				return nil
			}
			err := h.run(SetupOptions{Dir: "/custom/state", Yes: true})
			if err == nil || len(h.cmds) != 0 {
				t.Fatalf("unsafe path accepted: %v, commands %v", err, h.argvs())
			}
			switch kind {
			case "writable parent":
				if !strings.Contains(err.Error(), "run: chmod go-w ") {
					t.Fatalf("writable parent error lacks the chmod hint: %v", err)
				}
			case "sticky writable parent":
				want := fmt.Sprintf("unsafe setup path %q: %q is group- or world-writable; choose a path under a protected directory writable only by root or the operator (for example, /root/pipe/setup.json for input or /var/lib/pipe for state)", filepath.Join(parent, "state"), parent)
				if err.Error() != want {
					t.Fatalf("sticky writable parent error = %v, want %q", err, want)
				}
			}
			info, err := os.Stat(outside)
			must(t, err)
			if info.Mode().Perm() != 0755 {
				t.Fatal("setup changed the mode of the symlink target")
			}
			if kind != "symlink" {
				if _, err := os.Lstat(filepath.Join(parent, "state")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("setup created a directory under the unsafe parent: %v", err)
				}
			}
		})
	}
}

func TestSetupDNSIssuanceTimeoutIncludesTokenHint(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(t.TempDir(), "token")
	must(t, os.WriteFile(token, []byte("fixture-token"), 0600))
	cfg, source, err := proxyConfigForEnable(ProxyEnableOptions{
		Domain: testProxyDomain, CertMethod: "dns", DNS: proxyDNSCloudflare, DNSTokenFile: token,
	})
	must(t, err)
	update := setupUpdate{
		Initial: &setupInitialSettings{Mode: Shared, Domain: testProxyDomain},
		Proxy:   &setupProxyUpdate{Enabled: true, Listener: &cfg, DNSFile: source},
	}
	hooks := testProxySetup()
	hooks.issue = func(ctx context.Context, _, _ string, _ certmagic.DNSProvider, _ bool) error {
		<-ctx.Done()
		return errors.New("fixture-token")
	}
	synctest.Test(t, func(t *testing.T) {
		err := applySetupUpdate(t.Context(), dir, update, hooks, nil)
		if err == nil || !strings.Contains(err.Error(), "initial HTTPS proxy DNS-01 issuance timed out for "+testProxyDomain) ||
			!strings.Contains(err.Error(), "works from this server's IP address and can edit the zone") ||
			!strings.Contains(err.Error(), "Cloudflare tokens can be IP-restricted") || strings.Contains(err.Error(), "fixture-token") {
			t.Fatalf("unexpected setup timeout error: %v", err)
		}
	})
}

func TestSetupStagesUnderOpenedDirectory(t *testing.T) {
	h := newSetupHarness(t, "")
	dir, saved, outside := h.env.path("/state"), h.env.path("/moved"), h.env.path("/outside")
	must(t, os.Mkdir(dir, 0700))
	must(t, os.Mkdir(outside, 0700))
	must(t, os.WriteFile(h.env.path("/operator-credential"), []byte("credential"), 0600))
	state, err := openSetupState(dir, 990, false)
	must(t, err)
	defer state.Close()
	must(t, os.Rename(dir, saved))
	must(t, os.Symlink(outside, dir))

	r := setupRun{SetupEnv: h.env, uid: 990, gid: 990, opts: SetupOptions{Dir: "/state"}, state: state}
	staged, err := r.stage("/operator-credential", 4096, true)
	must(t, err)
	name := filepath.Base(staged)
	body, err := os.ReadFile(filepath.Join(saved, name))
	must(t, err)
	if string(body) != "credential" {
		t.Fatal("staged file is missing from the opened directory")
	}
	if _, err := os.Lstat(filepath.Join(outside, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged a credential in the symlink target: %v", err)
	}
}

func TestSetupAskStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pr, _ := io.Pipe() // never delivers a line
	var out strings.Builder
	r := &setupRun{ctx: ctx, SetupEnv: SetupEnv{Out: &out}, in: bufio.NewReader(pr)}
	cancel()
	if got := r.ask("Name", "dflt"); got != "dflt" {
		t.Fatalf("got %q", got)
	}
}

func TestSetupMigratesRetiredRescueAndProxyAsPipe(t *testing.T) {
	for _, port := range []uint16{9943, 9944} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			h := newSetupHarness(t, "")
			h.exists = true
			h.busy[80] = true
			setupRescueTestFiles(t, h, "rescue.example")
			writeProxyTestPair(t, "proxy.example", h.env.Root)
			state := h.env.path(setupStateDir)
			before := initSharedSetupState(t, state)
			before.CDNDomain, before.RescueListen = "rescue.example", "127.0.0.1:18080"
			before.HTTPSProxyListener = &httpsProxyListenerConfig{Domain: "proxy.example", Port: 9943, CertMethod: "nginx", ACMEListen: "127.0.0.1:18081"}
			before.borrowProxySite()
			must(t, writeJSON(state, settingsFile, before))
			raw, _, _, err := AddWithProxy(state, "phone", false)
			must(t, err)
			retired, err := link.Parse(raw)
			must(t, err)
			if retired.HTTPSProxy != "" || retired.CDN != "" || retired.WSPath != "" {
				t.Fatal("enrollment while the listeners are retired should omit hp, cdn and wsp")
			}
			legacy := retired
			legacy.HTTPSProxy = "proxy.example:9943"
			legacy.CDN, legacy.WSPath = before.CDNDomain, before.WSPath
			legacyRaw, err := legacy.Encode()
			must(t, err)
			devicesBefore, err := ReadDevices(state)
			must(t, err)
			devicesBefore[0].HTTPSProxyPassword = ""
			must(t, writeJSON(state, devicesFile, devicesBefore))
			h.env.probeBinding = func(b setupBinding) error {
				if b.port == before.fastPort() && b.network == "udp" ||
					b.network == "tcp" && (b.port == before.stealthPort() || b.port == before.HTTPSProxyListener.Port) {
					t.Errorf("setup attempted to bind a saved legacy %s port %d", b.network, b.port)
					return syscall.EADDRINUSE
				}
				return nil
			}
			devices, err := os.ReadFile(filepath.Join(state, devicesFile))
			must(t, err)

			must(t, h.run(setupConfigOptions(t, fmt.Sprintf(`{
				"sni":"proxy.example","device":"phone","proxy":{"port":%d},
				"cert":{"file":"/fullchain.pem","key":"/key.pem"},
				"rescue":{"sni":"rescue.example","port":2096,"cert":"/rescue.pem","key":"/rescue-key.pem"}
			}`, port))))
			if len(h.updates) != 1 || !h.cmds[0].AsPipe {
				t.Fatal("migration must use one unprivileged state update")
			}
			after, err := ReadSettings(state)
			must(t, err)
			gotDevices, err := os.ReadFile(filepath.Join(state, devicesFile))
			must(t, err)
			if after.fastName() != before.fastName() || after.HTTPSProxyListener.Domain != "proxy.example" ||
				after.RealityPrivateKey != before.RealityPrivateKey || string(gotDevices) != string(devices) {
				t.Fatal("migration changed the saved names, keys or devices")
			}
			for _, want := range []string{
				"Keeping the saved Fast TLS name origin.example and HTTPS proxy name proxy.example.",
				"Open Rescue TCP 2096 in the firewall. Only Cloudflare needs it.", "old configuration file from the website's nginx",
				"Re-add device \"phone\" to give it an HTTPS proxy password",
			} {
				if !strings.Contains(h.out.String(), want) {
					t.Errorf("missing migration note %q in %s", want, h.out.String())
				}
			}
			updates := map[string]string{"hp": fmt.Sprintf("proxy.example:%d", port), "cdn": "rescue.example:2096", "wsp": before.WSPath}
			for key, value := range updates {
				want := fmt.Sprintf("In each device link, set %s=%s (replace it if present, otherwise add it).", key, value)
				if !strings.Contains(h.out.String(), want) {
					t.Errorf("missing migration note %q", want)
				}
			}
			export := fmt.Sprintf("Use proxy.example:%d in existing export https_proxy and http_proxy lines.", port)
			if strings.Contains(h.out.String(), export) != (port != 9943) {
				t.Errorf("wrong export instructions for proxy port %d:\n%s", port, h.out.String())
			}
			for _, linkBefore := range []string{legacyRaw, raw} {
				u, err := url.Parse(linkBefore)
				must(t, err)
				params := u.Query()
				for key, value := range updates {
					params.Set(key, value)
				}
				u.RawQuery = params.Encode()
				profile, err := link.Parse(u.String())
				must(t, err)
				if profile.HTTPSProxy != updates["hp"] || profile.CDNEndpoint() != updates["cdn"] || profile.WSPath != updates["wsp"] {
					t.Fatal("updated device link does not point to the new proxy and Rescue")
				}
			}
			staged, err := filepath.Glob(filepath.Join(state, ".setup-*"))
			must(t, err)
			if len(staged) != 0 {
				t.Errorf("staged PEM files remain: %v", staged)
			}
		})
	}
}

func TestSetupClearsRescueAndKeepsProxyCertificateOnPortChange(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	state := h.env.path(setupStateDir)
	s := initSharedSetupState(t, state)
	s.CDNDomain, s.Ports.VMess = "rescue.example", 10001
	s.Rescue = &RescueConfig{Port: 2053, Cert: "/old.pem", Key: "/old-key.pem"}
	cert, key := writeProxyTestPair(t, "proxy.example", h.env.Root)
	s.HTTPSProxyListener = &httpsProxyListenerConfig{Domain: "proxy.example", Port: 9443, CertMethod: "files", Cert: cert, Key: key}
	must(t, writeJSON(state, settingsFile, s))
	h.busy[2053] = true
	must(t, h.run(SetupOptions{Yes: true, ClearRescue: true, SetupConfig: SetupConfig{Proxy: &SetupPort{Port: 2053}}}))
	after, err := ReadSettings(state)
	must(t, err)
	if len(h.updates) != 1 || after.Rescue != nil || after.HTTPSProxyListener.Port != 2053 ||
		after.HTTPSProxyListener.Cert != cert || after.HTTPSProxyListener.Key != key {
		t.Fatal("the same update must clear Rescue and move the existing proxy")
	}
}

func initSharedSetupState(t *testing.T, dir string) Settings {
	t.Helper()
	must(t, InitWithOptions(dir, "origin.example", "", InitOptions{Mode: Shared}))
	s, err := ReadSettings(dir)
	must(t, err)
	return s
}

func TestSetupFirstRescueUsesSavedWebSocketPath(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	state := h.env.path(setupStateDir)
	s := initSharedSetupState(t, state)
	_, _, _, err := AddWithProxy(state, "phone", false)
	must(t, err)
	setupRescueTestFiles(t, h, "rescue.example")
	must(t, h.run(setupConfigOptions(t, `{"sni":"origin.example","device":"phone",
		"rescue":{"sni":"rescue.example","cert":"/rescue.pem","key":"/rescue-key.pem"}}`)))
	for _, want := range []string{
		"Open Rescue TCP 2053 in the firewall. Only Cloudflare needs it.",
		"In each device link, set cdn=rescue.example:2053 (replace it if present, otherwise add it).",
		"In each device link, set wsp=" + s.WSPath + " (replace it if present, otherwise add it).",
		"Its existing link stays valid",
	} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("missing setup note %q", want)
		}
	}
	for _, c := range h.argvs() {
		if strings.Contains(c, " server add ") {
			t.Errorf("existing device was re-enrolled: %s", c)
		}
	}
}

func TestSetupOmissionsTurnOffOptionalServicesOnRerun(t *testing.T) {
	for _, mode := range []DeployMode{Standalone, Shared} {
		t.Run(string(mode), func(t *testing.T) {
			h := newSetupHarness(t, "")
			h.exists = true
			h.busy[443] = mode == Shared
			setupRescueTestFiles(t, h, "rescue.example")
			must(t, h.run(setupConfigOptions(t, `{
				"sni":"origin.example","proxy":{},"device":"phone",
				"rescue":{"sni":"rescue.example","cert":"/rescue.pem","key":"/rescue-key.pem"}
			}`)))
			state := h.env.path(setupStateDir)
			before, err := ReadSettings(state)
			must(t, err)
			if before.Mode != mode || before.rescuePort() == 0 || before.proxyAuthority() == "" {
				t.Fatal("the initial setup did not enable Rescue and the proxy")
			}
			devices, err := os.ReadFile(filepath.Join(state, devicesFile))
			must(t, err)
			h.cmds = nil
			h.out.Reset()
			h.busy[80], h.busy[443] = mode == Standalone, mode == Standalone
			must(t, h.run(setupConfigOptions(t, `{"sni":"origin.example","stealth":{"port":10443}}`)))
			after, err := ReadSettings(state)
			must(t, err)
			gotDevices, err := os.ReadFile(filepath.Join(state, devicesFile))
			must(t, err)
			if after.Mode != mode || after.RealityPrivateKey != before.RealityPrivateKey || after.WSPath != before.WSPath ||
				!slices.Equal(after.FastPrivateKey, before.FastPrivateKey) || string(gotDevices) != string(devices) {
				t.Fatal("rerun changed the deployment type, keys or devices")
			}
			if after.rescuePort() != 0 || after.proxyAuthority() != "" {
				t.Fatal("omitting the optional services did not disable them")
			}
			if after.fastPort() != before.fastPort() || after.stealthPort() != before.stealthPort() {
				t.Fatal("rerun changed the saved Fast or Stealth port")
			}
			if mode == Shared {
				assertSetupStealthOff(t, h, after.stealthPort())
			} else {
				nft, err := os.ReadFile(filepath.Join(state, "install", "pipe.nft"))
				must(t, err)
				if !strings.Contains(string(nft), "tcp dport 443 accept") || strings.Contains(h.out.String(), "Stealth is off") {
					t.Fatal("standalone Stealth must remain on without the proxy")
				}
			}
			for _, c := range h.cmds {
				if c.AsPipe && (c.Argv[2] == "init" || c.Argv[2] == "add") {
					t.Errorf("rerun unexpectedly ran %v", c.Argv)
				}
			}
		})
	}
}

func TestSetupKeepsTwoNamesAcrossProxyDisableAndRestore(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	dir := h.env.path(setupStateDir)
	saved := initSharedSetupState(t, dir)
	cert, key := writeProxyTestPair(t, "proxy.example", h.env.Root)
	saved.HTTPSProxyListener = &httpsProxyListenerConfig{
		Domain: "proxy.example", Port: 9443, CertMethod: "files", Cert: cert, Key: key,
	}
	saved.RealityDest = "old-cover.example:443"
	must(t, writeJSON(dir, settingsFile, saved))
	_, _, _, err := AddWithProxy(dir, "phone", false)
	must(t, err)
	devices, err := os.ReadFile(filepath.Join(dir, devicesFile))
	must(t, err)

	off := setupConfigOptions(t, `{"sni":"proxy.example","device":"phone"}`)
	for range 2 {
		must(t, h.run(off))
		got, err := ReadSettings(dir)
		must(t, err)
		if got.HTTPSProxyListener != nil || got.fastName() != "origin.example" || savedSetupSNI(got) != "proxy.example" {
			t.Fatal("disabling the proxy lost either saved TLS name")
		}
	}
	h.out.Reset()
	must(t, h.run(setupConfigOptions(t, `{"sni":"origin.example","proxy":{"port":9443},"device":"phone",
		"cert":{"file":"/fullchain.pem","key":"/key.pem"}}`)))
	got, err := ReadSettings(dir)
	must(t, err)
	after, err := os.ReadFile(filepath.Join(dir, devicesFile))
	must(t, err)
	if got.fastName() != "origin.example" || got.HTTPSProxyListener == nil || got.HTTPSProxyListener.Domain != "proxy.example" ||
		!slices.Equal(after, devices) || !strings.Contains(h.out.String(), "In each device link, set hp=proxy.example:9443 (replace it if present, otherwise add it).") {
		t.Fatal("restoring the proxy changed saved names or credentials, or omitted the link update")
	}
}

func TestSetupRescueOnInactiveStealthPort(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	h.busy[443] = true
	setupRescueTestFiles(t, h, "rescue.example")
	config := setupConfigOptions(t, `{"sni":"origin.example",
		"rescue":{"sni":"rescue.example","port":8443,"cert":"/rescue.pem","key":"/rescue-key.pem"}}`)
	must(t, h.run(config))
	dir := h.env.path(setupStateDir)
	s, err := ReadSettings(dir)
	must(t, err)
	if s.sharedRescuePort() != 8443 || s.realityTargetProblem() == nil {
		t.Fatal("Rescue should use TCP 8443 with Stealth disabled")
	}
	cert, key := writeProxyTestPair(t, "origin.example", h.env.Root)
	opts := ProxyEnableOptions{Domain: "origin.example", Port: 9443, CertFile: cert, KeyFile: key}
	if err := enableProxy(t.Context(), dir, opts, testProxySetup()); err == nil || !strings.Contains(err.Error(), "conflicts with Stealth") {
		t.Fatalf("enabling the proxy must recheck the Stealth collision: %v", err)
	}
	config.Proxy = &SetupPort{Port: 9443}
	if err := h.run(config); err == nil || !strings.Contains(err.Error(), "conflicts with Stealth") {
		t.Fatalf("rerunning setup must recheck the Stealth collision: %v", err)
	}
}

func TestSetupRefusesForeignPorts(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	h.busy[443] = true
	setupRescueTestFiles(t, h, "rescue.example")
	config := setupConfigOptions(t, `{"sni":"origin.example",
		"rescue":{"sni":"rescue.example","port":443,"cert":"/rescue.pem","key":"/rescue-key.pem"}}`)
	if err := h.run(config); err == nil || !strings.Contains(err.Error(), "Rescue TCP port 443") || len(h.cmds) != 0 {
		t.Fatalf("occupied website port: %v, commands %v", err, h.argvs())
	}
	h.env.probeBinding = func(b setupBinding) error {
		if b.network == "udp" && b.port == 443 {
			return syscall.EADDRINUSE
		}
		return nil
	}
	config.Rescue = nil
	if err := h.run(config); err == nil || !strings.Contains(err.Error(), "Fast UDP port 443") || len(h.cmds) != 0 {
		t.Fatalf("occupied Fast port: %v, commands %v", err, h.argvs())
	}

	initSharedSetupState(t, h.env.path(setupStateDir))
	must(t, h.run(config))
	h.cmds = nil
	h.env.probeBinding = func(b setupBinding) error {
		if b.network == "tcp" && b.port == 2096 {
			return syscall.EADDRINUSE
		}
		if !b.loopback {
			t.Errorf("unexpected probe for %s port %d", b.network, b.port)
		}
		return nil
	}
	config.Rescue = &SetupRescue{SNI: "rescue.example", Port: 2096, Cert: "/rescue.pem", Key: "/rescue-key.pem"}
	if err := h.run(config); err == nil || !strings.Contains(err.Error(), "Rescue TCP port 2096") || len(h.cmds) != 0 {
		t.Fatalf("new occupied port on rerun: %v, commands %v", err, h.argvs())
	}
}

func TestSetupRejectsOccupiedFastHopPortBeforeChanges(t *testing.T) {
	h := newSetupHarness(t, "")
	h.env.occupiedUDPPorts = func() ([]uint16, error) { return []uint16{31001}, nil }
	h.env.probeBinding = func(b setupBinding) error {
		if b.network == "udp4" && b.port == 31001 {
			return syscall.EADDRINUSE
		}
		return nil
	}
	o := setupConfigOptions(t, `{"sni":"origin.example","fast":{"hop":"31000-31002"}}`)
	if err := h.run(o); err == nil || !strings.Contains(err.Error(), "31001") || len(h.cmds) != 0 {
		t.Fatalf("unexpected setup result %v with %d changes", err, len(h.cmds))
	}
	if _, err := os.Stat(h.env.path(setupBinary)); !os.IsNotExist(err) {
		t.Fatalf("binary state after refusing the range: %v", err)
	}
}

func TestFastHopScopeUsesExternalInterfaceAddresses(t *testing.T) {
	loop := netip.MustParseAddr("11.0.0.80")
	local := netip.MustParseAddr("10.0.0.2")
	ifaces := []SetupInterface{{Loopback: true, Addrs: []netip.Addr{loop}}, {Addrs: []netip.Addr{local}}}
	addresses, err := fastHopDestinations(ifaces, netip.Addr{})
	if err != nil || !slices.Equal(addresses, []netip.Addr{local}) {
		t.Fatalf("hop addresses = %v, error = %v", addresses, err)
	}
}

func TestSetupProbesHopPortsInSelectedFamily(t *testing.T) {
	h := newSetupHarness(t, "")
	h.env.occupiedUDPPorts = func() ([]uint16, error) { return []uint16{443, 31001, 31003}, nil }
	var seen []string
	h.env.probeBinding = func(b setupBinding) error {
		if b.port >= 31000 && b.port <= 31002 {
			seen = append(seen, b.network)
			if b.address != netip.MustParseAddr("203.0.113.7") {
				t.Fatalf("unexpected hop probe destination %v", b.address)
			}
		}
		return nil
	}
	must(t, h.run(setupConfigOptions(t, `{"sni":"origin.example","fast":{"hop":"31000-31002","address":"203.0.113.7"}}`)))
	if !slices.Equal(seen, []string{"udp4"}) {
		t.Fatalf("hop preflight probed %v, want one probe for the occupied candidate port and selected address family", seen)
	}
}

func TestHopPreflightUsesKernelAddressAndWildcardScope(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the socket table fixture requires Linux")
	}
	for _, fixture := range []struct {
		host    string
		blocked bool
	}{{"127.0.0.2", false}, {"127.0.0.1", true}, {"0.0.0.0", true}} {
		t.Run(fixture.host, func(t *testing.T) {
			listener, err := net.ListenPacket("udp4", net.JoinHostPort(fixture.host, "0"))
			must(t, err)
			defer listener.Close()
			port := listener.LocalAddr().(*net.UDPAddr).Port
			destination := netip.MustParseAddr("127.0.0.1")
			err = checkHopPorts(fmt.Sprintf("%d-%d", port, port+1), 443, []netip.Addr{destination}, occupiedUDPPorts, probeSetupBinding)
			if fixture.blocked && !errors.Is(err, syscall.EADDRINUSE) || !fixture.blocked && err != nil {
				t.Fatalf("preflight for %s: %v", fixture.host, err)
			}
		})
	}
}

func TestSetupPersistsNATIPsForADNSAdvertisedHost(t *testing.T) {
	h := newSetupHarness(t, "")
	o := setupConfigOptions(t, `{"sni":"origin.example","block_egress_ips":["11.0.0.81","::ffff:11.0.0.81"]}`)
	must(t, h.run(o))
	dir := h.env.path(setupStateDir)
	check := func() {
		t.Helper()
		s, err := ReadSettings(dir)
		must(t, err)
		want := []netip.Addr{netip.MustParseAddr("11.0.0.81"), netip.MustParseAddr("203.0.113.7")}
		if s.Domain != "origin.example" || !slices.Equal(s.BlockEgressIPs, want) {
			t.Fatalf("saved host and blocked addresses = %s %v", s.Domain, s.BlockEgressIPs)
		}
		cli := netip.MustParseAddr("11.0.0.82")
		policy := newServerEgressPolicy(s, []netip.Addr{cli})
		if policy.Allows(want[0]) || policy.Allows(cli) || !policy.Allows(netip.MustParseAddr("11.0.0.80")) {
			t.Fatal("startup policy did not merge saved and command-line addresses")
		}
	}
	check()
	must(t, h.run(setupConfigOptions(t, `{"sni":"origin.example"}`)))
	check()
}

func TestUnattendedSetupDeliversLinkPrivately(t *testing.T) {
	h := newSetupHarness(t, "")
	o := setupConfigOptions(t, `{"sni":"origin.example","device":"fixture"}`)
	o.LinkFile = "/device-fixture.link"
	path := h.env.path(o.LinkFile)
	must(t, os.WriteFile(path, []byte("keep"), 0600))
	if err := h.run(o); !errors.Is(err, os.ErrExist) {
		t.Fatalf("output collision returned %v", err)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "keep" {
		t.Fatal("existing output file was overwritten")
	}
	must(t, os.Remove(path))
	h.cmds = nil
	if err := h.run(o); err != nil {
		t.Fatal(err)
	}
	for _, command := range h.argvs() {
		if strings.Contains(command, " server add ") {
			t.Fatal("unattended enrollment used the terminal command")
		}
	}
	if !strings.Contains(h.out.String(), "Device link written to ") || strings.Contains(h.out.String(), "pipe://") {
		t.Fatal("expected only the link file's path on the console")
	}
	body, err := localfile.Read(path, 4096, true)
	must(t, err)
	profile, err := link.Parse(strings.TrimSpace(string(body)))
	if err != nil || profile.Name != "fixture" {
		t.Fatal("output was not an importable device link")
	}
}

func TestEnrollmentFailedDeliveryCanRetry(t *testing.T) {
	dir := t.TempDir()
	must(t, Init(dir, "origin.example", ""))
	path := filepath.Join(dir, "output.link")
	must(t, os.WriteFile(path, nil, 0600))
	readonly, err := os.Open(path)
	must(t, err)
	if err := EnrollSetupDevice(dir, "fixture", readonly); err == nil {
		t.Fatal("expected the failed write to abort enrollment")
	}
	must(t, readonly.Close())
	devices, err := ReadDevices(dir)
	must(t, err)
	if len(devices) != 0 {
		t.Fatal("failed delivery enrolled a device")
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0600)
	must(t, err)
	must(t, EnrollSetupDevice(dir, "fixture", file))
	must(t, file.Close())
}

func TestSetupChildEnvironmentDropsParentSecrets(t *testing.T) {
	t.Setenv("PIPE_TEST_PARENT_SECRET", "unrelated fixture")
	t.Setenv("PATH", "/fixture-bin")
	env := setupChildEnvironment(true)
	want := []string{"HOME=" + setupStateDir, "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", setupInstallEnv + "=1"}
	if !slices.Equal(env, want) {
		t.Fatal("the setup child environment differs from its allowlist")
	}
}

func TestSetupBindingProbeUsesTestListeners(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		must(t, err)
		defer listener.Close()
		port := uint16(listener.Addr().(*net.TCPAddr).Port)
		if err := probeSetupBinding(setupBinding{network: "tcp", port: port, loopback: true}); !portInUse(err) {
			t.Fatalf("expected occupied TCP port %d, got %v", port, err)
		}
	})
	t.Run("udp", func(t *testing.T) {
		listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
		must(t, err)
		defer listener.Close()
		port := uint16(listener.LocalAddr().(*net.UDPAddr).Port)
		if err := probeSetupBinding(setupBinding{network: "udp", port: port, loopback: true}); !portInUse(err) {
			t.Fatalf("expected occupied UDP port %d, got %v", port, err)
		}
	})
}

func TestSetupMigrationFailureKeepsOldState(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	h.busy[80] = true
	must(t, os.WriteFile(h.env.path("/old-token"), []byte("fixture-token"), 0600))
	must(t, os.WriteFile(h.env.path("/new-token"), []byte("replacement-token"), 0600))
	must(t, h.run(setupConfigOptions(t, `{"sni":"proxy.example","proxy":{},
		"cert":{"dns":"cloudflare","token_file":"/old-token"},"device":"phone"}`)))

	state := h.env.path(setupStateDir)
	old, err := ReadSettings(state)
	must(t, err)
	paths := []string{filepath.Join(state, settingsFile), filepath.Join(state, devicesFile),
		filepath.Join(state, old.HTTPSProxyListener.DNSSecret)}
	before := make([][]byte, len(paths))
	for i, path := range paths {
		before[i], err = os.ReadFile(path)
		must(t, err)
	}
	must(t, os.WriteFile(h.env.Executable, []byte("binary-v2"), 0755))
	setupRescueTestFiles(t, h, "rescue.example")
	must(t, os.WriteFile(h.env.path("/bad-rescue-key"), []byte("invalid PEM"), 0600))
	for _, tc := range []struct{ config, message string }{
		{`{"sni":"proxy.example",
			"rescue":{"sni":"rescue.example","cert":"/rescue.pem","key":"/bad-rescue-key"}}`, "load Rescue certificate and key"},
		{`{"sni":"proxy.example","proxy":{},"cert":{"dns":"cloudflare","token_file":"/new-token"},
			"rescue":{"sni":"rescue.example","cert":"/rescue.pem","key":"/rescue-key.pem"}}`, "initial HTTPS proxy DNS-01 issuance failed"},
	} {
		h.issueErr = errors.New("simulated issuance failure")
		if err := h.run(setupConfigOptions(t, tc.config)); err == nil || !strings.Contains(err.Error(), tc.message) {
			t.Fatalf("expected %q, got %v", tc.message, err)
		}
		for i, path := range paths {
			got, err := os.ReadFile(path)
			must(t, err)
			if !slices.Equal(got, before[i]) {
				t.Fatalf("failure changed %s", filepath.Base(path))
			}
		}
		for _, pattern := range []string{".setup-*", "rescue-*.pem"} {
			got, err := filepath.Glob(filepath.Join(state, pattern))
			must(t, err)
			if len(got) != 0 {
				t.Fatalf("failed migration left staged files %v", got)
			}
		}
	}
	binary, err := os.ReadFile(h.env.path(setupBinary))
	must(t, err)
	if string(binary) != "binary-v2" {
		t.Fatal("the new binary must already be installed when certificate preparation fails")
	}
	if !slices.Equal(h.issuedFresh, []bool{true, true}) {
		t.Fatalf("first and replacement DNS credentials must force issuance: %v", h.issuedFresh)
	}
}

func TestSetupInterruptionAfterSettingsCommit(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	state := h.env.path(setupStateDir)
	before := initSharedSetupState(t, state)
	setupRescueTestFiles(t, h, "rescue.example")
	binary := h.env.path(setupBinary)
	must(t, os.MkdirAll(filepath.Dir(binary), 0755))
	must(t, os.WriteFile(binary, []byte("old-binary"), 0755))
	run := h.env.Run
	h.env.Run = func(ctx context.Context, command SetupCommand) error {
		if !command.AsPipe || command.Argv[2] != "setup" {
			t.Fatalf("unexpected activation command: %v", command.Argv)
		}
		data, err := os.ReadFile(binary)
		must(t, err)
		if string(data) != "binary-v1" {
			t.Fatal("the old executable was still installed when the child started")
		}
		if err := run(ctx, command); err != nil {
			return err
		}
		return context.Canceled
	}
	err := h.run(setupConfigOptions(t, `{"sni":"origin.example",
		"rescue":{"sni":"rescue.example","cert":"/rescue.pem","key":"/rescue-key.pem"}}`))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected interruption after commit, got %v", err)
	}
	after, err := ReadSettings(state)
	must(t, err)
	data, err := os.ReadFile(binary)
	must(t, err)
	if string(data) != "binary-v1" || after.sharedRescuePort() != DefaultRescuePort ||
		after.RealityPrivateKey != before.RealityPrivateKey {
		t.Fatal("interruption left the wrong binary or settings")
	}
}

func TestSetupRetiredWarningPrecedesBinaryInstall(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	state := h.env.path(setupStateDir)
	old := initSharedSetupState(t, state)
	old.CDNDomain = "rescue.example"
	old.HTTPSProxyListener = &httpsProxyListenerConfig{Domain: "proxy.example", Port: 9943, CertMethod: "nginx"}
	must(t, writeJSON(state, settingsFile, old))
	h.env.Chown = func(path string, _, _ uint32) error {
		if path == h.env.path(setupBinary) {
			for _, want := range []string{"Rescue will be off after restart", "HTTPS proxy will be off after restart",
				"Stealth will also be off until the proxy uses a supported certificate method",
				`"sni": "proxy.example"`, `"cert": {`, `"proxy": {`, `"rescue": {`, `"sni": "rescue.example"`} {
				if !strings.Contains(h.out.String(), want) {
					t.Errorf("warning before activation is missing %q", want)
				}
			}
		}
		return nil
	}
	must(t, h.run(SetupOptions{}))
	if len(h.updates) != 0 {
		t.Fatal("a bare upgrade must preserve the saved state")
	}
}

func TestSetupRewritesIdenticalWritableSystemFile(t *testing.T) {
	h := newSetupHarness(t, "")
	path := h.env.path("/etc/systemd/system/pipe.service")
	must(t, os.MkdirAll(filepath.Dir(path), 0755))
	must(t, os.WriteFile(path, []byte("fixture\n"), 0644))
	must(t, os.Chmod(path, 0664))
	r := &setupRun{SetupEnv: h.env}
	changed, err := r.installIfChanged(path, installFile{contents: "fixture\n", mode: 0644})
	must(t, err)
	info, err := os.Stat(path)
	must(t, err)
	if !changed || info.Mode().Perm() != 0644 {
		t.Fatal("identical bytes must not preserve an unsafe system file")
	}
}

func TestInstallRootOnlyUsesTrustedSetupForSystemFiles(t *testing.T) {
	dir := initProxyTestState(t)
	dst := t.TempDir()
	must(t, os.Chmod(dst, 0755))
	must(t, os.Symlink(dst, filepath.Join(dir, "install")))
	oldEUID := installEUID
	installEUID = func() int { return 0 }
	t.Cleanup(func() { installEUID = oldEUID })
	paths, hints, err := Install(t.Context(), dir, setupBinary, Auto, nil)
	must(t, err)
	files, err := os.ReadDir(dst)
	must(t, err)
	info, err := os.Stat(dst)
	must(t, err)
	if len(paths) != 0 || len(files) != 0 || info.Mode().Perm() != 0755 ||
		!strings.Contains(strings.Join(hints, "\n"), "sudo pipe server setup --yes") {
		t.Fatal("root installer wrote into the service's install directory or omitted the trusted setup command")
	}
}

func TestSetupInstallOutputOmitsManualSystemHints(t *testing.T) {
	dir := t.TempDir()
	must(t, InitWithOptions(dir, "origin.example", "", InitOptions{Mode: Standalone, FastHop: "25000-25003"}))
	oldEUID := installEUID
	installEUID = func() int { return 1000 }
	t.Cleanup(func() { installEUID = oldEUID })
	for _, tc := range []struct {
		name, marker string
		manual       bool
	}{
		{name: "manual install", manual: true},
		{name: "setup child", marker: "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(setupInstallEnv, tc.marker)
			paths, hints, err := Install(t.Context(), dir, setupBinary, Auto, nil)
			must(t, err)
			output := strings.Join(hints, "\n")
			for _, manual := range []string{"Use sudo pipe server setup --yes with the same --dir", "Fast port hopping is applied by pipe-hop.service"} {
				if strings.Contains(output, manual) != tc.manual {
					t.Fatalf("unexpected install hints:\n%s", output)
				}
			}
			if len(paths) == 0 || !strings.Contains(output, "Allow the Fast UDP hopping range 25000-25003") {
				t.Fatalf("missing install files or firewall guidance: %v, %s", paths, output)
			}
		})
	}
}
