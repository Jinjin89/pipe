// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bufio"
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type setupHarness struct {
	t      *testing.T
	env    SetupEnv
	cmds   []SetupCommand
	out    strings.Builder
	exists bool // pipe user exists
	ifaces []SetupInterface
	busy   map[int]bool
}

func newSetupHarness(t *testing.T, input string) *setupHarness {
	t.Helper()
	root := t.TempDir()
	h := &setupHarness{t: t, busy: map[int]bool{}}
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
	h.env = SetupEnv{
		Root: root, GOOS: "linux", EUID: 0, Executable: exe,
		Run: func(_ context.Context, c SetupCommand) error {
			h.cmds = append(h.cmds, c)
			if c.Argv[0] == "useradd" {
				h.exists = true
			}
			h.fakeChild(c)
			return nil
		},
		LookupPipeUser: func() (uint32, uint32, bool, error) { return 990, 990, h.exists, nil },
		Chown:          func(string, uint32, uint32) error { return nil },
		Interfaces:     func() ([]SetupInterface, error) { return h.ifaces, nil },
		PortBusy:       func(p int) bool { return h.busy[p] },
		Suffix:         func() string { return "abc123" },
		In:             strings.NewReader(input), Out: &h.out,
	}
	return h
}

// fakeChild emulates pipe server init/install. Standalone state and the install
// files come from the real InitWithOptions and GenerateInstall.
func (h *setupHarness) fakeChild(c SetupCommand) {
	if len(c.Argv) < 3 || c.Argv[0] != setupBinary {
		return
	}
	dir := filepath.Join(h.env.Root, setupStateDir)
	flag := func(name string) string {
		for i, a := range c.Argv {
			if a == name && i+1 < len(c.Argv) {
				return c.Argv[i+1]
			}
		}
		return ""
	}
	switch c.Argv[2] {
	case "init":
		if flag("--mode") == "shared" {
			_ = os.WriteFile(filepath.Join(dir, "server.json"), []byte(`{"mode":"shared","domain":"example.com"}`), 0600)
			return
		}
		err := InitWithOptions(dir, flag("--domain"), "", InitOptions{Mode: Standalone, FastHop: flag("--fast-hop")})
		if err != nil {
			h.t.Errorf("init: %v", err)
		}
	case "install":
		if _, err := GenerateInstall(dir, setupBinary); err != nil {
			// Shared state is faked above, so write the same shape by hand.
			inst := filepath.Join(dir, "install")
			_ = os.MkdirAll(inst, 0700)
			_ = os.WriteFile(filepath.Join(inst, "pipe.service"), []byte("ExecStart="+unitArgument(setupBinary)+" server run\n"), 0644)
			_ = os.WriteFile(filepath.Join(inst, "90-pipe.conf"), []byte("x\n"), 0644)
		}
	}
}

func (h *setupHarness) argvs() []string {
	var out []string
	for _, c := range h.cmds {
		who := "root"
		if c.AsPipe {
			who = "pipe"
		}
		out = append(out, who+": "+strings.Join(c.Argv, " "))
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
	err := h.run(SetupOptions{Yes: true, Domain: "example.com", FastHop: "20000-40000"})
	if err != nil {
		t.Fatal(err)
	}
	d := "/var/lib/pipe"
	wantCommands(t, h.argvs(), []string{
		"root: useradd --system --home-dir /var/lib/pipe --shell /usr/sbin/nologin pipe",
		"pipe: " + setupBinary + " server init --dir " + d + " --mode standalone --domain example.com --fast-hop 20000-40000",
		"pipe: " + setupBinary + " server install --dir " + d,
		"pipe: " + setupBinary + " server add phone --dir " + d,
		"root: sysctl -p /etc/sysctl.d/90-pipe.conf",
		"root: systemctl daemon-reload",
		"root: systemctl enable --now pipe-hop",
		"root: systemctl enable pipe",
		"root: systemctl restart pipe",
	})
	for _, p := range []string{"/etc/systemd/system/pipe.service", "/etc/systemd/system/pipe-hop.service", "/etc/sysctl.d/90-pipe.conf", "/usr/local/bin/pipe"} {
		if _, err := os.Stat(filepath.Join(h.env.Root, p)); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(h.out.String(), "A record example.com -> 203.0.113.7") {
		t.Fatalf("missing DNS step:\n%s", h.out.String())
	}
}

func TestSetupFreshSharedYes(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	h.busy[443] = true
	err := h.run(SetupOptions{
		Yes: true, Mode: "shared", Domain: "pipe.example.com", CDNDomain: "cdn.example.com",
		ProxyDomain: "proxy.example.com", ProxyCertMethod: "nginx", Device: "laptop",
	})
	if err != nil {
		t.Fatal(err)
	}
	d := "/var/lib/pipe"
	wantCommands(t, h.argvs(), []string{
		"pipe: " + setupBinary + " server init --dir " + d + " --mode shared --domain pipe.example.com --cdn-domain cdn.example.com --rescue-listen 172.17.0.1:18080",
		"pipe: " + setupBinary + " server proxy enable --dir " + d + " --domain proxy.example.com --cert-method nginx",
		"pipe: " + setupBinary + " server install --dir " + d,
		"pipe: " + setupBinary + " server add laptop --dir " + d,
		"root: sysctl -p /etc/sysctl.d/90-pipe.conf",
		"root: systemctl daemon-reload",
		"root: systemctl enable pipe",
		"root: systemctl restart pipe",
	})
}

func TestSetupYesMissingFlags(t *testing.T) {
	for name, opts := range map[string]SetupOptions{
		"standalone domain":    {Yes: true, Mode: "standalone"},
		"shared ip fast sni":   {Yes: true, Mode: "shared", Domain: "203.0.113.7"},
		"shared proxy domain":  {Yes: true, Mode: "standalone", Domain: "example.com", ProxyDomain: "p.example.com"},
		"cdn without listener": {Yes: true, Mode: "shared", Domain: "example.com", CDNDomain: "cdn.example.com"},
	} {
		h := newSetupHarness(t, "")
		h.ifaces = nil
		if err := h.run(opts); err == nil {
			t.Errorf("%s: expected error", name)
		}
		for _, c := range h.cmds {
			if c.AsPipe {
				t.Errorf("%s: child ran", name)
			}
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
	// Units already match what install will write.
	if _, err := GenerateInstall(state, setupBinary); err != nil {
		t.Fatal(err)
	}
	for name, dst := range map[string]string{"pipe.service": units, "90-pipe.conf": filepath.Join(h.env.Root, "/etc/sysctl.d")} {
		data, err := os.ReadFile(filepath.Join(state, "install", name))
		if err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(dst, name), data, 0644)
	}
	if err := h.run(SetupOptions{Yes: true}); err != nil {
		t.Fatal(err)
	}
	for _, a := range h.argvs() {
		if strings.Contains(a, " init ") || strings.Contains(a, " add ") {
			t.Fatalf("unexpected %s", a)
		}
	}
	if strings.Contains(h.out.String(), "Wrote ") {
		t.Fatalf("unchanged units must not be rewritten:\n%s", h.out.String())
	}
	if !strings.Contains(h.out.String(), "Existing install") {
		t.Fatal("missing summary")
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
	if err := h.run(SetupOptions{Yes: true, Domain: "example.com"}); err != nil {
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
	if err := os.WriteFile(filepath.Join(h.env.Root, "ali.key"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	var seen string
	run := h.env.Run
	h.env.Run = func(ctx context.Context, c SetupCommand) error {
		staged, _ := filepath.Glob(filepath.Join(h.env.Root, setupStateDir, ".setup-*"))
		if len(staged) != 0 && !strings.Contains(strings.Join(c.Argv, " "), "--dns-key-file") {
			t.Errorf("secret copy exists outside its child: %v", staged)
		}
		for i, a := range c.Argv {
			if a == "--dns-key-file" {
				data, err := os.ReadFile(filepath.Join(h.env.Root, c.Argv[i+1]))
				if err != nil || string(data) != "secret" {
					t.Errorf("staged key unreadable: %v", err)
				}
				seen = c.Argv[i+1]
			}
		}
		return run(ctx, c)
	}
	err := h.run(SetupOptions{
		Yes: true, Mode: "shared", Domain: "example.com",
		ProxyDomain: "proxy.example.com", ProxyCertMethod: "dns", DNS: "alidns", DNSKeyFile: "/ali.key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != "/var/lib/pipe/.setup-abc123" {
		t.Fatalf("staged path %q", seen)
	}
	if _, err := os.Stat(filepath.Join(h.env.Root, seen)); !os.IsNotExist(err) {
		t.Fatal("staged key must be removed")
	}
}

func TestSetupInteractiveShared(t *testing.T) {
	input := strings.Join([]string{
		"shared", "", "fast.example.com", "cdn.example.com", "",
		"n", "proxy.example.com", "dns", "cloudflare", "", "tablet",
	}, "\n") + "\n"
	h := newSetupHarness(t, input)
	h.exists = true
	h.busy[80] = true
	if err := h.run(SetupOptions{}); err != nil {
		t.Fatal(err)
	}
	d := "/var/lib/pipe"
	wantCommands(t, h.argvs()[:4], []string{
		"pipe: " + setupBinary + " server init --dir " + d + " --mode shared --domain 203.0.113.7 --fast-sni fast.example.com --cdn-domain cdn.example.com --rescue-listen 172.17.0.1:18080",
		"pipe: " + setupBinary + " server proxy enable --dir " + d + " --domain proxy.example.com --cert-method dns --dns cloudflare",
		"pipe: " + setupBinary + " server install --dir " + d,
		"pipe: " + setupBinary + " server add tablet --dir " + d,
	})
	if !strings.Contains(h.out.String(), "Suggested mode: shared") {
		t.Fatal("expected shared suggestion")
	}
}

func TestSetupDetect(t *testing.T) {
	h := newSetupHarness(t, "")
	h.busy[443] = true
	run := &setupRun{SetupEnv: h.env}
	d, err := run.detect()
	if err != nil {
		t.Fatal(err)
	}
	if len(d.PublicIPs) != 1 || d.PublicIPs[0].String() != "203.0.113.7" {
		t.Fatalf("public IPs %v", d.PublicIPs)
	}
	if len(d.Bridges) != 2 || d.Bridges[0].String() != "172.17.0.1" || d.Bridges[1].String() != "172.18.0.1" {
		t.Fatalf("bridges %v", d.Bridges)
	}
	if d.suggestedMode() != Shared || d.Port80Busy || !d.Port443Busy {
		t.Fatalf("%+v", d)
	}
	h.busy = map[int]bool{}
	if d, _ = run.detect(); d.suggestedMode() != Standalone {
		t.Fatal("free ports suggest standalone")
	}
}

func TestSetupAutoMethodResolvedAsRoot(t *testing.T) {
	for name, tc := range map[string]struct {
		busy   bool
		opts   SetupOptions
		method string
	}{
		"busy 80":  {busy: true, method: "nginx"},
		"free 80":  {method: "http"},
		"dns flag": {busy: true, opts: SetupOptions{DNS: "cloudflare"}, method: "dns"},
	} {
		h := newSetupHarness(t, "")
		h.exists = true
		h.busy[80] = tc.busy
		o := tc.opts
		o.Yes, o.Mode, o.Domain = true, "shared", "example.com"
		o.ProxyDomain, o.ACMEListen = "proxy.example.com", "172.17.0.1:18081"
		if err := h.run(o); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		found := false
		for _, a := range h.argvs() {
			if strings.Contains(a, "proxy enable") {
				found = strings.Contains(a, "--cert-method "+tc.method)
			}
		}
		if !found {
			t.Errorf("%s: want --cert-method %s in %v", name, tc.method, h.argvs())
		}
	}
	h := newSetupHarness(t, "")
	h.exists = true
	h.busy[80] = true
	err := h.run(SetupOptions{Yes: true, Mode: "shared", Domain: "example.com", ProxyDomain: "p.example.com"})
	if err == nil || !strings.Contains(err.Error(), "--acme-listen") {
		t.Fatalf("nginx without a listener must fail: %v", err)
	}
}

func TestSetupRefusesOpenSecretFile(t *testing.T) {
	h := newSetupHarness(t, "")
	h.exists = true
	key := filepath.Join(h.env.Root, "ali.key")
	if err := os.WriteFile(key, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	err := h.run(SetupOptions{Yes: true, Mode: "shared", Domain: "example.com",
		ProxyDomain: "p.example.com", ProxyCertMethod: "dns", DNS: "alidns", DNSKeyFile: "/ali.key"})
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
