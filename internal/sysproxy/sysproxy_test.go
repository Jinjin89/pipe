// SPDX-License-Identifier: GPL-3.0-or-later

package sysproxy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pipe/internal/localfile"
)

type memBackend struct {
	state       string
	captures    int
	applied     int
	failApply   bool
	failRestore bool
}

func (m *memBackend) Capture() (json.RawMessage, error) {
	m.captures++
	return json.Marshal(m.state)
}
func (m *memBackend) Apply(host string, port int) error {
	m.applied++
	m.state = "proxy"
	if m.failApply {
		return errors.New("boom")
	}
	return nil
}
func (m *memBackend) IsApplied(string, int) bool { return m.state == "proxy" }
func (m *memBackend) RestoreIfApplied(saved json.RawMessage, h string, p int) error {
	return restoreIfApplied(m, saved, h, p)
}
func (m *memBackend) Restore(raw json.RawMessage) error {
	if m.failRestore {
		return errors.New("restore failed")
	}
	return json.Unmarshal(raw, &m.state)
}

func TestFailedProxyRepairRetainsSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.armed")
	b := &memBackend{state: "original", failRestore: true}
	m := New(b, path)
	if err := m.Set("127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	if err := m.Repair(); err == nil || !m.Armed() {
		t.Fatalf("repair error = %v, armed = %v", err, m.Armed())
	}
	b.failRestore = false
	if err := m.Repair(); err != nil || m.Armed() || b.state != "original" {
		t.Fatalf("retry error = %v, armed = %v, state = %s", err, m.Armed(), b.state)
	}
}

func TestDamagedProxySnapshotSurvivesRestoreAttempts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.armed")
	b := &memBackend{state: "original"}
	m := New(b, path)
	if err := m.Set("127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	const broken = `{"saved":`
	if err := os.WriteFile(path, []byte(broken), 0600); err != nil {
		t.Fatal(err)
	}
	for _, restore := range []func() error{m.Repair, m.Clear, m.Clear} {
		if err := restore(); err == nil {
			t.Error("damaged recovery file was treated as a successful restore")
		}
		if raw, err := os.ReadFile(path); err != nil || string(raw) != broken || b.state != "proxy" {
			t.Fatalf("failed restore lost the recovery file or proxy state: %v", err)
		}
	}
}

func TestSetRejectsDamagedOrUnreadableProxySnapshot(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		directory bool
	}{
		{name: "invalid JSON", raw: `{"saved":`},
		{name: "missing saved settings", raw: `{"host":"127.0.0.1","port":7890}`},
		{name: "null saved settings", raw: `{"saved": null, "host":"127.0.0.1","port":7890}`},
		{name: "unreadable snapshot", directory: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "proxy.armed")
			if tc.directory {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := localfile.WritePrivate(path, []byte(tc.raw)); err != nil {
				t.Fatal(err)
			}
			b := &memBackend{state: "proxy"}
			if err := New(b, path).Set("127.0.0.1", 7891); err == nil {
				t.Error("Set accepted an invalid recovery snapshot")
			}
			if b.captures != 0 || b.applied != 0 {
				t.Fatal("Set captured or rewrote the active proxy")
			}
			if !tc.directory {
				if raw, err := os.ReadFile(path); err != nil || string(raw) != tc.raw {
					t.Fatalf("Set changed the invalid recovery file: %v", err)
				}
			}
		})
	}
}

func TestSetClearAndRepair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.armed")
	b := &memBackend{state: "original"}
	m := New(b, path)
	if err := m.Set("127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("armed file: %v %v", err, info)
	}
	// A second Set must keep the first saved value.
	if err := m.Set("127.0.0.1", 7891); err != nil {
		t.Fatal(err)
	}
	// A new manager (after a crash) repairs from the file.
	b2 := New(b, path)
	b.state = "changed-by-user"
	if err := b2.Repair(); err != nil || b.state != "changed-by-user" || b2.Armed() {
		t.Fatalf("repair must not overwrite a proxy that is not ours: %q %v", b.state, err)
	}
	b.state = "original"
	if err := m.Set("127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	if err := b2.Repair(); err != nil {
		t.Fatal(err)
	}
	if b.state != "original" || b2.Armed() {
		t.Fatalf("state=%q armed=%v", b.state, b2.Armed())
	}
	if err := b2.Clear(); err != nil {
		t.Fatal("clear when not armed:", err)
	}
}

func TestApplyFailureRestores(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.armed")
	b := &memBackend{state: "original", failApply: true}
	m := New(b, path)
	if err := m.Set("127.0.0.1", 1); err == nil {
		t.Fatal("expected error")
	}
	if b.state != "original" || m.Armed() {
		t.Fatalf("state=%q armed=%v", b.state, m.Armed())
	}
}

func TestUnsupported(t *testing.T) {
	m := New(nil, filepath.Join(t.TempDir(), "x"))
	if m.Supported() || !errors.Is(m.Set("127.0.0.1", 1), ErrUnsupported) || m.Clear() != nil {
		t.Fatal("nil backend must be unsupported and harmless")
	}
}

type recorder struct {
	calls []string
	out   map[string]string
}

func (r *recorder) run(name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	for prefix, out := range r.out {
		if strings.HasPrefix(line, prefix) {
			return out, nil
		}
	}
	return "", nil
}

func TestGsettingsRoundTrip(t *testing.T) {
	r := &recorder{out: map[string]string{"gsettings get org.gnome.system.proxy mode": "'none'\n"}}
	g := Gsettings{Run: r.run}
	saved, err := g.Capture()
	if err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	if err := g.Apply("127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(r.calls, "\n")
	for _, want := range []string{"http host 127.0.0.1", "socks port 7890", "ignore-hosts", "mode manual"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in\n%s", want, all)
		}
	}
	for _, want := range []string{"::1", "fe80::/10", "fc00::/7"} {
		if !strings.Contains(all, want) {
			t.Errorf("GNOME bypass is missing %q in\n%s", want, all)
		}
	}
	r.calls = nil
	if err := g.Restore(saved); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "org.gnome.system.proxy mode 'none'") {
		t.Fatalf("mode not restored: %v", r.calls)
	}
	if !strings.HasSuffix(r.calls[len(r.calls)-1], "mode 'none'") {
		t.Fatal("mode must be restored last")
	}
}

func TestGsettingsRestoresOnlyOwnedValues(t *testing.T) {
	r := &recorder{out: map[string]string{
		"gsettings get org.gnome.system.proxy mode":         "'manual'",
		"gsettings get org.gnome.system.proxy.http host":    "'127.0.0.1'",
		"gsettings get org.gnome.system.proxy.http port":    "7890",
		"gsettings get org.gnome.system.proxy.https host":   "'user-proxy.example'",
		"gsettings get org.gnome.system.proxy.https port":   "3128",
		"gsettings get org.gnome.system.proxy ignore-hosts": "['new.example']",
	}}
	g := Gsettings{Run: r.run}
	saved, err := json.Marshal(map[string]string{
		"org.gnome.system.proxy mode":         "'none'",
		"org.gnome.system.proxy.http host":    "'original.example'",
		"org.gnome.system.proxy.http port":    "8080",
		"org.gnome.system.proxy.https host":   "'original.example'",
		"org.gnome.system.proxy.https port":   "8080",
		"org.gnome.system.proxy ignore-hosts": "['original.example']",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.RestoreIfApplied(saved, "127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(r.calls, "\n")
	if !strings.Contains(all, "set org.gnome.system.proxy.http port 8080") ||
		strings.Contains(all, "set org.gnome.system.proxy.https") || strings.Contains(all, "set org.gnome.system.proxy ignore-hosts") {
		t.Fatalf("unexpected restore writes:\n%s", all)
	}
}

func TestNetworksetupParsingAndRestore(t *testing.T) {
	services := "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Old VPN\nEthernet\n"
	if got := parseServices(services, false); len(got) != 2 || got[0] != "Wi-Fi" || got[1] != "Ethernet" {
		t.Fatalf("services %v", got)
	}
	if p := parseProxy("Enabled: Yes\nServer: 192.0.2.1\nPort: 8080\nAuthenticated Proxy Enabled: 0\n"); !p.Enabled || p.Server != "192.0.2.1" || p.Port != 8080 {
		t.Fatalf("%+v", p)
	}
	if parseBypass("There aren't any bypass domains set on Wi-Fi.") != nil {
		t.Fatal("bypass should be empty")
	}
	r := &recorder{out: map[string]string{
		"networksetup -listallnetworkservices": services,
		"networksetup -getwebproxy":            "Enabled: Yes\nServer: 192.0.2.1\nPort: 8080\n",
		"networksetup -getproxybypassdomains":  "*.example.com\n",
	}}
	n := Networksetup{Run: r.run}
	saved, err := n.Capture()
	if err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	if err := n.Apply("127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(r.calls, "\n")
	if strings.Count(all, "-setwebproxy Wi-Fi 127.0.0.1 7890") != 1 || !strings.Contains(all, "-setsocksfirewallproxy Ethernet 127.0.0.1 7890") || strings.Contains(all, "Old VPN") {
		t.Fatalf("apply calls:\n%s", all)
	}
	for _, want := range []string{"::1", "fe80::/10", "fc00::/7"} {
		if !strings.Contains(all, want) {
			t.Errorf("macOS bypass is missing %q in\n%s", want, all)
		}
	}
	r.calls = nil
	if err := n.Restore(saved); err != nil {
		t.Fatal(err)
	}
	all = strings.Join(r.calls, "\n")
	if !strings.Contains(all, "-setwebproxy Wi-Fi 192.0.2.1 8080") || !strings.Contains(all, "-setwebproxystate Wi-Fi on") || !strings.Contains(all, "-setsecurewebproxystate Ethernet off") && !strings.Contains(all, "-setsecurewebproxystate Ethernet on") {
		t.Fatalf("restore calls:\n%s", all)
	}
}

func TestNetworksetupSetExtendsSavedServicesBeforeApply(t *testing.T) {
	const listServices = "networksetup -listallnetworkservices"
	r := &recorder{out: map[string]string{
		listServices: "*Wi-Fi\n*Ethernet\n",
	}}
	path := filepath.Join(t.TempDir(), "proxy.armed")
	readSaved := func() json.RawMessage {
		t.Helper()
		data, err := ReadPrivate(path)
		if err != nil {
			t.Fatal(err)
		}
		var file armedFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		return file.Saved
	}
	n := Networksetup{Run: func(name string, args ...string) (string, error) {
		out, err := r.run(name, args...)
		if args[0] == "-getwebproxy" && args[1] == "Ethernet" {
			r.out[listServices] += "USB Adapter\n" // enabled during Extend
		}
		if args[0] == "-setwebproxy" && args[1] == "Ethernet" {
			var saved []macService
			if err := json.Unmarshal(readSaved(), &saved); err != nil {
				t.Fatal(err)
			}
			if len(saved) != 3 || saved[0].Name != "Wi-Fi" || saved[0].Web.Server != "192.0.2.1" ||
				saved[1].Name != "Ethernet" || saved[1].Web.Server != "192.0.2.2" ||
				saved[2].Name != "USB Adapter" || saved[2].Web.Server != "192.0.2.3" {
				t.Fatalf("original services were not saved before apply: %+v", saved)
			}
		}
		return out, err
	}}
	m := New(n, path)
	if err := m.Set("127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	if got := string(readSaved()); got != "[]" {
		t.Fatalf("empty service snapshot was %s", got)
	}
	r.out[listServices] = "Wi-Fi\n*Ethernet\n"
	r.out["networksetup -getwebproxy Wi-Fi"] = "Enabled: Yes\nServer: 192.0.2.1\nPort: 8080\n"
	if err := m.Set("127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	r.out[listServices] = "Wi-Fi\nEthernet\n"
	r.out["networksetup -getwebproxy Wi-Fi"] = "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n"
	r.out["networksetup -getwebproxy Ethernet"] = "Enabled: Yes\nServer: 192.0.2.2\nPort: 8080\n"
	r.out["networksetup -getwebproxy USB Adapter"] = "Enabled: Yes\nServer: 192.0.2.3\nPort: 8080\n"
	if err := m.Set("127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	if calls := strings.Join(r.calls, "\n"); !strings.Contains(calls, "-setwebproxy Ethernet 127.0.0.1 7890") ||
		!strings.Contains(calls, "-setwebproxy USB Adapter 127.0.0.1 7890") {
		t.Fatalf("unexpected proxy writes:\n%s", calls)
	}
}

func TestNetworksetupSetBoundsRetriesWhenServicesKeepChanging(t *testing.T) {
	const listServices = "networksetup -listallnetworkservices"
	r := &recorder{out: map[string]string{listServices: "Wi-Fi\n"}}
	enableAfterCapture := map[string]string{"Wi-Fi": "Ethernet", "Ethernet": "Dock", "Dock": "USB Adapter"}
	n := Networksetup{Run: func(name string, args ...string) (string, error) {
		out, err := r.run(name, args...)
		if args[0] == "-getproxybypassdomains" {
			if next := enableAfterCapture[args[1]]; next != "" {
				r.out[listServices] += next + "\n"
				delete(enableAfterCapture, args[1])
			}
		}
		return out, err
	}}
	m := New(n, filepath.Join(t.TempDir(), "proxy.armed"))
	if err := m.Set("127.0.0.1", 7890); !errors.Is(err, errServicesChanged) || m.Armed() {
		t.Fatalf("Set did not roll back after exhausting retries: armed=%t, error=%v", m.Armed(), err)
	}
	calls := strings.Join(r.calls, "\n")
	if !strings.Contains(calls, "-setwebproxystate Dock off") || strings.Contains(calls, "-setwebproxy ") {
		t.Fatalf("expected two extensions and a rollback before applying any endpoints:\n%s", calls)
	}
}

func TestNetworksetupRestoreSkipsDeletedServices(t *testing.T) {
	for _, tc := range []struct {
		name       string
		onlyIfOurs bool
	}{
		{name: "clear", onlyIfOurs: true},
		{name: "rollback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const applied = "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n"
			r := &recorder{out: map[string]string{
				"networksetup -listallnetworkservices": "Wi-Fi\n*Dock\n",
				"networksetup -getwebproxy Wi-Fi":      applied,
				"networksetup -getwebproxy Dock":       applied,
			}}
			n := Networksetup{Run: func(name string, args ...string) (string, error) {
				out, err := r.run(name, args...)
				if len(args) > 1 && args[1] == "Retired Adapter" {
					return "", os.ErrNotExist
				}
				if args[0] == "-setwebproxystate" && args[2] == "off" {
					r.out["networksetup -getwebproxy "+args[1]] = "Enabled: No\n"
				}
				return out, err
			}}
			m := New(n, filepath.Join(t.TempDir(), "proxy.armed"))
			saved, err := json.Marshal([]macService{{Name: "Retired Adapter"}, {Name: "Wi-Fi"}, {Name: "Dock"}})
			if err != nil {
				t.Fatal(err)
			}
			if err := m.saveArmed(armedFile{Saved: saved, Host: "127.0.0.1", Port: 7890}); err != nil {
				t.Fatal(err)
			}
			restore := m.Clear
			if !tc.onlyIfOurs {
				restore = func() error { return m.restoreLocked(false) }
			}
			if err := restore(); err != nil || m.Armed() {
				t.Fatalf("restore after service deletion: armed=%t, error=%v", m.Armed(), err)
			}
			calls := strings.Join(r.calls, "\n")
			if strings.Contains(calls, "Retired Adapter") || !strings.Contains(calls, "-setwebproxystate Wi-Fi off") ||
				!strings.Contains(calls, "-setwebproxystate Dock off") {
				t.Fatalf("restore did not skip only the deleted service:\n%s", calls)
			}
		})
	}
}

func TestNetworksetupFailedApplyRetainsActiveProxySnapshot(t *testing.T) {
	const socksSettings = "networksetup -getsocksfirewallproxy Ethernet"
	r := &recorder{out: map[string]string{
		"networksetup -listallnetworkservices": "Ethernet\n",
		socksSettings:                          "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n",
	}}
	applyErr := errors.New("fixture secure proxy write failed")
	n := Networksetup{Run: func(name string, args ...string) (string, error) {
		out, err := r.run(name, args...)
		if args[0] == "-setsecurewebproxy" {
			return "", applyErr
		}
		return out, err
	}}
	m := New(n, filepath.Join(t.TempDir(), "proxy.armed"))
	if err := m.Set("127.0.0.1", 7890); !errors.Is(err, applyErr) || !m.Armed() {
		t.Fatalf("failed apply released the active proxy snapshot: armed=%t, error=%v", m.Armed(), err)
	}
	if calls := strings.Join(r.calls, "\n"); !strings.Contains(calls, "-setsocksfirewallproxy Ethernet 127.0.0.1 7890") {
		t.Fatalf("rollback did not restore the captured SOCKS endpoint:\n%s", calls)
	}
	if err := m.Clear(); err == nil || !m.Armed() {
		t.Fatalf("Clear released an active SOCKS proxy: armed=%t, error=%v", m.Armed(), err)
	}
	r.out[socksSettings] = "Enabled: No\n"
	if err := m.Clear(); err != nil || m.Armed() {
		t.Fatalf("Clear after disabling the SOCKS proxy: armed=%t, error=%v", m.Armed(), err)
	}
}

func TestNetworksetupClearRequiresVerifiedRestoration(t *testing.T) {
	for _, tc := range []struct {
		name, socks string
		err         error
	}{
		{name: "unsaved SOCKS proxy", socks: "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n"},
		{name: "service query failed", err: os.ErrPermission},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "proxy.armed")
			if err := localfile.WritePrivate(path, []byte(`{"saved":[],"host":"127.0.0.1","port":7890}`)); err != nil {
				t.Fatal(err)
			}
			socks, queryErr := tc.socks, tc.err
			m := New(Networksetup{Run: func(_ string, args ...string) (string, error) {
				switch args[0] {
				case "-listallnetworkservices":
					return "Ethernet\n", nil
				case "-getsocksfirewallproxy":
					return socks, queryErr
				default:
					return "Enabled: No\n", nil
				}
			}}, path)
			if err := m.Clear(); err == nil || !m.Armed() {
				t.Fatalf("Clear released unverified recovery settings: armed=%t, error=%v", m.Armed(), err)
			}
			socks, queryErr = "Enabled: No\n", nil
			if err := m.Clear(); err != nil || m.Armed() {
				t.Fatalf("Clear did not finish after verification: armed=%t, error=%v", m.Armed(), err)
			}
		})
	}
}

func TestKdeApplyAndDetect(t *testing.T) {
	r := &recorder{}
	k := Kde{Run: r.run, Write: "kwriteconfig6", Read: "kreadconfig6"}
	if err := k.Apply("127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "--key httpProxy http://127.0.0.1 7890") {
		t.Fatalf("%v", r.calls)
	}
	all := strings.Join(r.calls, "\n")
	for _, want := range []string{"::1", "fe80::/10", "fc00::/7"} {
		if !strings.Contains(all, want) {
			t.Errorf("KDE bypass is missing %q in\n%s", want, all)
		}
	}
	none := func(string) bool { return false }
	if b := detectLinux("XFCE", none, r.run); b != nil {
		t.Fatal("expected unsupported")
	}
	if b := detectLinux("KDE", func(s string) bool { return strings.HasSuffix(s, "config6") }, r.run); b == nil {
		t.Fatal("expected KDE")
	}
}

func TestPortChangeKeepsOriginalAndRepairs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.armed")
	b := &portBackend{saved: "original"}
	m := New(b, path)
	if err := m.Set("127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	if err := m.Set("127.0.0.1", 7999); err != nil {
		t.Fatal(err)
	}
	if err := New(b, path).Repair(); err != nil || b.saved != "original" || b.port != 0 {
		t.Fatalf("repair after port change: %+v %v", b, err)
	}
}

type portBackend struct {
	saved string
	port  int
}

func (b *portBackend) Capture() (json.RawMessage, error) { return json.Marshal(b.saved) }
func (b *portBackend) Apply(_ string, p int) error       { b.port = p; return nil }
func (b *portBackend) IsApplied(_ string, p int) bool    { return b.port == p && p != 0 }
func (b *portBackend) Restore(raw json.RawMessage) error {
	b.port = 0
	return json.Unmarshal(raw, &b.saved)
}
func (b *portBackend) RestoreIfApplied(s json.RawMessage, h string, p int) error {
	return restoreIfApplied(b, s, h, p)
}

func TestKdeRequiresProxyTypeAndRestoresUnset(t *testing.T) {
	r := &recorder{out: map[string]string{
		"kreadconfig6 --file kioslaverc --group Proxy Settings --key httpProxy": "http://127.0.0.1 7890\n",
		"kreadconfig6 --file kioslaverc --group Proxy Settings --key ProxyType": "0\n",
	}}
	k := Kde{Run: r.run, Write: "kwriteconfig6", Read: "kreadconfig6"}
	if k.IsApplied("127.0.0.1", 7890) {
		t.Fatal("ProxyType 0 is not ours")
	}
	r.calls = nil
	if err := k.Restore(json.RawMessage(`{"ProxyType":""}`)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "--key ProxyType 0") {
		t.Fatalf("%v", r.calls)
	}
}

func TestNetworksetupRepairPerService(t *testing.T) {
	r := &recorder{out: map[string]string{
		"networksetup -listallnetworkservices":      "Wi-Fi\nEthernet\n",
		"networksetup -getwebproxy Wi-Fi":           "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n",
		"networksetup -getsecurewebproxy Wi-Fi":     "Enabled: Yes\nServer: 192.0.2.9\nPort: 3128\n",
		"networksetup -getsocksfirewallproxy Wi-Fi": "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n",
		"networksetup -getwebproxy Ethernet":        "Enabled: Yes\nServer: 192.0.2.9\nPort: 3128\n",
	}}
	n := Networksetup{Run: r.run}
	saved, _ := json.Marshal([]macService{{Name: "Wi-Fi"}, {Name: "Ethernet"}})
	if err := n.RestoreIfApplied(saved, "127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(r.calls, "\n")
	if !strings.Contains(all, "-setwebproxystate Wi-Fi off") || !strings.Contains(all, "-setsocksfirewallproxystate Wi-Fi off") ||
		strings.Contains(all, "-setsecurewebproxystate Wi-Fi off") || strings.Contains(all, "Ethernet off") {
		t.Fatalf("only settings still pointing at Pipe should be restored:\n%s", all)
	}
}

func TestNetworksetupSetExtendsServiceEnabledDuringApply(t *testing.T) {
	const listServices = "networksetup -listallnetworkservices"
	r := &recorder{out: map[string]string{
		listServices:                         "Wi-Fi\n*Ethernet\n",
		"networksetup -getwebproxy Ethernet": "Enabled: Yes\nServer: 192.0.2.9\nPort: 8080\n",
	}}
	enabledDuringWrite := false
	n := Networksetup{Run: func(name string, args ...string) (string, error) {
		out, err := r.run(name, args...)
		if !enabledDuringWrite && args[0] == "-setwebproxy" && args[1] == "Wi-Fi" {
			enabledDuringWrite = true
			r.out[listServices] = "Wi-Fi\nEthernet\n"
		}
		return out, err
	}}
	m := New(n, filepath.Join(t.TempDir(), "proxy.armed"))
	if err := m.Set("127.0.0.1", 7890); err != nil {
		t.Fatalf("Set failed after service enabled mid-apply: %v", err)
	}
	if calls := strings.Join(r.calls, "\n"); !strings.Contains(calls, "-setwebproxy Ethernet 127.0.0.1 7890") {
		t.Fatalf("service enabled during apply was not configured:\n%s", calls)
	}
}

func TestNetworksetupVerifyClearedChecksDisabledServices(t *testing.T) {
	const applied = "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n"
	r := &recorder{out: map[string]string{
		"networksetup -listallnetworkservices":   "*Renamed Dock\n",
		"networksetup -getwebproxy Renamed Dock": applied,
	}}
	m := New(Networksetup{Run: r.run}, filepath.Join(t.TempDir(), "proxy.armed"))
	saved, _ := json.Marshal([]macService{{Name: "Old Dock"}})
	if err := m.saveArmed(armedFile{Saved: saved, Host: "127.0.0.1", Port: 7890}); err != nil {
		t.Fatal(err)
	}
	if err := m.Clear(); err == nil || !m.Armed() {
		t.Fatalf("Clear released snapshot while disabled service still pointed at Pipe: armed=%t, err=%v", m.Armed(), err)
	}
}

func TestNetworksetupTracksLocationAcrossClear(t *testing.T) {
	const locCmd = "networksetup -getcurrentlocation"
	r := &recorder{out: map[string]string{
		locCmd:                                 "Home\n",
		"networksetup -listallnetworkservices": "Wi-Fi\n",
	}}
	m := New(Networksetup{Run: r.run}, filepath.Join(t.TempDir(), "proxy.armed"))
	if err := m.Set("127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	r.out[locCmd] = "Office\n"
	if err := m.Clear(); err == nil || !m.Armed() {
		t.Fatalf("Clear released snapshot from wrong network location: armed=%t, err=%v", m.Armed(), err)
	}
	r.out[locCmd] = "Home\n"
	if err := m.Clear(); err != nil || m.Armed() {
		t.Fatalf("Clear failed after switching back to saved location: armed=%t, err=%v", m.Armed(), err)
	}
}

func TestLinuxVerifyClearedChecksHTTPSAndSOCKSAndReadErrors(t *testing.T) {
	g := Gsettings{Run: func(_ string, args ...string) (string, error) {
		switch args[1] + " " + args[2] {
		case "org.gnome.system.proxy mode":
			return "'manual'\n", nil
		case "org.gnome.system.proxy.socks host":
			return "'127.0.0.1'\n", nil
		case "org.gnome.system.proxy.socks port":
			return "7890\n", nil
		default:
			return "''\n", nil
		}
	}}
	if err := g.verifyCleared("127.0.0.1", 7890); err == nil {
		t.Fatal("GNOME verifyCleared missed active SOCKS proxy")
	}
	gErr := Gsettings{Run: func(_ string, _ ...string) (string, error) { return "", os.ErrPermission }}
	if err := gErr.verifyCleared("127.0.0.1", 7890); err == nil {
		t.Fatal("GNOME verifyCleared treated read error as cleared")
	}
	k := Kde{Write: "kwriteconfig6", Read: "kreadconfig6", Run: func(_ string, args ...string) (string, error) {
		switch args[len(args)-1] {
		case "ProxyType":
			return "1\n", nil
		case "socksProxy":
			return "socks://127.0.0.1 7890\n", nil
		default:
			return "\n", nil
		}
	}}
	if err := k.verifyCleared("127.0.0.1", 7890); err == nil {
		t.Fatal("KDE verifyCleared missed active SOCKS proxy")
	}
}
