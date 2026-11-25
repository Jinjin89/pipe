// SPDX-License-Identifier: GPL-3.0-or-later

package sysproxy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type memBackend struct {
	state     string
	applied   int
	failApply bool
}

func (m *memBackend) Capture() (json.RawMessage, error) { return json.Marshal(m.state) }
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
func (m *memBackend) Restore(raw json.RawMessage) error { return json.Unmarshal(raw, &m.state) }

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

func TestNetworksetupParsingAndRestore(t *testing.T) {
	services := "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Old VPN\nEthernet\n"
	if got := parseServices(services); len(got) != 2 || got[0] != "Wi-Fi" || got[1] != "Ethernet" {
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
		"networksetup -getwebproxy Wi-Fi":    "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n",
		"networksetup -getwebproxy Ethernet": "Enabled: Yes\nServer: 192.0.2.9\nPort: 3128\n",
	}}
	n := Networksetup{Run: r.run}
	saved, _ := json.Marshal([]macService{{Name: "Wi-Fi"}, {Name: "Ethernet"}})
	if err := n.RestoreIfApplied(saved, "127.0.0.1", 7890); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(r.calls, "\n")
	if !strings.Contains(all, "-setwebproxystate Wi-Fi off") || strings.Contains(all, "Ethernet off") {
		t.Fatalf("only Wi-Fi should be restored:\n%s", all)
	}
}
