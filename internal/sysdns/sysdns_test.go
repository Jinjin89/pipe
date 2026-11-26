// SPDX-License-Identifier: GPL-3.0-or-later

package sysdns

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type dnsCommandRecorder struct {
	calls   []string
	outputs map[string]string
	fail    map[string]error
	before  func(string)
}

func (r *dnsCommandRecorder) run(name string, args ...string) (string, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, call)
	if r.before != nil {
		r.before(call)
	}
	if err := r.fail[call]; err != nil {
		return "", err
	}
	if output, ok := r.outputs[call]; ok {
		return output, nil
	}
	return "", nil
}

func baseDNSCommands() map[string]string {
	return map[string]string{
		"/usr/sbin/networksetup -listallnetworkservices":  "An asterisk (*) denotes a network service is disabled.\nWi-Fi\n*Old VPN\nEthernet\n",
		"/usr/sbin/networksetup -getdnsservers Wi-Fi":     "192.168.1.1\nfe80::1%en0\n",
		"/usr/sbin/networksetup -getdnsservers Ethernet":  "There aren't any DNS Servers set on Ethernet.\n",
		"/usr/sbin/scutil show State:/Network/Global/DNS": "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 192.168.1.1\n    1 : fe80::1%en0\n  }\n}\n",
	}
}

func TestSetSavesAndSetsEnabledServicesBeforeApplying(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.armed")
	recorder := &dnsCommandRecorder{outputs: baseDNSCommands()}
	recorder.before = func(call string) {
		if strings.Contains(call, "-setdnsservers") {
			if _, err := os.Stat(path); err != nil {
				t.Errorf("armed snapshot must exist before apply: %v", err)
			}
		}
	}
	manager := New(Networksetup{Run: recorder.run}, path)
	if err := manager.Set(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("armed file permissions: %v, %v", info, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file armedFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	var saved macSnapshot
	if err := json.Unmarshal(file.Saved, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Services) != 2 || saved.Services[0].Name != "Wi-Fi" || saved.Services[1].Name != "Ethernet" ||
		!saved.Services[1].Automatic || !reflect.DeepEqual(saved.Global, []string{"192.168.1.1", "fe80::1%en0"}) {
		t.Fatalf("captured DNS state: %+v", saved)
	}
	all := strings.Join(recorder.calls, "\n")
	for _, want := range []string{
		"/usr/sbin/networksetup -setdnsservers Wi-Fi 172.19.0.2",
		"/usr/sbin/networksetup -setdnsservers Ethernet 172.19.0.2",
		"/usr/bin/dscacheutil -flushcache",
		"/usr/bin/killall -HUP mDNSResponder",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing command %q in\n%s", want, all)
		}
	}
	if strings.Contains(all, "Old VPN") {
		t.Fatalf("disabled service was changed:\n%s", all)
	}
}

func TestRestoreUsesEmptyForAutomaticDNS(t *testing.T) {
	recorder := &dnsCommandRecorder{outputs: baseDNSCommands()}
	path := filepath.Join(t.TempDir(), "dns.armed")
	manager := New(Networksetup{Run: recorder.run}, path)
	if err := manager.Set(); err != nil {
		t.Fatal(err)
	}
	recorder.calls = nil
	if err := manager.Restore(); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(recorder.calls, "\n")
	if !strings.Contains(all, "/usr/sbin/networksetup -setdnsservers Ethernet Empty") ||
		!strings.Contains(all, "/usr/sbin/networksetup -setdnsservers Wi-Fi 192.168.1.1 fe80::1%en0") {
		t.Fatalf("saved DNS settings were not restored:\n%s", all)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("armed file remains after restore: %v", err)
	}
}

func TestRepairRestoresLegacyTunnelResolver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.armed")
	saved := []byte(`{"saved":{"services":[{"name":"Wi-Fi","automatic":true}]}}`)
	if err := os.WriteFile(path, saved, 0600); err != nil {
		t.Fatal(err)
	}
	recorder := &dnsCommandRecorder{outputs: baseDNSCommands()}
	recorder.outputs["/usr/sbin/networksetup -getdnsservers Wi-Fi"] = "223.5.5.5\n"
	manager := New(Networksetup{Run: recorder.run}, path)
	if err := manager.Repair(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(recorder.calls, "\n"), "-setdnsservers Wi-Fi Empty") {
		t.Fatalf("legacy DNS was not restored: %v", recorder.calls)
	}
}

func TestRepairOnlyRestoresServicesStillPointingAtPipe(t *testing.T) {
	outputs := baseDNSCommands()
	recorder := &dnsCommandRecorder{outputs: outputs}
	path := filepath.Join(t.TempDir(), "dns.armed")
	manager := New(Networksetup{Run: recorder.run}, path)
	if err := manager.Set(); err != nil {
		t.Fatal(err)
	}
	recorder.outputs["/usr/sbin/networksetup -getdnsservers Wi-Fi"] = TUNDNSAddress + "\n"
	recorder.outputs["/usr/sbin/networksetup -getdnsservers Ethernet"] = "9.9.9.9\n"
	recorder.calls = nil
	if err := manager.Repair(); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(recorder.calls, "\n")
	if !strings.Contains(all, "/usr/sbin/networksetup -setdnsservers Wi-Fi 192.168.1.1 fe80::1%en0") || strings.Contains(all, "-setdnsservers Ethernet") {
		t.Fatalf("repair must only restore Pipe-owned DNS settings:\n%s", all)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("armed file remains after repair: %v", err)
	}
}

func TestRepairKeepsOnlyServicesThatFailedToRestore(t *testing.T) {
	outputs := baseDNSCommands()
	recorder := &dnsCommandRecorder{outputs: outputs}
	path := filepath.Join(t.TempDir(), "dns.armed")
	manager := New(Networksetup{Run: recorder.run}, path)
	if err := manager.Set(); err != nil {
		t.Fatal(err)
	}
	recorder.outputs["/usr/sbin/networksetup -getdnsservers Wi-Fi"] = TUNDNSAddress + "\n"
	recorder.outputs["/usr/sbin/networksetup -getdnsservers Ethernet"] = TUNDNSAddress + "\n"
	recorder.fail = map[string]error{"/usr/sbin/networksetup -setdnsservers Wi-Fi 192.168.1.1 fe80::1%en0": os.ErrPermission}
	recorder.calls = nil
	if err := manager.Repair(); err == nil {
		t.Fatal("expected a per-service restore error")
	}
	all := strings.Join(recorder.calls, "\n")
	if !strings.Contains(all, "/usr/sbin/networksetup -setdnsservers Ethernet Empty") {
		t.Fatalf("repair stopped before later services:\n%s", all)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("partial snapshot was not retained: %v", err)
	}
	var file armedFile
	var saved macSnapshot
	if json.Unmarshal(data, &file) != nil || json.Unmarshal(file.Saved, &saved) != nil ||
		len(saved.Services) != 1 || saved.Services[0].Name != "Wi-Fi" {
		t.Fatalf("snapshot should retain only failed service: %s", data)
	}
	delete(recorder.fail, "/usr/sbin/networksetup -setdnsservers Wi-Fi 192.168.1.1 fe80::1%en0")
	if err := manager.Repair(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("armed file remains after retry: %v", err)
	}
}

func TestRepairKeepsFullSnapshotWhenEveryRestoreFails(t *testing.T) {
	recorder := &dnsCommandRecorder{outputs: baseDNSCommands()}
	path := filepath.Join(t.TempDir(), "dns.armed")
	manager := New(Networksetup{Run: recorder.run}, path)
	if err := manager.Set(); err != nil {
		t.Fatal(err)
	}
	recorder.outputs["/usr/sbin/networksetup -getdnsservers Wi-Fi"] = TUNDNSAddress + "\n"
	recorder.outputs["/usr/sbin/networksetup -getdnsservers Ethernet"] = TUNDNSAddress + "\n"
	recorder.fail = map[string]error{
		"/usr/sbin/networksetup -setdnsservers Wi-Fi 192.168.1.1 fe80::1%en0": os.ErrPermission,
		"/usr/sbin/networksetup -setdnsservers Ethernet Empty":                os.ErrPermission,
	}
	if err := manager.Repair(); err == nil {
		t.Fatal("expected restore failure")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("full failed snapshot was removed: %v", err)
	}
	var file armedFile
	var saved macSnapshot
	if json.Unmarshal(data, &file) != nil || json.Unmarshal(file.Saved, &saved) != nil || len(saved.Services) != 2 {
		t.Fatalf("full snapshot should remain after total failure: %s", data)
	}
}

func TestRepairPreservesUnreadableArmedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.armed")
	if err := os.WriteFile(path, []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	manager := New(Networksetup{Run: (&dnsCommandRecorder{}).run}, path)
	if err := manager.Repair(); err == nil {
		t.Fatal("expected damaged snapshot error")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "damaged" {
		t.Fatalf("unreadable armed file was discarded: %q, %v", data, err)
	}
}

func TestSetExtendsSnapshotWithoutRecapturingSavedServices(t *testing.T) {
	outputs := map[string]string{
		"/usr/sbin/networksetup -listallnetworkservices":  "An asterisk (*) denotes a network service is disabled.\nWi-Fi\n",
		"/usr/sbin/networksetup -getdnsservers Wi-Fi":     "192.168.1.1\n",
		"/usr/sbin/scutil show State:/Network/Global/DNS": "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 192.168.1.1\n  }\n}\n",
	}
	recorder := &dnsCommandRecorder{outputs: outputs}
	path := filepath.Join(t.TempDir(), "dns.armed")
	manager := New(Networksetup{Run: recorder.run}, path)
	if err := manager.Set(); err != nil {
		t.Fatal(err)
	}
	recorder.outputs["/usr/sbin/networksetup -listallnetworkservices"] = "An asterisk (*) denotes a network service is disabled.\nWi-Fi\nEthernet\n"
	recorder.outputs["/usr/sbin/networksetup -getdnsservers Ethernet"] = "There aren't any DNS Servers set on Ethernet.\n"
	if err := manager.Set(); err != nil {
		t.Fatal(err)
	}
	var wifiReads, ethernetApplies int
	for _, call := range recorder.calls {
		if call == "/usr/sbin/networksetup -getdnsservers Wi-Fi" {
			wifiReads++
		}
		if call == "/usr/sbin/networksetup -setdnsservers Ethernet "+TUNDNSAddress {
			ethernetApplies++
		}
	}
	if wifiReads != 1 || ethernetApplies != 1 {
		t.Fatalf("saved service recaptured or new service unapplied: wifi reads=%d, ethernet applies=%d; calls=%v", wifiReads, ethernetApplies, recorder.calls)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file armedFile
	var saved macSnapshot
	if json.Unmarshal(data, &file) != nil || json.Unmarshal(file.Saved, &saved) != nil || len(saved.Services) != 2 ||
		saved.Services[0].Servers[0] != "192.168.1.1" || !saved.Services[1].Automatic ||
		!reflect.DeepEqual(saved.Global, []string{"192.168.1.1"}) {
		t.Fatalf("extended snapshot: %+v", saved)
	}
}

func TestSetFailureKeepsServicesThatCouldNotBeRolledBack(t *testing.T) {
	recorder := &dnsCommandRecorder{outputs: baseDNSCommands(), fail: map[string]error{
		"/usr/sbin/networksetup -setdnsservers Ethernet " + TUNDNSAddress:     os.ErrPermission,
		"/usr/sbin/networksetup -setdnsservers Wi-Fi 192.168.1.1 fe80::1%en0": os.ErrPermission,
	}}
	path := filepath.Join(t.TempDir(), "dns.armed")
	manager := New(Networksetup{Run: recorder.run}, path)
	if err := manager.Set(); err == nil {
		t.Fatal("expected apply failure")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed rollback lost the armed file: %v", err)
	}
	var file armedFile
	var saved macSnapshot
	if json.Unmarshal(data, &file) != nil || json.Unmarshal(file.Saved, &saved) != nil ||
		len(saved.Services) != 1 || saved.Services[0].Name != "Wi-Fi" {
		t.Fatalf("armed file should contain only the service still needing restore: %s", data)
	}
	if !strings.Contains(strings.Join(recorder.calls, "\n"), "/usr/sbin/networksetup -setdnsservers Ethernet Empty") {
		t.Fatalf("rollback did not continue after a service error: %v", recorder.calls)
	}
}

func TestFailedRepeatedSetKeepsArmedDNS(t *testing.T) {
	recorder := &dnsCommandRecorder{outputs: baseDNSCommands()}
	path := filepath.Join(t.TempDir(), "dns.armed")
	manager := New(Networksetup{Run: recorder.run}, path)
	if err := manager.Set(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	recorder.calls = nil
	recorder.fail = map[string]error{
		"/usr/sbin/networksetup -setdnsservers Ethernet " + TUNDNSAddress: os.ErrPermission,
	}
	if err := manager.Set(); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("reapply returned %v", err)
	}
	for _, call := range recorder.calls {
		if strings.Contains(call, "-setdnsservers") && !strings.HasSuffix(call, " "+TUNDNSAddress) {
			t.Fatalf("reapply restored physical DNS while armed: %s", call)
		}
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != string(before) {
		t.Fatalf("reapply lost the original DNS snapshot: %v", err)
	}
}

func TestFlushDNSFailuresDoNotFailSetOrRestore(t *testing.T) {
	recorder := &dnsCommandRecorder{outputs: baseDNSCommands(), fail: map[string]error{
		"/usr/bin/dscacheutil -flushcache":    os.ErrPermission,
		"/usr/bin/killall -HUP mDNSResponder": os.ErrPermission,
	}}
	path := filepath.Join(t.TempDir(), "dns.armed")
	manager := New(Networksetup{Run: recorder.run}, path)
	if err := manager.Set(); err != nil {
		t.Fatalf("flush error failed Set: %v", err)
	}
	if err := manager.Restore(); err != nil {
		t.Fatalf("flush error failed Restore: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("armed file retained after successful restore: %v", err)
	}
}

func TestRestoreSkipsRemovedServices(t *testing.T) {
	outputs := baseDNSCommands()
	recorder := &dnsCommandRecorder{outputs: outputs}
	path := filepath.Join(t.TempDir(), "dns.armed")
	manager := New(Networksetup{Run: recorder.run}, path)
	if err := manager.Set(); err != nil {
		t.Fatal(err)
	}
	recorder.outputs["/usr/sbin/networksetup -listallnetworkservices"] = "An asterisk (*) denotes a network service is disabled.\nWi-Fi\n"
	recorder.calls = nil
	if err := manager.Restore(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(recorder.calls, "\n"), "Ethernet") {
		t.Fatalf("removed service was not skipped: %v", recorder.calls)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("armed file remains: %v", err)
	}
}

func TestCurrentServersUsePrimaryServiceAndSavedGlobalFallback(t *testing.T) {
	outputs := baseDNSCommands()
	outputs["/usr/sbin/scutil show State:/Network/Global/IPv4"] = "<dictionary> {\n  PrimaryService : 1234-ABCD\n}\n"
	outputs["/usr/sbin/scutil show State:/Network/Service/1234-ABCD/DNS"] = "<dictionary> {\n  ServerAddresses : <array> {\n    0 : " + TUNDNSAddress + "\n  }\n}\n"
	recorder := &dnsCommandRecorder{outputs: outputs}
	path := filepath.Join(t.TempDir(), "dns.armed")
	manager := New(Networksetup{Run: recorder.run}, path)
	if err := manager.Set(); err != nil {
		t.Fatal(err)
	}
	got := manager.Servers()
	want := []string{"192.168.1.1:53", "[fe80::1%en0]:53"}
	var actual []string
	for _, server := range got {
		actual = append(actual, server.String())
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("saved resolver fallback: %v", actual)
	}
}

func TestCurrentServersFallsBackToIPv6AndZonesLinkLocalDNS(t *testing.T) {
	outputs := map[string]string{
		"/usr/sbin/scutil show State:/Network/Global/IPv4":           "<dictionary> {\n  Router : 192.0.2.1\n}\n",
		"/usr/sbin/scutil show State:/Network/Global/IPv6":           "<dictionary> {\n  PrimaryService : 6F00-ABCD\n  PrimaryInterface : en7\n}\n",
		"/usr/sbin/scutil show State:/Network/Service/6F00-ABCD/DNS": "<dictionary> {\n  ServerAddresses : <array> {\n    0 : fe80::1\n    1 : 2001:db8::53\n  }\n}\n",
	}
	servers, err := (Networksetup{Run: (&dnsCommandRecorder{outputs: outputs}).run}).CurrentServers()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"[fe80::1%en7]:53", "[2001:db8::53]:53"}
	var got []string
	for _, server := range servers {
		got = append(got, server.String())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv6 service resolvers: %v, want %v", got, want)
	}
}

func TestScutilParsersKeepScopedAddresses(t *testing.T) {
	ipv4 := "<dictionary> {\n  PrimaryService : 49F9-12AB\n}\n"
	dns := "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 192.168.1.1\n    1 : fe80::1%en0\n  }\n  SearchDomains : <array> {\n  }\n}\n"
	if got := parseScutilValue(ipv4, "PrimaryService"); got != "49F9-12AB" {
		t.Fatalf("primary service %q", got)
	}
	if got, want := parseScutilServers(dns), []string{"192.168.1.1", "fe80::1%en0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scutil DNS servers %v, want %v", got, want)
	}
}

func TestUnsupportedBackendIsNoOp(t *testing.T) {
	manager := New(nil, filepath.Join(t.TempDir(), "dns.armed"))
	if manager.Supported() || manager.Set() != nil || manager.Restore() != nil || manager.Repair() != nil || manager.Servers() != nil {
		t.Fatal("unsupported DNS manager must be harmless")
	}
}

func TestNonDarwinDefaultIsNoOp(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("the default backend is supported on macOS")
	}
	manager := NewDefault()
	if manager.Supported() || manager.Set() != nil || manager.Restore() != nil || manager.Repair() != nil || manager.Servers() != nil {
		t.Fatal("non-darwin default manager must be a no-op")
	}
}
