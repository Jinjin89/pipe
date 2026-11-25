// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !android

package relay

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRelayTableOwnershipAndTransactions(t *testing.T) {
	ctx := t.Context()
	exists, owned := true, false
	var batches []string
	n := relaySystem{run: func(_ context.Context, tool, input string, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "-j -a list tables":
			if exists {
				return `{"nftables":[{"table":{"family":"inet","name":"pipe_relay","handle":12}}]}`, nil
			}
			return `{"nftables":[{"table":{"family":"inet","name":"pipe","handle":1}}]}`, nil
		case "-n -t list table inet pipe_relay":
			if owned {
				return "table inet pipe_relay {\n\tcomment \"Pipe relay\"\n}\n", nil
			}
			return "table inet pipe_relay {\n\tchain test {\n\t\tcomment \"Pipe relay\"\n\t}\n}\n", nil
		case "-f -":
			batches = append(batches, input)
			exists = strings.Contains(input, "create table")
			return "", nil
		default:
			t.Fatalf("unexpected %s call %v", tool, args)
			return "", nil
		}
	}}
	if _, err := n.ownedTable(ctx); err == nil {
		t.Fatal("accepted a table with only a rule ownership comment")
	}
	owned = true
	table, err := n.ownedTable(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const create = "create table inet pipe_relay { comment \"Pipe relay\"; }\n"
	if err := n.writeTable(ctx, table.Handle, create); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		table, err = n.ownedTable(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.writeTable(ctx, table.Handle, ""); err != nil {
			t.Fatal(err)
		}
	}
	const remove = "delete table inet handle 12\n"
	if !slices.Equal(batches, []string{remove + create, remove}) {
		t.Fatalf("unexpected nft transactions %q", batches)
	}
}

func TestRelayServiceAndSysctl(t *testing.T) {
	text := unitText("/opt/Pipe space/pipe%$\"\\", "/tmp/relay space%$.conf")
	if want := ` relay apply
`; !strings.Contains(unitText("/opt/pipe", DefaultStatePath), want) {
		t.Fatal("default unit should only run relay apply")
	}
	for _, want := range []string{
		"After=nftables.service local-fs.target",
		"Before=network-pre.target",
		"Type=oneshot",
		`ExecStart="/opt/Pipe space/pipe%%$$\"\\" relay apply --state "/tmp/relay space%%$$.conf"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("unit missing %q\n%s", want, text)
		}
	}
	n := relaySystem{host: true, run: func(_ context.Context, tool, _ string, args ...string) (string, error) {
		if tool != "sysctl" || !slices.Equal(args, []string{"-n", conntrackMax}) {
			t.Fatalf("unexpected %s call %v", tool, args)
		}
		return "524288\n", nil
	}}
	raKey := raSysctl("eth0.100")
	previous := map[string]string{ipv6Forward: "0", raKey: "1"}
	settings, err := n.tunings(t.Context(), []string{ipv6Forward}, previous)
	if err != nil {
		t.Fatal(err)
	}
	text = sysctlText(settings, previous)
	if !strings.Contains(text, "net.core.default_qdisc = fq\n") ||
		!strings.Contains(text, conntrackMax+" = 524288\n") ||
		!strings.Contains(text, "# previous "+raKey+"=1\n"+raKey+" = 2\n") ||
		!strings.Contains(text, ipv6Forward+" = 1\n") ||
		strings.Contains(text, ipv4Forward) || strings.Contains(text, "bbr") ||
		!maps.Equal(priorSysctls(text), previous) {
		t.Fatalf("unexpected sysctl config\n%s", text)
	}
	n.host = false
	settings, err = n.tunings(t.Context(), []string{ipv6Forward}, nil)
	if err != nil || !slices.Equal(settings, []sysctlSetting{{ipv6Forward, "1"}}) {
		t.Fatalf("namespace settings = %v, %v", settings, err)
	}
}

func TestRelayLoadsRulesBeforeReadingConntrackMax(t *testing.T) {
	for _, test := range []struct {
		name    string
		readErr error
	}{
		{"key appears after load", nil},
		{"key still missing after load", os.ErrNotExist},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := testRoute(t, "93.184.216.34", "8443", "", "relay.example")
			next := state{ingress{IPv4: []string{"eth0"}}, []route{r}}
			path := filepath.Join(t.TempDir(), "90-pipe-relay.conf")
			loaded, enabled := false, false
			n := relaySystem{host: true, sysctlFile: path, run: func(_ context.Context, tool, input string, args ...string) (string, error) {
				switch tool + " " + strings.Join(args, " ") {
				case "nft -j -a list tables":
					return `{"nftables":[]}`, nil
				case "sysctl -n " + ipv4Forward:
					return "0\n", nil
				case "nft -f -":
					if !strings.Contains(input, "create table inet pipe_relay") || !strings.Contains(input, "ct state new") {
						t.Fatalf("expected stateful rules in the nft batch\n%s", input)
					}
					loaded = true
					return "", nil
				case "sysctl -n " + conntrackMax:
					if !loaded {
						t.Fatal("conntrack sysctl read before loading the rules")
					}
					return "65536\n", test.readErr
				case "sysctl -w net.core.default_qdisc=fq " + conntrackMax + "=262144 " + ipv4Forward + "=1":
					enabled = true
					return "", nil
				default:
					t.Fatalf("unexpected %s call %v", tool, args)
					return "", nil
				}
			}}
			active, err := n.apply(t.Context(), next)
			if !active || !loaded {
				t.Fatalf("apply() = active %t, %v, after loading a table: %t", active, err, loaded)
			}
			if test.readErr != nil {
				if !errors.Is(err, test.readErr) || !strings.Contains(err.Error(), conntrackMax+" after loading relay rules") || enabled {
					t.Fatalf("expected a conntrack read error before enabling forwarding, got %v (enabled %t)", err, enabled)
				}
				return
			}
			if err != nil || !enabled {
				t.Fatalf("apply() error = %v, forwarding enabled = %t", err, enabled)
			}
		})
	}
}

func TestRelayRestoreForwarding(t *testing.T) {
	var writes []string
	n := relaySystem{run: func(_ context.Context, tool, input string, args ...string) (string, error) {
		if args[0] == "-n" {
			return "1\n", nil
		}
		writes = append(writes, args[1:]...)
		return "", nil
	}}
	previous := map[string]string{ipv4Forward: "0", ipv6Forward: "1"}
	if err := n.restoreSysctls(t.Context(), previous, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(writes, []string{ipv4Forward + "=0"}) {
		t.Fatalf("restored settings = %v", writes)
	}
}

func TestRelayAcceptRAApplyReinstallAndRemove(t *testing.T) {
	managed := raSysctl("eth0.100")
	disabled := raSysctl("eth1")
	forwardingRA := raSysctl("eth2")
	removed := raSysctl("eth3")
	state := map[string]string{ipv6Forward: "0", managed: "1", disabled: "0", forwardingRA: "2", removed: "1"}
	var writes []string
	n := relaySystem{run: func(_ context.Context, tool, _ string, args ...string) (string, error) {
		if tool != "sysctl" {
			t.Fatalf("unexpected %s call %v", tool, args)
		}
		switch args[0] {
		case "-n":
			return state[args[1]], nil
		case "-e":
			return state[args[2]], nil
		case "-w":
			for _, arg := range args[1:] {
				if key, value, ok := strings.Cut(arg, "="); ok {
					state[key] = value
					writes = append(writes, arg)
				}
			}
			return "", nil
		default:
			t.Fatalf("unexpected sysctl arguments %v", args)
			return "", nil
		}
	}}
	deviceNames := []string{"eth0.100", "eth1", "eth2", "eth3"}
	prior := map[string]string{ipv6Forward: "0", managed: "1", removed: "1"}
	var baseline map[string]string
	for range 2 {
		previous, err := n.prepareSysctls(t.Context(), baseline, []string{ipv6Forward}, deviceNames)
		if err != nil || !maps.Equal(previous, prior) {
			t.Fatalf("prepareSysctls() = %v, %v, want %v", previous, err, prior)
		}
		settings, err := n.tunings(t.Context(), []string{ipv6Forward}, previous)
		if err != nil {
			t.Fatal(err)
		}
		writes = nil
		if err := n.applySysctls(t.Context(), settings); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(writes, []string{managed + "=2", removed + "=2", ipv6Forward + "=1"}) {
			t.Fatalf("unexpected apply order %v", writes)
		}
		baseline = previous
	}
	delete(state, removed)
	writes = nil
	if err := n.restoreSysctls(t.Context(), baseline, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(writes, []string{ipv6Forward + "=0", managed + "=1"}) {
		t.Fatalf("unexpected restore order %v", writes)
	}
	if state[disabled] != "0" || state[forwardingRA] != "2" {
		t.Fatalf("unmanaged RA settings updated to %v", state)
	}
}

func TestRelayKeepsRAWhenAlreadyForwarding(t *testing.T) {
	n := relaySystem{run: func(_ context.Context, tool, _ string, args ...string) (string, error) {
		if tool != "sysctl" || !slices.Equal(args, []string{"-n", ipv6Forward}) {
			t.Fatalf("unexpected %s call %v", tool, args)
		}
		return "1\n", nil
	}}
	previous, err := n.prepareSysctls(t.Context(), nil, []string{ipv6Forward}, []string{"eth0"})
	if err != nil || !maps.Equal(previous, map[string]string{ipv6Forward: "1"}) {
		t.Fatalf("prepareSysctls() = %v, %v", previous, err)
	}
}

func TestRelayManagedFileOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe-relay.service")
	if text, err := readOwnedFile(path); err != nil || text != "" {
		t.Fatalf("missing file = %q, %v", text, err)
	}
	if err := writeManagedFile(path, "[Unit]\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnedFile(path); err == nil {
		t.Fatal("accepted unrelated file")
	}
	want := ownedHeader + "[Unit]\n"
	if err := writeManagedFile(path, want); err != nil {
		t.Fatal(err)
	}
	if text, err := readOwnedFile(path); err != nil || text != want {
		t.Fatalf("managed file = %q, %v, want %q", text, err, want)
	}
	link := filepath.Join(filepath.Dir(path), "other.service")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnedFile(link); err == nil {
		t.Fatal("accepted a symlink")
	}
	if _, err := readManagedFile(path, int64(len(want)-1)); err == nil {
		t.Fatal("accepted an oversized managed file")
	}
	if err := os.Chmod(path, 0664); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnedFile(path); err == nil {
		t.Fatal("accepted a group-writable file")
	}
}

func TestRelayChangeRestoresStateOnFailedNft(t *testing.T) {
	ipv4 := testRoute(t, "93.184.216.34", "8443", "", "relay.example")
	ipv6 := testRoute(t, "2606:4700::1234", "8444", "", "relay.example")
	old := state{ingress{IPv4: []string{"eth0"}, IPv6: []string{"eth1"}}, []route{ipv4, ipv6}}
	next := state{ingress{IPv4: []string{"eth0"}}, []route{ipv4}}
	text, err := stateText(old)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "relay.conf")
	if err := writeManagedFile(path, text); err != nil {
		t.Fatal(err)
	}
	rejected := errors.New("nft batch rejected")
	var writes []string
	n := relaySystem{run: func(_ context.Context, tool, _ string, args ...string) (string, error) {
		switch tool + " " + strings.Join(args, " ") {
		case "nft -j -a list tables":
			return "{\"nftables\":[{\"table\":{\"family\":\"inet\",\"name\":\"pipe_relay\",\"handle\":12}}]}", nil
		case "nft -n -t list table inet pipe_relay":
			return "table inet pipe_relay {\n\tcomment \"Pipe relay " + ipv4Forward + "=0 " + ipv6Forward + "=0\"\n}\n", nil
		case "nft -f -":
			return "", rejected
		case "sysctl -n " + ipv6Forward:
			return "1\n", nil
		case "sysctl -w " + ipv6Forward + "=0", "sysctl -w " + ipv6Forward + "=1":
			writes = append(writes, args[1])
			return "", nil
		default:
			t.Fatalf("unexpected %s call %v", tool, args)
			return "", nil
		}
	}}
	if err := n.change(t.Context(), path, next, text, ""); !errors.Is(err, rejected) {
		t.Fatalf("change() error = %v", err)
	}
	if _, raw, err := readState(path); err != nil || raw != text {
		t.Fatalf("state after failed change = %q, %v", raw, err)
	}
	if !slices.Equal(writes, []string{ipv6Forward + "=0", ipv6Forward + "=1"}) {
		t.Fatalf("IPv6 writes after failed change = %v", writes)
	}
}
