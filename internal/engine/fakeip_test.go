// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
)

func TestFakeIPSurvivesEngineReplacement(t *testing.T) {
	cache := &FakeIP{}
	t.Cleanup(func() { _ = cache.Close() })
	options := option.FakeIPDNSServerOptions{
		Inet4Range: (*badoption.Prefix)(new(netip.MustParsePrefix("198.18.0.0/15"))),
		Inet6Range: (*badoption.Prefix)(new(netip.MustParsePrefix("fc00::/18"))),
	}
	startTransport := func() (adapter.FakeIPStore, *adapter.Scope) {
		t.Helper()
		log := logger.NOP()
		transport, err := cache.newTransport(t.Context(), log, "fake-ip", options)
		if err != nil {
			t.Fatal(err)
		}
		scope := adapter.NewScope(t.Context(), log)
		if err := transport.Start(adapter.StartStateStart, scope); err != nil {
			t.Fatal(err)
		}
		return transport.(adapter.FakeIPTransport).Store(), scope
	}
	old, oldScope := startTransport()
	t.Cleanup(func() { _ = oldScope.Close() })
	address, err := old.Create("cached.example", false)
	if err != nil {
		t.Fatal(err)
	}
	replacement, replacementScope := startTransport()
	t.Cleanup(func() { _ = replacementScope.Close() })
	other, err := replacement.Create("new.example", false)
	if err != nil || other == address {
		t.Fatalf("replacement reused a cached IP: %s, %v", other, err)
	}
	if err := oldScope.Close(); err != nil {
		t.Fatal(err)
	}
	if domain, ok := replacement.Lookup(address); !ok || domain != "cached.example" {
		t.Fatalf("cached address after replacement maps to %q, found %v", domain, ok)
	}
}
