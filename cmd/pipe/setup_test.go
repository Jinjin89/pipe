// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"pipe/internal/server"
)

func TestMergeSetupConfig(t *testing.T) {
	cfg := server.SetupOptions{Mode: "shared", Domain: "a.example.com", Device: "phone"}
	flags := server.SetupOptions{Dir: "/var/lib/pipe", Domain: "b.example.com", Device: "ignored"}
	got := mergeSetupConfig(cfg, flags, map[string]bool{"domain": true})
	if !got.Yes || got.Dir != "/var/lib/pipe" || got.Mode != "shared" || got.Domain != "b.example.com" || got.Device != "phone" {
		t.Fatalf("unexpected merge: %+v", got)
	}
	cfg.Dir = "/srv/pipe"
	if got := mergeSetupConfig(cfg, flags, nil); got.Dir != "/srv/pipe" {
		t.Fatalf("config dir lost: %+v", got)
	}
	if got := mergeSetupConfig(cfg, flags, map[string]bool{"dir": true}); got.Dir != "/var/lib/pipe" {
		t.Fatalf("flag dir lost: %+v", got)
	}
}

func TestPrintSetupTemplateNoRoot(t *testing.T) {
	env := server.SetupEnv{
		GOOS: "linux", EUID: 1000,
		Interfaces: func() ([]server.SetupInterface, error) { return nil, nil },
		PortProbe:  func(int) (bool, bool) { return false, true },
		Run: func(context.Context, server.SetupCommand) error {
			t.Fatal("template must not run commands")
			return nil
		},
	}
	var out bytes.Buffer
	if err := printSetupTemplate(env, &out, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"mode": "standalone"`) {
		t.Fatalf("output: %s", out.String())
	}
}
