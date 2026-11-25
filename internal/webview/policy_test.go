// SPDX-License-Identifier: GPL-3.0-or-later

package webview

import (
	"errors"
	"runtime"
	"testing"
)

func TestParseOrigin(t *testing.T) {
	for _, tc := range []struct {
		url  string
		want string
	}{
		{"http://127.0.0.1:54321/#boot=abc", "127.0.0.1:54321"},
		{"HTTP://127.0.0.1:8080/", "127.0.0.1:8080"},
		{"http://127.0.0.1:65535/index.html", "127.0.0.1:65535"},
	} {
		got, err := ParseOrigin(tc.url)
		if err != nil || got.Host != tc.want {
			t.Errorf("ParseOrigin(%q) = (%+v, %v), want %q", tc.url, got, err, tc.want)
		}
	}

	for _, bad := range []string{
		"",
		"https://127.0.0.1:54321/",
		"http://localhost:54321/",
		"http://[::1]:54321/",
		"http://127.0.0.2:54321/",
		"http://127.0.0.1/",
		"http://127.0.0.1:0/",
		"http://127.0.0.1:05432/",
		"http://127.0.0.1:65536/",
		"http://127.0.0.1:abc/",
		"http://user@127.0.0.1:54321/",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"://broken",
	} {
		if _, err := ParseOrigin(bad); err == nil {
			t.Errorf("ParseOrigin(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestDecideNavigation(t *testing.T) {
	origin, err := ParseOrigin("http://127.0.0.1:41234/#boot=nonce")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		target string
		want   bool
	}{
		{"same origin root", "http://127.0.0.1:41234/", true},
		{"same origin boot", "http://127.0.0.1:41234/#boot=xyz", true},
		{"same origin api", "http://127.0.0.1:41234/api/status", true},
		{"same origin upper scheme", "HTTP://127.0.0.1:41234/index.html", true},
		{"wrong port", "http://127.0.0.1:9999/", false},
		{"localhost alias", "http://localhost:41234/", false},
		{"https same port", "https://127.0.0.1:41234/", false},
		{"external https", "https://example.org/docs", false},
		{"external http", "http://example.org/", false},
		{"file scheme", "file:///etc/passwd", false},
		{"javascript scheme", "javascript:alert(1)", false},
		{"data scheme", "data:text/html,<h1>hi</h1>", false},
		{"blob scheme", "blob:http://127.0.0.1:41234/uuid", false},
		{"about blank", "about:blank", false},
		{"userinfo spoof", "http://127.0.0.1:41234@evil.example/", false},
		{"userinfo same host", "http://u:p@127.0.0.1:41234/", false},
		{"empty target", "", false},
		{"invalid url", "http://[::1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := origin.DecideNavigation(tc.target); got != tc.want {
				t.Errorf("DecideNavigation(%q) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}

	var empty Origin
	if empty.DecideNavigation("http://127.0.0.1:41234/") {
		t.Error("empty origin allowed navigation")
	}
}

func TestShouldRetryProvisional(t *testing.T) {
	for i := range maxProvisionalRetries {
		if !shouldRetryProvisional(i, -1004) {
			t.Errorf("retry %d should be allowed", i)
		}
	}
	if shouldRetryProvisional(maxProvisionalRetries, -1004) {
		t.Error("retry past max should be denied")
	}
	if shouldRetryProvisional(0, errCodeCancelled) {
		t.Error("cancelled navigation should not trigger retry")
	}
	if shouldRetryProvisional(0, errCodePolicyInterrupt) {
		t.Error("policy-interrupted navigation should not trigger retry")
	}
}

func TestOpenUnsupportedOffDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("darwin backend tested on macOS")
	}
	if _, err := Open("http://127.0.0.1:12345/", Options{Title: "Pipe"}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported on %s, got %v", runtime.GOOS, err)
	}
}
