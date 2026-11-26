// SPDX-License-Identifier: GPL-3.0-or-later

package mobile

import (
	"encoding/json"
	"strings"
	"testing"

	"pipe/internal/link"
)

func TestImportShowsIndependentProxyAndTierEndpoints(t *testing.T) {
	_, profile := sampleProfile(t)
	profile.HTTPSProxy = "proxy.example:9443"
	profile.FastSNI = "fast.example"
	profile.FastPort = 8443
	profile.StealthPort = 7443
	raw, err := profile.Encode()
	if err != nil {
		t.Fatal(err)
	}
	preview, err := ParseLink(raw)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal([]byte(preview), &fields); err != nil {
		t.Fatal(err)
	}
	if fields["proxyAuthority"] != "proxy.example:9443" ||
		!strings.Contains(fields["fastEndpoint"], ":8443 (TLS name fast.example)") ||
		!strings.Contains(fields["stealthEndpoint"], ":7443") ||
		strings.Contains(preview, link.EncodeKey(profile.Seed)) {
		t.Fatalf("incorrect import summary: %s", preview)
	}
}
