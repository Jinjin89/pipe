// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pipe/internal/localfile"
)

func TestYAMLCommentsAndRules(t *testing.T) {
	const input = `# Portable preferences
server: home # saved profile
mode: smart
tun: true
ipv6: false
rules:
  # Earlier rules have priority.
  - netflix.com -> proxy # video
  - 'suffix:example.test -> block'
  - 'keyword:video -> proxy'
  - 'app:com.tencent.mm -> direct'
  - 'process:/opt/Video Player -> proxy'
  - 192.0.2.1/24 -> direct
  - 2001:db8::/32 -> direct
`
	file, err := ParseYAML([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	want := []Rule{
		{"domain", "netflix.com", "proxy"},
		{"domain_suffix", "example.test", "block"},
		{"domain_keyword", "video", "proxy"},
		{"package_name", "com.tencent.mm", "direct"},
		{"process_path", "/opt/Video Player", "proxy"},
		{"ip_cidr", "192.0.2.0/24", "direct"},
		{"ip_cidr", "2001:db8::/32", "direct"},
	}
	if !file.TUN || file.IPv6 || file.Server != "home" || !slices.Equal(file.Rules, want) {
		t.Fatalf("unexpected preferences: %+v", file.Preferences)
	}
	file.Node.Content[0].Content[3].Value = "global"
	encoded, err := file.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, comment := range []string{"# Portable preferences", "# saved profile", "# Earlier rules have priority.", "# video"} {
		if !strings.Contains(string(encoded), comment) {
			t.Errorf("missing comment %q", comment)
		}
	}
	parsed, err := ParseYAML(encoded)
	if err != nil || parsed.Mode != Global || !slices.Equal(parsed.Rules, want) {
		t.Fatalf("edited YAML lost settings: %v", err)
	}
}

func TestReadYAMLRejectsNonRegularAndOversizeFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadYAML(dir); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected directory rejection, got %v", err)
	}
	path := filepath.Join(dir, "pipe.yaml")
	prefix := "mode: smart\n#"
	for _, size := range []int{localfile.MaxConfigBytes, localfile.MaxConfigBytes + 1} {
		if err := os.WriteFile(path, []byte(prefix+strings.Repeat("a", size-len(prefix))), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadYAML(path)
		if size == localfile.MaxConfigBytes && err != nil || size > localfile.MaxConfigBytes && (err == nil || !strings.Contains(err.Error(), "exceeds")) {
			t.Fatalf("unexpected YAML read result for %d bytes: %v", size, err)
		}
	}
}

func TestYAMLValidation(t *testing.T) {
	for _, test := range []struct {
		name, yaml, message string
		line                int
	}{
		{"unknown", "mode: smart\nlink: secret\n", "unknown field", 2},
		{"duplicate", "mode: smart\nmode: global\n", "duplicate", 2},
		{"alias", "server: ../home\n", "profile alias", 1},
		{"mode", "mode: unknown\n", "mode must", 1},
		{"bool", "tun: 'true'\n", "true or false", 1},
		{"rule action", "rules:\n  - example.test -> accept\n", "expected <match>", 2},
		{"rule match", "rules:\n  - 2001:db8::/129 -> direct\n", "invalid domain", 2},
		{"sequence", "rules: {one: two}\n", "ordered list", 1},
		{"multiple", "---\nmode: smart\n---\nmode: global\n", "one YAML document", 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseYAML([]byte(test.yaml))
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("line %d:", test.line)) || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected line %d error about %q, got %v", test.line, test.message, err)
			}
		})
	}
}
