// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestReleaseDependenciesExcludeTemplates(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if errors.Is(err, exec.ErrNotFound) {
		t.Skip("go is not on PATH")
	}
	if err != nil {
		t.Fatal(err)
	}

	// Match the Linux release configuration in scripts/package-desktop.sh.
	const tags = "with_gvisor,with_quic,with_utls,with_acme,badlinkname,tfogo_checklinkname0"
	cmd := exec.CommandContext(t.Context(), goTool, "list", "-p", "2", "-mod=readonly", "-deps", "-tags", tags, "pipe/cmd/pipe")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOWORK=off")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("list release dependencies: %v\n%s", err, output)
	}
	for _, dependency := range strings.Fields(string(output)) {
		switch dependency {
		case "html/template", "text/template":
			t.Errorf("release binary depends on %s, whose reflection retains otherwise unused methods", dependency)
		}
	}
}
