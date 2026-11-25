// SPDX-License-Identifier: GPL-3.0-or-later

package sysproxy

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner runs a command and returns its standard output. Tests replace it.
type Runner func(name string, args ...string) (string, error)

// ExecRunner runs real commands with a timeout.
func ExecRunner(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w", name, err)
	}
	return string(out), nil
}

func lookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func trim(s string) string { return strings.TrimSpace(s) }
