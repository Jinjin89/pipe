// SPDX-License-Identifier: GPL-3.0-or-later

package sysdns

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner runs a system command and returns its standard output.
type Runner func(name string, args ...string) (string, error)

// ExecRunner runs system commands with a timeout.
func ExecRunner(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name)
	if name != "/usr/sbin/scutil" {
		command.Args = append(command.Args, args...)
	} else {
		command.Stdin = strings.NewReader(strings.Join(args, " ") + "\nquit\n")
	}
	out, err := command.Output()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w", name, err)
	}
	return string(out), nil
}
