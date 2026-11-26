// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"pipe/internal/localfile"
)

const ReadSetupOperatorInputCommand = "--read-operator-input"

// Use the protected binary installed by setup to enforce both the trusted
// path rules and the operator's actual file permissions on config inputs.
func (r *setupRun) readSetupInputAsOperator(path string, limit int64, ownerOnly bool) ([]byte, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	uid := strconv.FormatUint(uint64(r.operatorUID), 10)
	account, err := user.LookupId(uid)
	if err != nil {
		return nil, fmt.Errorf("look up setup operator UID %s: %w", uid, err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid GID for setup operator %q", account.Username)
	}
	cmd := exec.CommandContext(r.ctx, r.path(setupBinary), "server", "setup", ReadSetupOperatorInputCommand,
		path, strconv.FormatUint(uint64(r.uid), 10), strconv.FormatInt(limit, 10), strconv.FormatBool(ownerOnly))
	cmd.Env = setupChildEnvironment(false)
	if err := dropCredentials(cmd, r.operatorUID, uint32(gid)); err != nil {
		return nil, err
	}
	data, err := cmd.Output()
	if err != nil {
		clear(data)
		var exit *exec.ExitError
		if errors.As(err, &exit) && len(exit.Stderr) != 0 {
			err = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exit.Stderr)))
		}
		return nil, fmt.Errorf("read setup input %q as operator %q: %w", path, account.Username, err)
	}
	return data, nil
}

// ReadSetupOperatorInput is the unprivileged child entry point for setup inputs.
func ReadSetupOperatorInput(path, serviceUID, maxBytes, private string, out io.Writer) error {
	if runtime.GOOS != "linux" || os.Getuid() == 0 || os.Geteuid() == 0 {
		return errors.New("setup operator input reader requires an unprivileged Linux user")
	}
	pipeUID, uidErr := strconv.ParseUint(serviceUID, 10, 32)
	limit, sizeErr := strconv.ParseInt(maxBytes, 10, 64)
	ownerOnly, modeErr := strconv.ParseBool(private)
	if uidErr != nil || sizeErr != nil || modeErr != nil || limit <= 0 || limit > localfile.MaxConfigBytes {
		return errors.New("invalid setup operator input request")
	}
	data, err := readSetupOperatorFile(path, uint32(pipeUID), uint32(os.Getuid()), limit, ownerOnly)
	if err != nil {
		return err
	}
	defer clear(data)
	_, err = out.Write(data)
	return err
}
