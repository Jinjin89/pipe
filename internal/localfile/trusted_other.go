// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !unix

package localfile

import (
	"errors"
	"os"
)

var errTrustedUnsupported = errors.New("system executable installation is unavailable on this platform")

func TrustedExecutable(string) (string, error)         { return "", errTrustedUnsupported }
func OpenTrustedRunningImage(string) (*os.File, error) { return nil, errTrustedUnsupported }
func MakeTrustedDirectory(string) error                { return errTrustedUnsupported }
func InstallTrustedExecutable(*os.File, string) error  { return errTrustedUnsupported }
