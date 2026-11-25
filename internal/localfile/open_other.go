// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !unix

package localfile

import "os"

func openRegular(path string) (*os.File, error) { return os.Open(path) }
