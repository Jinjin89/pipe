// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !unix && !windows

package update

import "os"

func directoryAnchor(string) (string, error)         { return "", errUnsafeDirectory }
func checkDirectory(string, os.FileInfo, bool) error { return errUnsafeDirectory }
func mkdirPrivate(string) error                      { return errUnsafeDirectory }
