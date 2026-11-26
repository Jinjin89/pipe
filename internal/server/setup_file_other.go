// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !unix

package server

import (
	"errors"
	"os"
)

func openSetupFile(string) (*os.File, error) {
	return nil, errors.New("secure server setup file access requires Unix")
}

func openSetupOperatorFile(string, uint32) (*os.File, error) {
	return nil, errors.New("secure server setup file access requires Unix")
}

func openSetupState(string, uint32, bool) (*os.Root, error) {
	return nil, errors.New("secure server setup state access requires Linux")
}

func setupFileOwner(os.FileInfo) (uint32, bool) { return 0, false }
