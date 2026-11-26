// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !unix

package update

import (
	"errors"
	"os"
	"path/filepath"
)

type localSourceDir struct {
	root *os.Root
}

func openLocalSourceDir(dir string) (*localSourceDir, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &localSourceDir{root: root}, nil
}

func (d *localSourceDir) Close() error { return d.root.Close() }

func (d *localSourceDir) OpenRegular(name string) (*os.File, os.FileInfo, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, nil, errors.New("invalid local release filename")
	}
	linfo, err := d.root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !linfo.Mode().IsRegular() {
		return nil, nil, errors.New("release input must be a regular file")
	}
	f, err := d.root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil || !os.SameFile(linfo, info) || !info.Mode().IsRegular() {
		f.Close()
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, errors.New("release input must be a regular file")
	}
	return f, info, nil
}
