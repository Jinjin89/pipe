// SPDX-License-Identifier: GPL-3.0-or-later
//go:build unix

package update

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type localSourceDir struct {
	fd   int
	path string
}

func openLocalSourceDir(dir string) (*localSourceDir, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &localSourceDir{fd: fd, path: dir}, nil
}

func (d *localSourceDir) Close() error {
	if d == nil || d.fd < 0 {
		return nil
	}
	err := unix.Close(d.fd)
	d.fd = -1
	return err
}

func (d *localSourceDir) OpenRegular(name string) (*os.File, os.FileInfo, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, nil, errors.New("invalid local release filename")
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(d.path, name))
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, errors.New("release input must be a regular file")
	}
	return f, info, nil
}
