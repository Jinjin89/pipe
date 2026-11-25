// SPDX-License-Identifier: GPL-3.0-or-later

// Package localfile reads bounded configuration files.
package localfile

import (
	"fmt"
	"io"
	"runtime"
)

const MaxConfigBytes = 1 << 20

// Read checks the open file before reading and detects growth past the limit.
func Read(path string, limit int64, ownerOnly bool) ([]byte, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", path)
	}
	if ownerOnly && runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s permissions must restrict access to the owner", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, nil
}
