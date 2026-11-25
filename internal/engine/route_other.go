// SPDX-License-Identifier: GPL-3.0-or-later

//go:build android || ios || (!linux && !darwin && !windows)

package engine

import "errors"

func ipv6DefaultInterfaces() (map[int]struct{}, error) {
	return nil, errors.ErrUnsupported
}
