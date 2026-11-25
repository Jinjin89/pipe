// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !linux && !darwin && !windows

package desktop

func acquireLock(path string) (func(), bool, error) { return func() {}, false, nil }
