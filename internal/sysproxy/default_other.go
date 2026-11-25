// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !linux && !darwin && !windows

package sysproxy

func Default() Backend { return nil }
