// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin

package sysproxy

func Default() Backend { return Networksetup{Run: ExecRunner} }
