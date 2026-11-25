// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin

package sysdns

func NewDefault() *Manager {
	return New(Networksetup{Run: ExecRunner}, defaultArmedPath)
}
