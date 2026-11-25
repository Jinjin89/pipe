// SPDX-License-Identifier: GPL-3.0-or-later
//go:build windows

package desktop

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// RegistryAutostart uses HKCU Run\Pipe.
type RegistryAutostart struct{}

func (RegistryAutostart) Enable(exe string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if strings.ContainsAny(exe, "\"\r\n") {
		return errors.New("the program path contains characters that can't be used at login")
	}
	return k.SetStringValue("Pipe", `"`+exe+`" app --background`)
}

func (RegistryAutostart) Disable() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	if err := k.DeleteValue("Pipe"); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

func init() { windowsAutostart = RegistryAutostart{} }
