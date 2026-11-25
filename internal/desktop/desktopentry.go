// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed icon-256.png
var icon256 []byte

// MenuDesktop is the application-menu entry.
func MenuDesktop(exe string) string {
	return "[Desktop Entry]\nType=Application\nName=Pipe\nComment=Private proxy\nExec=" + desktopExec(exe) +
		" app\nIcon=pipe\nTerminal=false\nCategories=Network;\nStartupWMClass=pipe\n"
}

// InstallDesktopEntry writes pipe.desktop and its icon under dataHome
// (normally ~/.local/share). It returns the .desktop path.
func InstallDesktopEntry(dataHome, exe string) (string, error) {
	iconPath := filepath.Join(dataHome, "icons", "hicolor", "256x256", "apps", "pipe.png")
	if err := WriteFileAtomic(iconPath, icon256, 0644); err != nil {
		return "", fmt.Errorf("write icon: %w", err)
	}
	entry := filepath.Join(dataHome, "applications", "pipe.desktop")
	if err := WriteFileAtomic(entry, []byte(MenuDesktop(exe)), 0644); err != nil {
		return "", fmt.Errorf("write desktop entry: %w", err)
	}
	return entry, nil
}

// DataHome returns XDG_DATA_HOME or ~/.local/share.
func DataHome() (string, error) {
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share"), nil
}
