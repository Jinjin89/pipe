// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// FileAutostart writes a login item file (macOS LaunchAgent or Linux .desktop).
type FileAutostart struct {
	Path   string
	Render func(exe string) string
}

func (f FileAutostart) Enable(exe string) error {
	return WriteFileAtomic(f.Path, []byte(f.Render(exe)), 0644)
}

func (f FileAutostart) Disable() error {
	if err := os.Remove(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// LaunchAgentPlist is the macOS login item (io.pipe.app).
func LaunchAgentPlist(exe string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>io.pipe.app</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEscape(exe) + `</string>
		<string>app</string>
		<string>--background</string>
	</array>
	<key>RunAtLoad</key><true/>
</dict>
</plist>
`
}

// desktopExec quotes a path for the Exec key of a .desktop file.
func desktopExec(exe string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", "$", `\$`)
	return `"` + strings.ReplaceAll(r.Replace(exe), "%", "%%") + `"`
}

// AutostartDesktop is the Linux autostart entry.
func AutostartDesktop(exe string) string {
	return "[Desktop Entry]\nType=Application\nName=Pipe\nComment=Private proxy\nExec=" +
		desktopExec(exe) + " app --background\nIcon=pipe\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
}

// windowsAutostart is set by autostart_windows.go.
var windowsAutostart Autostart

// DefaultAutostart returns the login-item manager for this OS, or nil.
func DefaultAutostart(goos string) Autostart {
	if goos == "windows" && windowsAutostart != nil {
		return windowsAutostart
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return autostartFor(goos, home)
}

func autostartFor(goos, home string) Autostart {
	switch goos {
	case "darwin":
		return FileAutostart{Path: filepath.Join(home, "Library", "LaunchAgents", "io.pipe.app.plist"), Render: LaunchAgentPlist}
	case "linux":
		return FileAutostart{Path: filepath.Join(home, ".config", "autostart", "pipe.desktop"), Render: AutostartDesktop}
	}
	return nil
}
