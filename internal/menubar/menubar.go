// SPDX-License-Identifier: GPL-3.0-or-later

// Package menubar is the macOS menu bar icon (APP_DESIGN §8.6). It's pure Go
// through purego, so there's no cgo. On other OSes Run returns ErrUnsupported.
package menubar

import "errors"

// ErrUnsupported is returned by Run where there is no menu bar icon.
var ErrUnsupported = errors.New("no menu bar on this OS")

// Capital upper-cases the first letter of a lowercase ASCII word.
func Capital(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}

// State is what the menu shows. Actions.State is called when Changes fires,
// when the menu opens, and every 30 s as a slow fallback; there is no timer
// while the menu is idle.
type State struct {
	Status       string // off|connecting|on|error
	Title        string // first, disabled line, e.g. "Connected · Fast · 42 ms"
	Tooltip      string
	Mode         string // smart|global|direct
	Tier         string // the route preference: auto|fast|stealth|rescue
	RelayHost    string // configured relay's host
	RelayState   string // empty, pending, via or direct
	Rescue       bool   // the Rescue route exists for this profile
	TUN          bool   // TUN is the chosen way to connect
	TUNAvailable bool   // this OS has Pipe Helper
	SystemProxy  bool   // the System proxy setting
}

func menuTitle(s State) string {
	if s.Title == "" {
		return "Pipe"
	}
	if s.Status == "on" {
		switch s.RelayState {
		case "via":
			return s.Title + " · via " + s.RelayHost
		case "direct":
			return s.Title + " · relay not reachable, direct"
		}
	}
	return s.Title
}

// Actions are called on their own goroutine, never on the main thread, so
// they may block (for example on the OS password prompt).
type Actions struct {
	State          func() State
	Changes        <-chan struct{} // fires after any state transition (may be nil)
	Connect        func()
	Disconnect     func()
	SetMode        func(mode string)
	SetTier        func(tier string)
	SetTUN         func(on bool)
	SetSystemProxy func(on bool)
	Open           func() // show the window
	Quit           func() // clean quit; Run returns after Stop
}
