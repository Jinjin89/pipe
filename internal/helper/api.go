// SPDX-License-Identifier: GPL-3.0-or-later

// Package helper is Pipe Helper, the small root service that runs TUN
// sessions for the desktop app, and the app's client for it. The contract is
// docs/APP_DESIGN.md §8. This file is the frozen API; the rest of the
// package implements it.
package helper

import (
	"encoding/json"
	"errors"
)

const (
	// Label is the launchd label (macOS); the systemd unit is pipe-helper.service.
	Label = "io.pipe.helper"
	// ProtocolVersion changes only when the wire format does.
	ProtocolVersion = 4
)

// Info states.
const (
	StateMissing     = "missing"     // not installed, or not running
	StateOK          = "ok"          // answering with the app's version
	StateOutdated    = "outdated"    // answering with another version
	StateUnsupported = "unsupported" // no helper on this OS
	StateError       = "error"       // installed but refuses us (another owner) or is broken
)

// Info is the helper state the app shows.
type Info struct {
	State   string `json:"state"`
	Version string `json:"version"` // the helper's version when it answered
	Note    string `json:"note"`    // friendly text for any state but ok
}

// ErrCanceled means the user dismissed the OS password prompt.
var ErrCanceled = errors.New("Cancelled.")

// ErrOutdated means the connected helper needs an update.
var ErrOutdated = errors.New(msgOutdated)

// Paths are the fixed, root-owned locations of an installed helper.
type Paths struct {
	Binary  string // root-owned copy of pipe that the service runs
	Service string // LaunchDaemon plist (macOS) or systemd unit (Linux)
	Owner   string // owner record: the one user id allowed to connect
	Socket  string // control socket
}

// PathsFor returns the helper paths for goos, or false when the OS has no helper.
func PathsFor(goos string) (Paths, bool) {
	switch goos {
	case "darwin":
		return Paths{
			Binary:  "/Library/PrivilegedHelperTools/io.pipe.helper",
			Service: "/Library/LaunchDaemons/io.pipe.helper.plist",
			Owner:   "/Library/Application Support/io.pipe.helper/owner",
			Socket:  "/var/run/io.pipe.helper.sock",
		}, true
	case "linux":
		return Paths{
			Binary:  "/usr/local/lib/pipe/pipe-helper",
			Service: "/etc/systemd/system/pipe-helper.service",
			Owner:   "/etc/pipe-helper/owner",
			Socket:  "/run/pipe-helper/helper.sock",
		}, true
	}
	return Paths{}, false
}

// Request is one line from the app to the helper.
type Request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is the helper's one-line answer. Error is friendly text.
type Response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// SessionOptions is clientctl.Options on the wire. The profile travels as its
// pipe:// link and the rules as rule text, so the helper parses and validates
// both itself. TUN is not on the wire: the helper always runs TUN.
type SessionOptions struct {
	Link     string   `json:"link"`
	Relay    string   `json:"relay,omitempty"` // optional relay code
	Mode     string   `json:"mode"`
	Tier     string   `json:"tier"`
	IPv6     bool     `json:"ipv6"`
	Rules    []string `json:"rules"`
	Listen   string   `json:"listen"`
	LogLevel string   `json:"logLevel"`
}

// TestProfileParams is the request for a fresh probe of a saved profile.
type TestProfileParams struct {
	Link  string `json:"link"`
	Relay string `json:"relay,omitempty"`
	IPv6  bool   `json:"ipv6"`
}
