// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"context"

	"pipe/internal/clientctl"
	"pipe/internal/helper"
)

// Controller is the session controller the server drives (design section 1.5).
// *clientctl.Controller implements it; tests use a fake.
type Controller interface {
	Start(opts clientctl.Options) error
	Stop() error
	Status() clientctl.Status
	SetMode(mode string) error
	SetTier(tier string) error
	Apply(opts clientctl.Options) error
	TestRoutes(ctx context.Context) map[string]clientctl.RouteLatency
}

// Helper is Pipe Helper as the app sees it: a Controller for the TUN session
// that runs inside the root service, plus install and remove
// (APP_DESIGN §8). *helper.Remote implements it.
type Helper interface {
	Controller
	TestProfile(context.Context, clientctl.ProbeOptions) (map[string]clientctl.RouteLatency, error)
	Info() helper.Info
	Install() error  // shows the OS password prompt; helper.ErrCanceled when dismissed
	Remove() error   // shows the OS password prompt
	SyncLogs()       // copies the helper's new log lines into the app's log ring
	OnChange(func()) // f runs when the helper session ends on its own; f must not block
}

// Autostart installs or removes "start at login".
type Autostart interface {
	Enable(exe string) error
	Disable() error
}
