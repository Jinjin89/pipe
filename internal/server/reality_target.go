// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"errors"
	"strings"
)

// realitySelf is the only shared-mode reality_dest: REALITY borrows this
// server's own HTTPS proxy site on 127.0.0.1. An empty value means no Stealth.
const realitySelf = "self"

var (
	errSelfNeedsProxy = errors.New("reality_dest self needs the HTTPS proxy on its own domain (proxy_domain)")
	errRealityNotSelf = errors.New("REALITY now always borrows your own HTTPS proxy site: use reality_dest self (it needs proxy_domain)")
)

func equalDNS(a, b string) bool { return strings.EqualFold(a, b) }

// CheckRealityDest accepts the retired --reality-dest flag only as "self".
func CheckRealityDest(dest string) error {
	if dest != "" && !strings.EqualFold(dest, realitySelf) {
		return errRealityNotSelf
	}
	return nil
}

// realityTargetProblem is nil when Stealth may open: shared mode, dest self
// and a running HTTPS proxy. Anything else leaves Stealth off while Fast,
// Rescue and the proxy run. It uses no network.
func (s Settings) realityTargetProblem() error {
	switch {
	case s.Mode != Shared:
		return nil
	case s.realityBlocked != "":
		return errors.New(s.realityBlocked)
	case s.RealityDest == "" || s.HTTPSProxyListener == nil:
		return errors.New("Stealth in shared mode borrows your own HTTPS proxy site, which is not enabled (pipe server proxy enable)")
	case s.RealityDest != realitySelf:
		return errors.New("the saved REALITY target " + s.RealityDest + " is no longer supported. Run: pipe server reality")
	}
	return nil
}

// SetRealityTarget is the migration for an older shared server: it moves a
// saved third-party REALITY target to self. Keys and devices are kept. Device
// links made earlier carry the old REALITY name and need rsni changed.
func SetRealityTarget(dir string) (bool, error) {
	unlock, err := lockDir(dir)
	if err != nil {
		return false, err
	}
	defer unlock()
	settings, err := ReadSettings(dir)
	if err != nil {
		return false, err
	}
	if settings.Mode != Shared {
		return false, errors.New("only a shared server has a REALITY target")
	}
	if settings.HTTPSProxyListener == nil {
		return false, errSelfNeedsProxy
	}
	if !settings.borrowProxySite() {
		return false, nil
	}
	settings.Ports.RealityOrigin = 0
	return true, writeJSON(dir, settingsFile, settings)
}

// borrowProxySite points REALITY at the HTTPS proxy site and reports a change.
func (s *Settings) borrowProxySite() bool {
	cfg := s.HTTPSProxyListener
	name, address := strings.ToLower(cfg.Domain), addrPort("127.0.0.1", cfg.Port)
	changed := s.RealityDest != realitySelf || s.RealitySNI != name || s.RealityAddress != address
	s.RealityDest, s.RealitySNI, s.RealityAddress = realitySelf, name, address
	return changed
}
