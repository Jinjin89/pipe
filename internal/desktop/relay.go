// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"net/http"
	"net/netip"
	"strings"

	"pipe/internal/config"
)

func sameServerHost(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	addr, addrErr := netip.ParseAddr(a)
	other, otherErr := netip.ParseAddr(b)
	return addrErr == nil && otherErr == nil && addr.Unmap() == other.Unmap()
}

func (s *Server) putProfileRelay(r *http.Request) (any, error) {
	var relay ProfileRelay
	if err := readJSON(r, &relay); err != nil {
		return nil, err
	}
	relay.Code = strings.TrimSpace(relay.Code)
	if relay.On && relay.Code == "" {
		return nil, bad("Enter a relay IP, name or code.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, err := s.storedName(r)
	if err != nil {
		return nil, err
	}
	profile, err := s.profiles.Load(name)
	if err != nil {
		return nil, errNoProfile
	}
	parsed, err := config.ParseRelay(relay.Code, profile.Host)
	if err != nil {
		return nil, bad(friendly(err))
	}
	relay.Code = parsed.String()
	data := s.store.Snapshot()
	var apply func() error
	if name == data.Active && relay.enabledCode() != data.relayFor(name, profile.Host).enabledCode() && running(s.active().Status()) {
		if s.getVia() == viaTUN {
			if err := s.needHelper(); err != nil {
				return nil, err
			}
		}
		apply = func() error { return s.applyLiveLocked(false) }
	}
	defer s.notify()
	if err := s.transact(func(d *appData) { d.setRelay(name, relay) }, apply); err != nil {
		return nil, err
	}
	return map[string]any{"relay": relay, "status": s.statusLocked()}, nil
}
