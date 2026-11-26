// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !android

package clientctl

import (
	"errors"
	"slices"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-tun"
)

func prepareTUNGuardRoutes(opts *tun.Options) error {
	rules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	// sing-tun uses eleven priorities for installation and cleanup. Select a
	// free range ahead of the live tunnel, including after an orphaned rule.
	const window = 16
	for first := tun.DefaultIPRoute2RuleIndex - window; first >= tun.DefaultIPRoute2RuleIndex-256; first -= window {
		if !slices.ContainsFunc(rules, func(rule netlink.Rule) bool {
			return rule.Priority >= first && rule.Priority <= first+10
		}) {
			opts.IPRoute2RuleIndex = first
			return nil
		}
	}
	return errors.New("no routing rule priorities are available for the TUN guard")
}
