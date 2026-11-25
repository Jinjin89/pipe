// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !android

package relay

import (
	"fmt"
	"strings"
)

func (s state) forwarding() []string {
	var keys []string
	if len(s.IPv4) > 0 {
		keys = append(keys, ipv4Forward)
	}
	if len(s.IPv6) > 0 {
		keys = append(keys, ipv6Forward)
	}
	return keys
}

func sysctlText(settings []sysctlSetting, previous map[string]string) string {
	var out strings.Builder
	out.WriteString(ownedHeader)
	for _, setting := range settings {
		if value := previous[setting.key]; validPreviousSysctl(setting.key, value) {
			fmt.Fprintf(&out, "# previous %s=%s\n", setting.key, value)
		}
		fmt.Fprintf(&out, "%s = %s\n", setting.key, setting.value)
	}
	return out.String()
}

func priorSysctls(text string) map[string]string {
	previous := make(map[string]string)
	for line := range strings.SplitSeq(text, "\n") {
		if value, ok := strings.CutPrefix(line, "# previous "); ok {
			key, state, found := strings.Cut(value, "=")
			if found && validPreviousSysctl(key, state) {
				previous[key] = state
			}
		}
	}
	return previous
}

func unitText(executable, path string) string {
	args := []string{unitArgument(executable), "relay", "apply"}
	if path != DefaultStatePath {
		args = append(args, "--state", unitArgument(path))
	}
	return ownedHeader + fmt.Sprintf(`[Unit]
Description=Pipe relay
DefaultDependencies=no
Wants=network-pre.target
After=nftables.service local-fs.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
ExecStart=%s

[Install]
WantedBy=multi-user.target
`, strings.Join(args, " "))
}

func unitArgument(value string) string {
	escape := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$", "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return `"` + escape.Replace(value) + `"`
}
