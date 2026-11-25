// SPDX-License-Identifier: GPL-3.0-or-later

package relay

import (
	"encoding/json"
	"fmt"
	"strings"
)

type nftCounter struct {
	Name    string `json:"name"`
	Family  string `json:"family"`
	Table   string `json:"table"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

func readCounters(output string) (map[string]nftCounter, error) {
	var ruleset struct {
		Entries []struct {
			Counter nftCounter `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(output), &ruleset); err != nil {
		return nil, fmt.Errorf("read relay counters: %w", err)
	}
	counters := make(map[string]nftCounter)
	for _, entry := range ruleset.Entries {
		c := entry.Counter
		if c.Family == "inet" && c.Table == tableName {
			counters[c.Name] = c
		}
	}
	return counters, nil
}

func statusText(s state, active bool, counters map[string]nftCounter) string {
	if len(s.routes) == 0 {
		if active {
			return "Pipe relay has a kernel table but no route state.\n"
		}
		return "Pipe relay is not installed.\n"
	}
	var out strings.Builder
	if !active {
		out.WriteString("Pipe relay has saved routes but no kernel table. Run pipe relay apply.\n")
	}
	for i, r := range s.routes {
		fmt.Fprintf(&out, "%s %s", r.targets(), r.code())
		for _, tier := range []struct {
			name string
			used bool
		}{{"tcp", r.RelayTCP != 0}, {"udp", r.RelayUDP.valid()}} {
			if !active || !tier.used {
				continue
			}
			if c, ok := counters[counterName(i, tier.name)]; ok {
				fmt.Fprintf(&out, " %s %d packets %d bytes", strings.ToUpper(tier.name), c.Packets, c.Bytes)
			} else {
				fmt.Fprintf(&out, " %s counter unavailable", strings.ToUpper(tier.name))
			}
		}
		out.WriteByte('\n')
	}
	return out.String()
}
