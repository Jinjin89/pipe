// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"strings"

	"github.com/sagernet/sing-box/log"
)

// expectedRefusals are Pipe's own deliberate, instant refusals. sing-box logs
// every failed connection as an error, so these are demoted to debug.
var expectedRefusals = []string{errQUICDisabled.Error()}

// levelWriter drops messages less severe than the configured level, because
// sing-box hands platform writers every level.
type levelWriter struct {
	next log.PlatformWriter
	max  log.Level
}

func newLevelWriter(next log.PlatformWriter, level string) log.PlatformWriter {
	max, err := log.ParseLevel(level)
	if err != nil {
		max = log.LevelWarn
	}
	return levelWriter{next: next, max: max}
}

func (w levelWriter) WriteMessage(level log.Level, message string) {
	for _, refusal := range expectedRefusals {
		if strings.HasSuffix(message, refusal) {
			level = log.LevelDebug
		}
	}
	if level <= w.max {
		w.next.WriteMessage(level, message)
	}
}
