// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"testing"

	"github.com/sagernet/sing-box/log"
)

type recordWriter struct{ levels []log.Level }

func (w *recordWriter) WriteMessage(level log.Level, _ string) { w.levels = append(w.levels, level) }

// Slow tiers refuse QUIC on purpose, so browsers switch to TCP at once; that
// refusal is not an error worth showing.
func TestQUICRefusalIsNotAnError(t *testing.T) {
	for level, want := range map[string]int{"warn": 1, "debug": 2} {
		next := &recordWriter{}
		w := newLevelWriter(next, level)
		w.WriteMessage(log.LevelError, "[1 0ms] connection: listen packet connection using  using outbound/vmess[rescue]: "+errQUICDisabled.Error())
		w.WriteMessage(log.LevelError, "[2 0ms] connection: open connection: dial tcp: refused")
		if len(next.levels) != want || next.levels[len(next.levels)-1] != log.LevelError {
			t.Fatalf("level %s: got %v", level, next.levels)
		}
		if level == "debug" && next.levels[0] != log.LevelDebug {
			t.Fatalf("QUIC refusal logged as %v", next.levels[0])
		}
	}
}
