// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !linux

package overload

import "context"

func sampleSystem(ctx context.Context) Snapshot {
	s := sampleGoMemory()
	if ctx.Err() == nil {
		s.FDProbeOK, s.FDExhausted = checkSingleFD()
	}
	return s
}

func ConfigureMemoryLimit() (int64, bool) { return 0, false }
