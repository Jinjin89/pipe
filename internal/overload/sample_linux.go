// SPDX-License-Identifier: GPL-3.0-or-later
//go:build linux

package overload

import (
	"context"
	"io"
	"iter"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const cgroupRoot = "/sys/fs/cgroup"

func sampleSystem(ctx context.Context) Snapshot {
	s := sampleGoMemory()
	sampleCgroups(&s, cgroupRoot, processCgroup())
	if len(s.Cgroups) == 0 {
		raw, _ := os.ReadFile("/proc/meminfo")
		s.HostMemTotalBytes, s.HostMemAvailableBytes = meminfo(string(raw))
	}
	sampleFDs(&s, ctx, softFDLimit(), os.Open, func(fd uint64) error {
		_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		return err
	})
	return s
}

func processCgroup() string {
	raw, _ := os.ReadFile("/proc/self/cgroup")
	return unifiedCgroup(string(raw))
}

func unifiedCgroup(data string) string {
	for line := range strings.SplitSeq(data, "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok && filepath.IsAbs(path) {
			return filepath.Clean(path)
		}
	}
	return ""
}

func cgroupLimits(root, group string) iter.Seq2[string, uint64] {
	root = filepath.Clean(root)
	return func(yield func(string, uint64) bool) {
		if !filepath.IsAbs(group) {
			return
		}
		for path := filepath.Join(root, filepath.Clean(group)); ; path = filepath.Dir(path) {
			limit := readCgroupBytes(path, "memory.max")
			if high := readCgroupBytes(path, "memory.high"); high != 0 && (limit == 0 || high < limit) {
				limit = high
			}
			if limit != 0 && !yield(path, limit) || path == root {
				return
			}
		}
	}
}

func minCgroupLimit(root, group string) (minimum uint64) {
	for _, limit := range cgroupLimits(root, group) {
		if minimum == 0 || limit < minimum {
			minimum = limit
		}
	}
	return minimum
}

func sampleCgroups(s *Snapshot, root, group string) {
	var mostUsed CgroupMemory
	for path, limit := range cgroupLimits(root, group) {
		raw, _ := os.ReadFile(filepath.Join(path, "memory.events"))
		entry := CgroupMemory{
			Path:          path,
			CurrentBytes:  readCgroupBytes(path, "memory.current"),
			LimitBytes:    limit,
			ReclaimEvents: memoryEvents(string(raw)),
		}
		s.Cgroups = append(s.Cgroups, entry)
		if mostUsed.LimitBytes == 0 || higherUtilization(entry, mostUsed) {
			mostUsed = entry
		}
	}
	s.CgroupCurrentBytes = mostUsed.CurrentBytes
	s.CgroupLimitBytes = mostUsed.LimitBytes
	s.CgroupReclaimEvents = mostUsed.ReclaimEvents
}

func higherUtilization(a, b CgroupMemory) bool {
	// Compare the cross-products without overflowing or rounding a ratio.
	aHi, aLo := bits.Mul64(a.CurrentBytes, b.LimitBytes)
	bHi, bLo := bits.Mul64(b.CurrentBytes, a.LimitBytes)
	if aHi != bHi {
		return aHi > bHi
	}
	if aLo != bLo {
		return aLo > bLo
	}
	return a.LimitBytes < b.LimitBytes
}

func readCgroupBytes(dir, name string) uint64 {
	raw, _ := os.ReadFile(filepath.Join(dir, name))
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func memoryEvents(data string) (events uint64) {
	for line := range strings.SplitSeq(data, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case "high", "max", "oom", "oom_kill":
			if n, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				events += min(n, math.MaxUint64-events)
			}
		}
	}
	return events
}

func meminfo(data string) (total, available uint64) {
	foundAvailable := false
	for line := range strings.SplitSeq(data, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[2] != "kB" {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 54)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total = n << 10
		case "MemAvailable:":
			available, foundAvailable = n<<10, true
		}
	}
	if !foundAvailable {
		// Preserve the distinction between a missing value and real zero headroom.
		return 0, 0
	}
	return total, available
}

func softFDLimit() uint64 {
	var lim unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &lim) != nil || lim.Cur == unix.RLIM_INFINITY {
		return 0
	}
	return lim.Cur
}

func sampleFDs(s *Snapshot, ctx context.Context, limit uint64, open func(string) (*os.File, error), fdOpenFn func(uint64) error) {
	if limit == 0 {
		if ctx.Err() == nil {
			s.FDProbeOK, s.FDExhausted = checkSingleFD()
		}
		return
	}
	count, err := countOpenFDs(ctx, open)
	if err == nil {
		s.OpenFDs, s.MaxFDs = count, limit
		return
	}
	if isFDExhausted(err) {
		s.MaxFDs, s.FDExhausted = limit, true
		return
	}

	reserve := fdFlowReserve(limit)
	targetFree := limit // Scan every slot at small limits.
	if limit > 4096 {
		targetFree = reserve + 64
	}
	openCount, freeCount, err := scanFDTable(ctx, limit, targetFree, fdOpenFn)
	if err != nil || ctx.Err() != nil {
		return
	}
	_, exhausted := checkSingleFD()
	switch {
	case exhausted:
		s.MaxFDs, s.FDExhausted = limit, true
	case openCount+freeCount == limit:
		s.OpenFDs, s.MaxFDs = openCount, limit
	default:
		s.ProbeFreeFDs, s.ProbeReserve, s.ProbeLimit = freeCount, reserve, limit
	}
}

func scanFDTable(ctx context.Context, limit, targetFree uint64, fdOpenFn func(uint64) error) (open, free uint64, err error) {
	for fd := uint64(0); fd < limit; fd++ {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		switch err := fdOpenFn(fd); err {
		case nil:
			open++
		case unix.EBADF:
			free++
			if free == targetFree {
				return open, free, nil
			}
		default:
			return 0, 0, err
		}
	}
	return open, free, nil
}

func countOpenFDs(ctx context.Context, open func(string) (*os.File, error)) (uint64, error) {
	f, err := open("/proc/self/fd")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var count uint64
	for ctx.Err() == nil {
		names, err := f.Readdirnames(256)
		count += uint64(len(names))
		if err == io.EOF {
			return count - min(count, 1), nil
		}
		if err != nil {
			return 0, err
		}
	}
	return 0, ctx.Err()
}

var setMemoryLimit = sync.OnceValues(func() (int64, bool) {
	limit := minCgroupLimit(cgroupRoot, processCgroup())
	if limit < 64<<20 {
		return 0, false
	}
	derived := int64(min(math.MaxInt64-1, max(64<<20, percent(limit, 70))))
	debug.SetMemoryLimit(derived)
	return derived, true
})

func ConfigureMemoryLimit() (int64, bool) {
	if os.Getenv("GOMEMLIMIT") != "" {
		return 0, false
	}
	return setMemoryLimit()
}
