// SPDX-License-Identifier: GPL-3.0-or-later

package version

import (
	"bytes"
	"io"
	"runtime"
	"strings"
)

// ReleaseIdentity is embedded once in every compiled Pipe executable so
// release signing and self-update can confirm the binary's OS, CPU and version.
var ReleaseIdentity = "\x00pipe-desktop-release-v1 " + runtime.GOOS + " " + runtime.GOARCH + " " + Version + "\x00"

// Use the same bytes for scanning and signing so the search does not embed
// a second marker in the executable.
func identityMarker() []byte {
	return []byte(ReleaseIdentity[:1+len("pipe-desktop-release-v1 ")])
}

// ParseIdentity finds the unique embedded release identity marker in data.
func ParseIdentity(data []byte) (goos, goarch, ver string, ok bool) {
	return ScanIdentity(bytes.NewReader(data))
}

// ScanIdentity streams r with a small fixed buffer and returns the unique
// embedded release identity marker, or ok=false if absent, malformed, or repeated.
func ScanIdentity(r io.Reader) (goos, goarch, ver string, ok bool) {
	const maxPayload = 128
	marker := identityMarker()
	keep := len(marker) + maxPayload
	buf := make([]byte, 64*1024+keep)
	carry := 0
	found := 0
	var payload string
	for {
		n, err := r.Read(buf[carry:])
		total := carry + n
		if total > 0 {
			window := buf[:total]
			scanLimit := total
			if err == nil {
				scanLimit = max(0, total-keep)
			}
			pos := 0
			for pos < scanLimit {
				idx := bytes.Index(window[pos:], marker)
				if idx < 0 {
					break
				}
				abs := pos + idx
				if abs >= scanLimit {
					break
				}
				found++
				if found > 1 {
					return "", "", "", false
				}
				start := abs + len(marker)
				endRel := bytes.IndexByte(window[start:min(total, start+maxPayload)], 0)
				if endRel <= 0 {
					return "", "", "", false
				}
				payload = string(window[start : start+endRel])
				pos = start
			}
			carry = copy(buf, window[scanLimit:])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", "", false
		}
	}
	if found != 1 {
		return "", "", "", false
	}
	fields := strings.Split(payload, " ")
	if len(fields) != 3 || fields[0] == "" || fields[1] == "" || fields[2] == "" {
		return "", "", "", false
	}
	return fields[0], fields[1], fields[2], true
}
