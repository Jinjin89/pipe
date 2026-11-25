// SPDX-License-Identifier: GPL-3.0-or-later

// Package logring keeps a bounded, memory-only log shared by the engine and
// the front ends. Nothing here is ever written to disk.
package logring

import (
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/sagernet/sing-box/log"
)

const (
	DefaultCapacity = 1000
	MaxMessage      = 2048
)

// Level names, ordered from most to least severe.
const (
	Error = "error"
	Warn  = "warn"
	Info  = "info"
	Debug = "debug"
)

// Entry is one log line.
type Entry struct {
	Seq     uint64 `json:"seq"`
	Time    string `json:"time"`
	Level   string `json:"level"`
	Source  string `json:"source"`
	Message string `json:"message"`
}

// Ring is a fixed-size log buffer. It is safe for concurrent use.
type Ring struct {
	mu      sync.Mutex
	entries []Entry // circular buffer
	start   int
	count   int
	seq     uint64
	min     int
	now     func() time.Time
}

// New returns a ring holding the last capacity entries (1000 if capacity <= 0).
// The default minimum level is debug, so every entry is kept.
func New(capacity int) *Ring {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Ring{entries: make([]Entry, capacity), min: rank(Debug), now: time.Now}
}

func rank(level string) int {
	switch level {
	case Error:
		return 0
	case Warn:
		return 1
	case Info:
		return 2
	default:
		return 3
	}
}

func normalize(level string) string {
	switch strings.ToLower(level) {
	case "error", "fatal", "panic":
		return Error
	case "warn", "warning":
		return Warn
	case "info":
		return Info
	default:
		return Debug
	}
}

// SetLevel drops entries below minLevel on Add ("error", "warn", "info", "debug").
func (r *Ring) SetLevel(minLevel string) {
	r.mu.Lock()
	r.min = rank(normalize(minLevel))
	r.mu.Unlock()
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// sing-box prefixes platform lines with "LEVEL[0012] ".
var boxPrefix = regexp.MustCompile(`^(TRACE|DEBUG|INFO|WARN|ERROR|FATAL|PANIC)(\[\d+\])? `)

var noisy = []string{
	"canceled by remote with error code 0",
	"use of closed network connection",
	"context canceled",
}

// Demote reports whether a message is routine connection teardown noise that
// belongs at debug level.
func Demote(msg string) bool {
	for _, n := range noisy {
		if strings.Contains(msg, n) {
			return true
		}
	}
	if strings.HasSuffix(strings.TrimSpace(msg), ": EOF") {
		return true
	}
	closing := strings.Contains(msg, "connection upload closed") || strings.Contains(msg, "connection download closed")
	if closing && (strings.Contains(msg, "connection reset by peer") || strings.Contains(msg, "i/o timeout")) {
		return true
	}
	return false
}

// Clean strips ANSI sequences and control characters and caps the length.
func Clean(msg string) string {
	msg = ansi.ReplaceAllString(msg, "")
	msg = strings.TrimSpace(strings.Map(func(c rune) rune {
		if c == '\n' || c == '\r' || c == '\t' {
			return ' '
		}
		if c < 0x20 || c == 0x7f {
			return -1
		}
		return c
	}, msg))
	if len(msg) > MaxMessage {
		msg = msg[:MaxMessage]
		for !utf8.ValidString(msg) {
			msg = msg[:len(msg)-1]
		}
	}
	return msg
}

// Classify applies the cleaning and the noise filter and returns the final
// level and message. It is shared with the CLI printer.
func Classify(level, msg string) (string, string) {
	msg = Clean(msg)
	level = normalize(level)
	if level != Debug && Demote(msg) {
		level = Debug
	}
	return level, msg
}

// Add appends an entry unless it is below the ring's level.
func (r *Ring) Add(level, source, msg string) {
	level, msg = Classify(level, msg)
	r.mu.Lock()
	defer r.mu.Unlock()
	if rank(level) > r.min {
		return
	}
	r.seq++
	e := Entry{Seq: r.seq, Time: r.now().UTC().Format("2006-01-02T15:04:05.000Z07:00"), Level: level, Source: source, Message: msg}
	n := len(r.entries)
	if r.count < n {
		r.entries[(r.start+r.count)%n] = e
		r.count++
		return
	}
	r.entries[r.start] = e
	r.start = (r.start + 1) % n
}

// Since returns entries with Seq > after, oldest first, and the cursor to pass
// next time. With a limit, it returns the newest limit entries when more are
// pending (limit <= 0 means all).
func (r *Ring) Since(after uint64, limit int) ([]Entry, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Entry{}
	n := len(r.entries)
	for i := 0; i < r.count; i++ {
		if e := r.entries[(r.start+i)%n]; e.Seq > after {
			out = append(out, e)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	next := after
	if after > r.seq {
		next = r.seq
	}
	if len(out) > 0 {
		next = out[len(out)-1].Seq
	} else if r.count == 0 || after < r.seq {
		next = r.seq
	}
	return out, next
}

// Clear drops every entry. Sequence numbers keep increasing.
func (r *Ring) Clear() {
	r.mu.Lock()
	r.start, r.count = 0, 0
	r.mu.Unlock()
}

// Writer adapts the ring to sing-box's platform log interface.
func (r *Ring) Writer() log.PlatformWriter { return writer{r} }

type writer struct{ r *Ring }

func (w writer) WriteMessage(level log.Level, message string) {
	w.r.Add(levelName(level), "core", stripPrefix(message))
}

func levelName(level log.Level) string {
	switch level {
	case log.LevelPanic, log.LevelFatal, log.LevelError:
		return Error
	case log.LevelWarn:
		return Warn
	case log.LevelInfo:
		return Info
	default:
		return Debug
	}
}

func stripPrefix(message string) string {
	return boxPrefix.ReplaceAllString(ansi.ReplaceAllString(message, ""), "")
}
