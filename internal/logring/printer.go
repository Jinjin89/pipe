// SPDX-License-Identifier: GPL-3.0-or-later

package logring

import (
	"fmt"
	"io"
	"sync"

	"github.com/sagernet/sing-box/log"
)

// Printer writes filtered engine logs as plain lines, for the CLI.
type Printer struct {
	mu  sync.Mutex
	out io.Writer
	min int
}

// NewPrinter prints messages at minLevel or more severe, after the noise filter.
func NewPrinter(out io.Writer, minLevel string) *Printer {
	return &Printer{out: out, min: rank(normalize(minLevel))}
}

// WriteMessage implements log.PlatformWriter.
func (p *Printer) WriteMessage(level log.Level, message string) {
	l, msg := Classify(levelName(level), stripPrefix(message))
	if rank(l) > p.min || msg == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.out, "%s: %s\n", l, msg)
}
