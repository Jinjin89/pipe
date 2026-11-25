// SPDX-License-Identifier: GPL-3.0-or-later

package logring

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/log"
)

func TestSinceAndWrap(t *testing.T) {
	r := New(3)
	for _, m := range []string{"a", "b", "c", "d"} {
		r.Add(Info, "pipe", m)
	}
	got, next := r.Since(0, 0)
	if len(got) != 3 || got[0].Message != "b" || got[2].Seq != 4 || next != 4 {
		t.Fatalf("got %+v next %d", got, next)
	}
	got, next = r.Since(3, 10)
	if len(got) != 1 || got[0].Message != "d" || next != 4 {
		t.Fatalf("got %+v next %d", got, next)
	}
	got, next = r.Since(4, 10)
	if len(got) != 0 || next != 4 {
		t.Fatalf("got %+v next %d", got, next)
	}
	got, next = r.Since(0, 2)
	if len(got) != 2 || got[0].Seq != 3 || next != 4 {
		t.Fatalf("limit must return the newest entries: %+v next %d", got, next)
	}
	r.Clear()
	got, next = r.Since(0, 0)
	if len(got) != 0 || next != 4 {
		t.Fatalf("after clear: %+v %d", got, next)
	}
	r.Add(Info, "pipe", "e")
	if got, _ = r.Since(4, 0); len(got) != 1 || got[0].Seq != 5 {
		t.Fatalf("seq must keep growing: %+v", got)
	}
}

func TestSetLevel(t *testing.T) {
	r := New(10)
	r.SetLevel("warn")
	r.Add(Info, "pipe", "no")
	r.Add(Debug, "pipe", "no")
	r.Add(Warn, "pipe", "yes")
	r.Add(Error, "pipe", "yes")
	if got, _ := r.Since(0, 0); len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestNoiseDemoted(t *testing.T) {
	for _, m := range []string{
		"connection: connection upload closed: stream 112 canceled by remote with error code 0",
		"read tcp 1.2.3.4:1: use of closed network connection",
		"dial: context canceled",
		"connection: read: EOF",
		"connection upload closed: read: connection reset by peer",
		"connection download closed: i/o timeout",
	} {
		r := New(5)
		r.Add(Error, "core", m)
		got, _ := r.Since(0, 0)
		if len(got) != 1 || got[0].Level != Debug {
			t.Errorf("%q not demoted: %+v", m, got)
		}
	}
	r := New(5)
	r.Add(Error, "core", "dial tcp: connection refused")
	r.Add(Error, "core", "connection upload closed: something else")
	got, _ := r.Since(0, 0)
	if got[0].Level != Error || got[1].Level != Error {
		t.Fatalf("real errors demoted: %+v", got)
	}
}

func TestANSICapAndPrefix(t *testing.T) {
	r := New(5)
	w := r.Writer()
	w.WriteMessage(log.LevelError, "\x1b[31mERROR\x1b[0m[0015] [\x1b[38;5;3m12\x1b[0m 3ms] boom")
	w.WriteMessage(log.LevelInfo, "INFO[0001] hello")
	r.Add(Info, "pipe", strings.Repeat("x", 5000))
	got, _ := r.Since(0, 0)
	if got[0].Message != "[12 3ms] boom" || got[0].Level != Error || got[0].Source != "core" {
		t.Fatalf("%+v", got[0])
	}
	if got[1].Message != "hello" || got[1].Level != Info {
		t.Fatalf("%+v", got[1])
	}
	if len(got[2].Message) != MaxMessage {
		t.Fatalf("len %d", len(got[2].Message))
	}
}

func TestConcurrent(t *testing.T) {
	r := New(50)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				r.Add(Info, "pipe", "m")
				r.Since(0, 10)
			}
		}()
	}
	wg.Wait()
	if _, next := r.Since(0, 0); next != 1600 {
		t.Fatalf("next %d", next)
	}
}

func TestPrinter(t *testing.T) {
	var buf bytes.Buffer
	p := NewPrinter(&buf, "warn")
	p.WriteMessage(log.LevelError, "ERROR[0015] connection: connection upload closed: stream 112 canceled by remote with error code 0")
	p.WriteMessage(log.LevelInfo, "INFO[0001] inbound connection")
	p.WriteMessage(log.LevelError, "ERROR[0002] dial failed")
	if buf.String() != "error: dial failed\n" {
		t.Fatalf("%q", buf.String())
	}
	buf.Reset()
	p = NewPrinter(&buf, "debug")
	p.WriteMessage(log.LevelError, "ERROR[0015] x: EOF")
	if buf.String() != "debug: x: EOF\n" {
		t.Fatalf("%q", buf.String())
	}
}
