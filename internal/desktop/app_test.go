// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"errors"
	"strings"
	"testing"

	"pipe/internal/clientctl"
	"pipe/internal/helper"
)

func TestNativeQuitWaitsForProxyRestoration(t *testing.T) {
	e, _ := newTUNEnv(t, helper.StateOK)
	if err := e.srv.Connect(); err != nil {
		t.Fatal(err)
	}
	a := &App{opts: AppOptions{Config: e.srv.cfg}, srv: e.srv, quit: make(chan struct{})}
	e.proxy.restoreErr = errors.New("fixture restore failure")
	if a.Quit() {
		t.Fatal("native Quit allowed termination after restoration failed")
	}
	select {
	case <-a.quit:
		t.Fatal("native Quit signaled process exit while OS proxy still pointed at Pipe")
	default:
	}
	if e.ctl.Status().State != clientctl.StateOn || e.srv.getVia() != viaProxy || !e.srv.cfg.Proxy.Armed() {
		t.Fatal("native Quit lost the local listener or recovery snapshot")
	}
	entries, _ := e.srv.cfg.Logs.Since(0, 20)
	if len(entries) == 0 || !strings.Contains(entries[len(entries)-1].Message, "fixture restore failure") {
		t.Fatal("native Quit did not log the restore failure")
	}
	e.proxy.restoreErr = nil
	if !a.Quit() {
		t.Fatal("native Quit refused termination after restoration succeeded")
	}
	select {
	case <-a.quit:
	default:
		t.Fatal("native Quit did not signal exit after restoring the proxy")
	}
	if e.ctl.Status().State != clientctl.StateOff || e.proxy.state != "orig" || e.srv.cfg.Proxy.Armed() {
		t.Fatal("native Quit failed to restore proxy settings and stop the listener")
	}
}
