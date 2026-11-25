// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
)

func TestListenerReplacementRetriesOnlyAddressInUse(t *testing.T) {
	for _, test := range []struct {
		name  string
		bind  error
		retry bool
	}{
		{"busy", fmt.Errorf("bind: %w", syscall.EADDRINUSE), true},
		{"permission", syscall.EPERM, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			logger := log.NewNOPFactory().NewLogger("reload-test")
			parent := adapter.NewScope(t.Context(), logger)
			defer parent.Close()
			initial := &testReloadInbound{}
			first := &testReloadInbound{bindErr: test.bind}
			success := &testReloadInbound{}
			created := 0
			in := reloadableInbound{
				Adapter: inbound.NewAdapter("test", "proxy"), logger: logger, current: initial,
				create: func(options any) (adapter.Inbound, error) {
					if options != "credentials" {
						t.Fatal("retry lost replacement options")
					}
					created++
					return success, nil
				},
			}
			for _, stage := range adapter.ListStartStages {
				if err := in.Start(stage, parent); err != nil {
					t.Fatal(err)
				}
			}
			err := in.replace(first, "credentials")
			if test.retry {
				if err != nil || created != 1 || in.current != success {
					t.Fatalf("transient bind error did not install a new inbound: %v", err)
				}
			} else if !errors.Is(err, test.bind) || created != 0 {
				t.Fatalf("unexpected retry for permanent error: %v", err)
			}
			if initial.closed != 1 || first.closed != 1 {
				t.Fatal("old or partially started listener was not closed")
			}
		})
	}
}

type testReloadInbound struct {
	inbound.Adapter
	bindErr error
	closed  int
}

func (in *testReloadInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateStart {
		scope.Add(func() error { in.closed++; return nil })
		return in.bindErr
	}
	return nil
}
