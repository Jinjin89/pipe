// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
)

func registerInbound[T any](registry *inbound.Registry, reloads map[string]*reloadableInbound, sessions *deviceSessions, kind string, create inbound.ConstructorFunc[T]) {
	if sessions == nil {
		inbound.Register(registry, kind, create)
		return
	}
	inbound.Register(registry, kind, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options T) (adapter.Inbound, error) {
		router = sessions.wrapRouter(router)
		initial, err := create(ctx, router, logger, tag, options)
		if err != nil {
			return nil, err
		}
		item := &reloadableInbound{
			Adapter: inbound.NewAdapter(kind, tag), logger: logger, current: initial, options: &options,
			create: func(options any) (adapter.Inbound, error) {
				return create(ctx, router, logger, tag, *options.(*T))
			},
		}
		reloads[tag] = item
		return item, nil
	})
}

// A separate listener scope lets credential changes keep the router and its
// established TCP flows alive. A QUIC listener owns its transport sessions.
type reloadableInbound struct {
	inbound.Adapter
	logger  log.ContextLogger
	mu      sync.Mutex
	parent  *adapter.Scope
	scope   *adapter.Scope
	current adapter.Inbound
	options any
	create  func(any) (adapter.Inbound, error)
}

func (in *reloadableInbound) Start(stage adapter.StartStage, parent *adapter.Scope) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if stage == adapter.StartStateInitialize {
		in.parent = parent
		if in.current != nil {
			in.scope = adapter.NewScope(parent.Context(), in.logger)
		}
		parent.Add(func() error {
			in.mu.Lock()
			defer in.mu.Unlock()
			return in.stop()
		})
	}
	if in.scope == nil {
		return nil
	}
	return in.scope.Start(in.Tag(), in.current, stage)
}

func (in *reloadableInbound) InterfaceUpdated(ctx context.Context) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if listener, ok := in.current.(adapter.InterfaceUpdateListener); ok {
		listener.InterfaceUpdated(ctx)
	}
}

func (in *reloadableInbound) replace(next adapter.Inbound, options any) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.options = options
	if in.current == nil {
		return nil
	}
	if err := in.stop(); err != nil {
		return err
	}
	return in.start(next)
}

func (in *reloadableInbound) setEnabled(enabled bool) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if enabled == (in.current != nil) {
		return nil
	}
	if !enabled {
		return in.stop()
	}
	next, err := in.create(in.options)
	if err != nil {
		return err
	}
	if in.parent == nil {
		in.current = next
		return nil
	}
	return in.start(next)
}

func (in *reloadableInbound) stop() error {
	in.current = nil
	scope := in.scope
	in.scope = nil
	if scope == nil {
		return nil
	}
	return scope.Close()
}

func (in *reloadableInbound) start(next adapter.Inbound) error {
	ctx := in.parent.Context()
	for delay := 25 * time.Millisecond; ; delay *= 2 {
		scope := adapter.NewScope(ctx, in.logger)
		err := in.startReplacement(scope, next)
		if err == nil {
			in.current, in.scope = next, scope
			return nil
		}
		if closeErr := scope.Close(); closeErr != nil {
			return errors.Join(err, closeErr)
		}
		if !addressInUse(err) || delay > 200*time.Millisecond {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		// A failed Start may have set up part of the previous component.
		next, err = in.create(in.options)
		if err != nil {
			return err
		}
	}
}

// SetInboundEnabled opens or closes one server inbound within its existing router.
func (i *Instance) SetInboundEnabled(tag string, enabled bool) error {
	in := i.reloads[tag]
	if in == nil {
		return fmt.Errorf("unknown server listener %q", tag)
	}
	return in.setEnabled(enabled)
}

func (in *reloadableInbound) startReplacement(scope *adapter.Scope, next adapter.Inbound) error {
	for _, stage := range adapter.ListStartStages {
		if err := scope.Start(in.Tag(), next, stage); err != nil {
			return err
		}
	}
	return nil
}

func addressInUse(err error) bool {
	const winsockAddressInUse = syscall.Errno(10048)
	return errors.Is(err, syscall.EADDRINUSE) || runtime.GOOS == "windows" && errors.Is(err, winsockAddressInUse)
}

// ReloadInbounds replaces server listeners in their existing router. On an
// error the caller must close the instance to avoid a partial credential set.
func (i *Instance) ReloadInbounds(config Object, deviceIDs []string) error {
	decoded, err := i.decode(config)
	if err != nil {
		return err
	}
	if i.sessions == nil {
		return fmt.Errorf("credential reload requires a server engine")
	}
	type replacement struct {
		previous *reloadableInbound
		next     adapter.Inbound
		options  any
	}
	var replacements []replacement
	for _, options := range decoded.Inbounds {
		if options.Tag == RealityFrontTag && options.Type == "direct" {
			continue // The raw TLS listener has no credentials to replace.
		}
		active := i.reloads[options.Tag]
		if active == nil || active.Type() != options.Type {
			return fmt.Errorf("unknown listener %q for reload", options.Tag)
		}
		next, err := active.create(options.Options)
		if err != nil {
			return fmt.Errorf("prepare listener %s: %w", options.Tag, err)
		}
		replacements = append(replacements, replacement{active, next, options.Options})
	}
	if len(replacements) != len(i.reloads) {
		return fmt.Errorf("invalid server listener count for reload")
	}
	i.sessions.allow(deviceIDs)
	for _, replacement := range replacements {
		if err := replacement.previous.replace(replacement.next, replacement.options); err != nil {
			return fmt.Errorf("replace listener %s: %w", replacement.previous.Tag(), err)
		}
	}
	return nil
}
