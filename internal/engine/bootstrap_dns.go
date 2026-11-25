// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

const BootstrapDNSType = "pipe-bootstrap-doh"

const (
	bootstrapUpstreamTimeout = 2 * time.Second
	bootstrapRefreshRetry    = 15 * time.Second
	bootstrapFamilyGrace     = 250 * time.Millisecond
)

type bootstrapDNSOptions struct {
	Hosts     []string `json:"hosts"`
	Upstreams []string `json:"upstreams"`
}

// bootstrapDNS uses the engine's direct DoH transports and keeps an isolated
// cache for the proxy endpoints. Reconnects can use a cached answer while its
// refresh is pending or an upstream is temporarily unavailable.
type bootstrapDNS struct {
	dns.TransportAdapter
	manager   adapter.DNSTransportManager
	hosts     map[string]bool
	upstreams []adapter.DNSTransport
	ctx       context.Context

	mu      sync.Mutex
	cache   map[mDNS.Question]*bootstrapRecord
	changed chan struct{}
	lookups sync.WaitGroup
}

type bootstrapRecord struct {
	response *mDNS.Msg
	refresh  time.Time
	pending  *bootstrapLookup
	err      error
}

type bootstrapLookup struct {
	done      chan struct{}
	response  *mDNS.Msg
	err       error
	completed time.Time
	// grace is when the cold family stops being waited for, set once for the
	// whole lookup when the other family has addresses (guarded by mu).
	grace time.Time
}

func newBootstrapDNS(ctx context.Context, _ log.ContextLogger, tag string, options bootstrapDNSOptions) (adapter.DNSTransport, error) {
	if len(options.Hosts) == 0 || len(options.Upstreams) == 0 {
		return nil, errors.New("proxy bootstrap needs endpoint names and DoH upstreams")
	}
	hosts := make(map[string]bool, len(options.Hosts))
	for _, host := range options.Hosts {
		hosts[mDNS.CanonicalName(host)] = true
	}
	return &bootstrapDNS{
		TransportAdapter: dns.NewTransportAdapter(BootstrapDNSType, tag, options.Upstreams),
		manager:          service.FromContext[adapter.DNSTransportManager](ctx),
		hosts:            hosts,
		cache:            make(map[mDNS.Question]*bootstrapRecord),
		changed:          make(chan struct{}),
	}, nil
}

func (b *bootstrapDNS) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	var upstreams []adapter.DNSTransport
	for _, tag := range b.Dependencies() {
		upstream, ok := b.manager.Transport(tag)
		if !ok || upstream.Type() != C.DNSTypeHTTPS || len(upstream.Dependencies()) != 0 {
			return fmt.Errorf("proxy bootstrap upstream %q must be a direct DoH transport", tag)
		}
		if referenced, ok := upstream.(adapter.Referrer); ok && len(referenced.References()) != 0 {
			return fmt.Errorf("proxy bootstrap upstream %q cannot use a detour", tag)
		}
		upstreams = append(upstreams, upstream)
	}
	b.mu.Lock()
	b.ctx, b.upstreams = scope.Context(), upstreams
	b.mu.Unlock()
	scope.Add(func() error {
		// The scope cancels ctx first. Synchronize with any lookup being queued.
		b.mu.Lock()
		b.mu.Unlock()
		b.lookups.Wait()
		return nil
	})
	return nil
}

func (b *bootstrapDNS) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	// The engine resets the upstream sockets separately. Refresh the addresses
	// on the new network without losing the previous successful answers.
	for _, record := range b.cache {
		record.refresh = time.Time{}
	}
}

func (b *bootstrapDNS) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if len(message.Question) != 1 {
		return nil, errors.New("proxy bootstrap expects one DNS question")
	}
	question := message.Question[0]
	question.Name = mDNS.CanonicalName(question.Name)
	if !b.hosts[question.Name] || question.Qclass != mDNS.ClassINET || (question.Qtype != mDNS.TypeA && question.Qtype != mDNS.TypeAAAA) {
		return nil, errors.New("proxy bootstrap only resolves configured endpoint addresses")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	if b.ctx == nil || b.ctx.Err() != nil {
		b.mu.Unlock()
		return nil, errors.New("proxy bootstrap resolver is stopped")
	}
	record := b.cache[question]
	if record == nil {
		record = &bootstrapRecord{}
		b.cache[question] = record
	}
	if record.pending == nil && !time.Now().Before(record.refresh) {
		pending := &bootstrapLookup{done: make(chan struct{})}
		record.pending = pending
		b.lookups.Add(1)
		go b.refresh(record, pending, message.Copy())
	}
	response, err, pending := record.response, record.err, record.pending
	other := question
	other.Qtype = mDNS.TypeA
	if question.Qtype == mDNS.TypeA {
		other.Qtype = mDNS.TypeAAAA
	}
	b.mu.Unlock()

	if response != nil {
		return bootstrapReply(response, message), nil
	}
	if pending == nil {
		return nil, err
	}
	for {
		select {
		case <-pending.done:
			return bootstrapLookupReply(pending, message)
		default:
		}

		b.mu.Lock()
		if peer := b.cache[other]; pending.completed.IsZero() && pending.grace.IsZero() && peer != nil && len(adapter.DNSResponseAddresses(peer.response)) > 0 {
			pending.grace = time.Now().Add(bootstrapFamilyGrace)
		}
		graceDeadline, changed := pending.grace, b.changed
		b.mu.Unlock()

		var timer *time.Timer
		var grace <-chan time.Time
		if !graceDeadline.IsZero() {
			delay := time.Until(graceDeadline)
			if delay <= 0 {
				select {
				case <-pending.done:
					return bootstrapLookupReply(pending, message)
				default:
					return new(mDNS.Msg).SetReply(message), nil
				}
			}
			timer = time.NewTimer(delay)
			grace = timer.C
		}
		select {
		case <-ctx.Done():
			stopBootstrapTimer(timer)
			return nil, ctx.Err()
		case <-pending.done:
			stopBootstrapTimer(timer)
			return bootstrapLookupReply(pending, message)
		case <-changed:
			stopBootstrapTimer(timer)
		case <-grace:
			stopBootstrapTimer(timer)
			select {
			case <-pending.done:
				return bootstrapLookupReply(pending, message)
			default:
				return new(mDNS.Msg).SetReply(message), nil
			}
		}
	}
}

// bootstrapLookupReply always uses an answer that arrived; a failure after the
// other family's grace is an empty answer, so the dial goes on with that family.
func bootstrapLookupReply(pending *bootstrapLookup, query *mDNS.Msg) (*mDNS.Msg, error) {
	if pending.err == nil {
		return bootstrapReply(pending.response, query), nil
	}
	if !pending.grace.IsZero() && pending.completed.After(pending.grace) {
		return new(mDNS.Msg).SetReply(query), nil
	}
	return nil, pending.err
}

func stopBootstrapTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func (b *bootstrapDNS) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { callback(b.Exchange(ctx, message)) }()
}

func (b *bootstrapDNS) refresh(record *bootstrapRecord, pending *bootstrapLookup, message *mDNS.Msg) {
	defer b.lookups.Done()
	response, err := b.exchangeUpstream(message)
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		record.response = response
		record.refresh = time.Now().Add(bootstrapTTL(response))
	} else if record.response != nil {
		record.refresh = time.Now().Add(bootstrapRefreshRetry)
	} else {
		record.refresh = time.Time{}
	}
	record.err, record.pending = err, nil
	pending.response, pending.err = response, err
	pending.completed = time.Now()
	close(pending.done)
	close(b.changed)
	b.changed = make(chan struct{})
}

func (b *bootstrapDNS) exchangeUpstream(message *mDNS.Msg) (*mDNS.Msg, error) {
	var failures []error
	for _, upstream := range b.upstreams {
		if err := b.ctx.Err(); err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(b.ctx, bootstrapUpstreamTimeout)
		response, err := upstream.Exchange(ctx, message)
		cancel()
		if err == nil && response != nil && !response.Truncated {
			if response.Rcode == mDNS.RcodeSuccess {
				return response, nil
			}
			err = dns.RcodeError(response.Rcode)
		}
		if err == nil {
			err = errors.New("unusable DNS response")
		}
		failures = append(failures, fmt.Errorf("%s: %w", upstream.Tag(), err))
	}
	return nil, fmt.Errorf("proxy endpoint DNS lookup failed: %w", errors.Join(failures...))
}

func bootstrapReply(response, query *mDNS.Msg) *mDNS.Msg {
	reply := response.Copy()
	reply.Id = query.Id
	return reply
}

func bootstrapTTL(response *mDNS.Msg) time.Duration {
	if len(response.Answer) == 0 {
		return 30 * time.Second
	}
	ttl := response.Answer[0].Header().Ttl
	for _, answer := range response.Answer[1:] {
		ttl = min(ttl, answer.Header().Ttl)
	}
	return max(time.Second, time.Duration(ttl)*time.Second)
}
