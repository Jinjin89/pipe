// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

const bootstrapTestHost = "origin.example."

func TestBootstrapStartsOnlyWithDirectDoH(t *testing.T) {
	for _, detour := range []string{"", "proxy"} {
		resolver, err := newBootstrapDNS(t.Context(), nil, "bootstrap", bootstrapDNSOptions{
			Hosts: []string{bootstrapTestHost}, Upstreams: []string{"primary", "backup"},
		})
		if err != nil {
			t.Fatal(err)
		}
		bootstrap := resolver.(*bootstrapDNS)
		bootstrap.manager = testBootstrapManager{transports: map[string]adapter.DNSTransport{
			"primary": &testDoHTransport{tag: "primary"},
			"backup":  &testDoHTransport{tag: "backup", detour: detour},
		}}
		scope := adapter.NewScope(t.Context(), log.NewNOPFactory().NewLogger("bootstrap-test"))
		err = bootstrap.Start(adapter.StartStateStart, scope)
		if closeErr := scope.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if (err != nil) != (detour != "") {
			t.Fatalf("unexpected bootstrap startup for detour %q: %v", detour, err)
		}
	}
}

func TestBootstrapDoHFallsBackOnResolverFailure(t *testing.T) {
	for _, rcode := range []int{mDNS.RcodeServerFailure, mDNS.RcodeNameError} {
		t.Run(mDNS.RcodeToString[rcode], func(t *testing.T) {
			var calls []string
			resolver := testBootstrapDNS(t,
				&testDoHTransport{tag: "primary", exchange: func(_ context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
					calls = append(calls, "primary")
					return new(mDNS.Msg).SetRcode(q, rcode), nil
				}},
				&testDoHTransport{tag: "backup", exchange: func(_ context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
					calls = append(calls, "backup")
					return bootstrapAddressReply(q, "203.0.113.7"), nil
				}},
			)
			query := new(mDNS.Msg).SetQuestion("Origin.Example.", mDNS.TypeA)
			response, err := resolver.Exchange(t.Context(), query)
			checkBootstrapAddress(t, response, err, "203.0.113.7")
			if response.Id != query.Id || !reflect.DeepEqual(calls, []string{"primary", "backup"}) {
				t.Fatalf("lookup did not use primary before backup: %v", calls)
			}
			if _, err := resolver.Exchange(t.Context(), new(mDNS.Msg).SetQuestion("unlisted.example.", mDNS.TypeA)); err == nil {
				t.Fatal("bootstrap answered a non-endpoint DNS question")
			}
		})
	}
}

func TestBootstrapKeepsLastGoodAddressWhileRefreshing(t *testing.T) {
	var calls atomic.Int32
	refreshStarted, refreshRelease := make(chan struct{}), make(chan struct{})
	resolver := testBootstrapDNS(t,
		&testDoHTransport{tag: "primary", exchange: func(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
			switch calls.Add(1) {
			case 1:
				return bootstrapAddressReply(q, "203.0.113.7"), nil
			case 2:
				close(refreshStarted)
				select {
				case <-refreshRelease:
					return new(mDNS.Msg).SetRcode(q, mDNS.RcodeNameError), nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			default:
				return bootstrapAddressReply(q, "203.0.113.8"), nil
			}
		}},
		&testDoHTransport{tag: "backup", exchange: func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
			return nil, errors.New("backup temporarily unavailable")
		}},
	)
	query := new(mDNS.Msg).SetQuestion(bootstrapTestHost, mDNS.TypeA)
	response, err := resolver.Exchange(t.Context(), query)
	checkBootstrapAddress(t, response, err, "203.0.113.7")

	resolver.Reset()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	response, err = resolver.Exchange(ctx, query)
	checkBootstrapAddress(t, response, err, "203.0.113.7")
	select {
	case <-refreshStarted:
	case <-ctx.Done():
		t.Fatal("stale answer did not schedule a refresh")
	}
	close(refreshRelease)
	resolver.lookups.Wait()
	response, err = resolver.Exchange(t.Context(), query)
	checkBootstrapAddress(t, response, err, "203.0.113.7")
	if calls.Load() != 2 {
		t.Fatal("a failed refresh should back off while serving the cached address")
	}

	resolver.Reset()
	if _, err := resolver.Exchange(t.Context(), query); err != nil {
		t.Fatal(err)
	}
	resolver.lookups.Wait()
	response, err = resolver.Exchange(t.Context(), query)
	checkBootstrapAddress(t, response, err, "203.0.113.8")
}

func TestBootstrapColdAWaitsForItsAnswerWithinPeerGrace(t *testing.T) {
	aStarted, aRelease := make(chan struct{}), make(chan struct{})
	resolver := testBootstrapDNS(t, &testDoHTransport{tag: "primary", exchange: func(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
		if q.Question[0].Qtype == mDNS.TypeA {
			close(aStarted)
			select {
			case <-aRelease:
				return bootstrapAddressReply(q, "203.0.113.7"), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return bootstrapAddressReply(q, "2001:db8::7"), nil
	}})
	type result struct {
		response *mDNS.Msg
		err      error
	}
	aResult := make(chan result, 1)
	go func() {
		response, err := resolver.Exchange(t.Context(), new(mDNS.Msg).SetQuestion(bootstrapTestHost, mDNS.TypeA))
		aResult <- result{response, err}
	}()
	select {
	case <-aStarted:
	case <-time.After(time.Second):
		t.Fatal("A lookup did not start")
	}
	response, err := resolver.Exchange(t.Context(), new(mDNS.Msg).SetQuestion(bootstrapTestHost, mDNS.TypeAAAA))
	checkBootstrapAddress(t, response, err, "2001:db8::7")
	close(aRelease)
	select {
	case got := <-aResult:
		checkBootstrapAddress(t, got.response, got.err, "203.0.113.7")
	case <-time.After(time.Second):
		t.Fatal("cold A lookup did not return its answer inside the family grace")
	}
}

func TestBootstrapColdAAAAReturnsEmptyAfterPeerGraceAndKeepsLooking(t *testing.T) {
	aaaaStarted, aaaaRelease := make(chan struct{}), make(chan struct{})
	resolver := testBootstrapDNS(t, &testDoHTransport{tag: "primary", exchange: func(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
		if q.Question[0].Qtype == mDNS.TypeAAAA {
			close(aaaaStarted)
			select {
			case <-aaaaRelease:
				return bootstrapAddressReply(q, "2001:db8::7"), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return bootstrapAddressReply(q, "203.0.113.7"), nil
	}})
	response, err := resolver.Exchange(t.Context(), new(mDNS.Msg).SetQuestion(bootstrapTestHost, mDNS.TypeA))
	checkBootstrapAddress(t, response, err, "203.0.113.7")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	type answer struct {
		response *mDNS.Msg
		err      error
	}
	result := make(chan answer, 1)
	started := time.Now()
	go func() {
		response, err := resolver.Exchange(ctx, new(mDNS.Msg).SetQuestion(bootstrapTestHost, mDNS.TypeAAAA))
		result <- answer{response, err}
	}()
	select {
	case <-aaaaStarted:
	case <-time.After(time.Second):
		t.Fatal("AAAA lookup did not start")
	}
	var elapsed time.Duration
	select {
	case got := <-result:
		response, err = got.response, got.err
		elapsed = time.Since(started)
	case <-ctx.Done():
		t.Fatal("cold AAAA query did not return after family grace")
	}
	if err != nil || response == nil || response.Rcode != mDNS.RcodeSuccess || len(response.Answer) != 0 {
		t.Fatalf("cold AAAA should become an empty success after peer grace: response=%v error=%v", response, err)
	}
	if elapsed < bootstrapFamilyGrace/2 || elapsed > time.Second {
		t.Fatalf("cold AAAA returned after %v; expected the short family grace", elapsed)
	}
	// The grace belongs to the lookup: a later caller does not wait it again.
	started = time.Now()
	response, err = resolver.Exchange(t.Context(), new(mDNS.Msg).SetQuestion(bootstrapTestHost, mDNS.TypeAAAA))
	if elapsed = time.Since(started); err != nil || response == nil || len(response.Answer) != 0 || elapsed > bootstrapFamilyGrace/2 {
		t.Fatalf("later cold AAAA after %v: response=%v error=%v", elapsed, response, err)
	}
	close(aaaaRelease)
	resolver.lookups.Wait()
	response, err = resolver.Exchange(t.Context(), new(mDNS.Msg).SetQuestion(bootstrapTestHost, mDNS.TypeAAAA))
	checkBootstrapAddress(t, response, err, "2001:db8::7")
}

func TestBootstrapColdFailureRetriesOnNextQuery(t *testing.T) {
	var calls atomic.Int32
	resolver := testBootstrapDNS(t, &testDoHTransport{tag: "primary", exchange: func(_ context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("temporary lookup failure")
		}
		return bootstrapAddressReply(q, "203.0.113.8"), nil
	}})
	query := new(mDNS.Msg).SetQuestion(bootstrapTestHost, mDNS.TypeA)
	if _, err := resolver.Exchange(t.Context(), query); err == nil {
		t.Fatal("first cold lookup should report its failure")
	}
	response, err := resolver.Exchange(t.Context(), query)
	checkBootstrapAddress(t, response, err, "203.0.113.8")
	if calls.Load() != 2 {
		t.Fatalf("cold failure was suppressed instead of retried: %d upstream calls", calls.Load())
	}
}

func testBootstrapDNS(t *testing.T, upstreams ...adapter.DNSTransport) *bootstrapDNS {
	t.Helper()
	tags := make([]string, 0, len(upstreams))
	for _, upstream := range upstreams {
		tags = append(tags, upstream.Tag())
	}
	transport, err := newBootstrapDNS(t.Context(), nil, "bootstrap", bootstrapDNSOptions{
		Hosts: []string{bootstrapTestHost}, Upstreams: tags,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := transport.(*bootstrapDNS)
	resolver.ctx, resolver.upstreams = t.Context(), upstreams
	t.Cleanup(resolver.lookups.Wait)
	return resolver
}

func bootstrapAddressReply(query *mDNS.Msg, address string) *mDNS.Msg {
	response := new(mDNS.Msg).SetReply(query)
	header := mDNS.RR_Header{Name: query.Question[0].Name, Class: mDNS.ClassINET, Ttl: 60}
	switch query.Question[0].Qtype {
	case mDNS.TypeA:
		header.Rrtype = mDNS.TypeA
		response.Answer = []mDNS.RR{&mDNS.A{Hdr: header, A: net.ParseIP(address).To4()}}
	case mDNS.TypeAAAA:
		header.Rrtype = mDNS.TypeAAAA
		response.Answer = []mDNS.RR{&mDNS.AAAA{Hdr: header, AAAA: net.ParseIP(address).To16()}}
	default:
		panic("unsupported bootstrap address query")
	}
	return response
}

func checkBootstrapAddress(t *testing.T, response *mDNS.Msg, err error, want string) {
	t.Helper()
	addresses := adapter.DNSResponseAddresses(response)
	if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr(want) {
		t.Fatalf("wanted %s, got addresses %v, error %v", want, addresses, err)
	}
}

type testDoHTransport struct {
	adapter.DNSTransport
	tag      string
	detour   string
	exchange func(context.Context, *mDNS.Msg) (*mDNS.Msg, error)
}

func (t *testDoHTransport) Tag() string { return t.tag }

func (t *testDoHTransport) Type() string { return "https" }

func (t *testDoHTransport) Dependencies() []string { return nil }

func (t *testDoHTransport) References() []string {
	if t.detour != "" {
		return []string{t.detour}
	}
	return nil
}

func (t *testDoHTransport) Exchange(ctx context.Context, query *mDNS.Msg) (*mDNS.Msg, error) {
	return t.exchange(ctx, query)
}

type testBootstrapManager struct {
	adapter.DNSTransportManager
	transports map[string]adapter.DNSTransport
}

func (m testBootstrapManager) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, ok := m.transports[tag]
	return transport, ok
}
