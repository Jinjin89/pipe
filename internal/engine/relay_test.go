// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type relayTestDialer struct {
	N.Dialer
	dial func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (d relayTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx, network, destination)
}

type relayTestConn struct {
	net.Conn
	closed bool
}

func (c *relayTestConn) Close() error {
	c.closed = true
	return nil
}

func TestRelayStaggerAndFallback(t *testing.T) {
	server := M.ParseSocksaddrHostPort("origin.example", 8443)
	relay := M.ParseSocksaddrHostPort("relay.example", 8444)
	tests := []struct {
		name        string
		relayDelay  time.Duration
		relayFails  bool
		directAfter time.Duration
		viaRelay    bool
	}{
		{"quick relay", 100 * time.Millisecond, false, 0, true},
		{"stalled relay", 2 * time.Second, false, time.Second, false},
		{"immediate fallback on failure", 25 * time.Millisecond, true, 25 * time.Millisecond, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				type call struct {
					destination M.Socksaddr
					at          time.Duration
				}
				start := time.Now()
				calls := make(chan call, 3)
				relayConn, directConn := new(relayTestConn), new(relayTestConn)
				dialer := relayTestDialer{dial: func(_ context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
					if network != N.NetworkTCP {
						t.Errorf("dial used network %q", network)
					}
					calls <- call{destination, time.Since(start)}
					if destination == relay {
						time.Sleep(test.relayDelay)
						if test.relayFails {
							return nil, errors.New("relay closed")
						}
						return relayConn, nil
					}
					return directConn, nil
				}}
				state := newRelayState(Relay{Host: relay.Fqdn, Tags: []string{"stealth"}, StealthPort: relay.Port})
				conn, err := dialRelay(t.Context(), state, "stealth", func(ctx context.Context, viaRelay bool) (net.Conn, error) {
					if viaRelay {
						return dialer.DialContext(ctx, N.NetworkTCP, relay)
					}
					return dialer.DialContext(ctx, N.NetworkTCP, server)
				}, func(conn net.Conn) { conn.Close() })
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				time.Sleep(2 * time.Second)
				synctest.Wait()
				close(calls)
				var attempts []call
				for attempt := range calls {
					attempts = append(attempts, attempt)
				}
				want := []call{{relay, 0}}
				winner := relayConn
				if test.directAfter != 0 {
					want = append(want, call{server, test.directAfter})
					winner = directConn
				}
				if !slices.Equal(attempts, want) || conn != winner {
					t.Errorf("attempts %v and winner %p, want %v and %p", attempts, conn, want, winner)
				}
				wantState := "direct"
				if test.viaRelay {
					wantState = "via"
				}
				if got := (&Instance{relay: state}).RelayState("stealth"); got != wantState {
					t.Errorf("RelayState(stealth) = %q, want %q", got, wantState)
				}
				if !test.viaRelay && !test.relayFails && !relayConn.closed {
					t.Error("late relay connection stayed open")
				}
				if winner.closed {
					t.Error("winning connection was closed")
				}
			})
		})
	}
}

func TestRelayCooldownSharedAcrossTiersAndClearedOnNetworkChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		state := newRelayState(Relay{Host: "192.0.2.2", Tags: []string{"stealth", "fast"}, StealthPort: 8444, FastPort: 444})
		instance := &Instance{relay: state}
		if instance.RelayState("stealth") != "pending" || instance.RelayState("fast") != "pending" {
			t.Fatal("configured relay paths should initially be pending")
		}
		dial := func(tag string, relayFails bool, want []bool) {
			t.Helper()
			calls := make(chan bool, 2)
			_, err := dialRelay(t.Context(), state, tag, func(_ context.Context, viaRelay bool) (string, error) {
				calls <- viaRelay
				if viaRelay && relayFails {
					return "", errors.New("no route to relay")
				}
				return "ok", nil
			}, func(string) {})
			if err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			close(calls)
			var attempts []bool
			for call := range calls {
				attempts = append(attempts, call)
			}
			if !slices.Equal(attempts, want) {
				t.Fatalf("%s attempted %v (true is relay), want %v", tag, attempts, want)
			}
			wantState := "direct"
			if want[len(want)-1] {
				wantState = "via"
			}
			if got := instance.RelayState(tag); got != wantState {
				t.Errorf("RelayState(%s) = %q, want %q", tag, got, wantState)
			}
		}

		dial("stealth", true, []bool{true, false})
		time.Sleep(time.Minute - time.Nanosecond)
		dial("fast", false, []bool{false})
		time.Sleep(time.Nanosecond)
		dial("fast", false, []bool{true})
		dial("stealth", true, []bool{true, false})
		if instance.RelayState("fast") != "via" {
			t.Error("Stealth reset Fast's last successful path")
		}
		state.reset()
		if instance.RelayState("fast") != "pending" || instance.RelayState("stealth") != "pending" {
			t.Fatal("network reset kept the last successful paths")
		}
		dial("stealth", false, []bool{true})
	})
}

func TestRelayProbeEngineDoesNotShareCooldown(t *testing.T) {
	instance, err := New(t.Context(), Options{
		Relay:                Relay{Host: "192.0.2.2", Tags: []string{"stealth", "fast"}, StealthPort: 8444, FastPort: 444},
		DisableRelayCooldown: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()

	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		state := instance.relay
		directStarted, finishDirect := make(chan struct{}), make(chan struct{})
		stealthDone := make(chan error, 1)
		go func() {
			_, err := dialRelay(ctx, state, "stealth", func(_ context.Context, viaRelay bool) (bool, error) {
				if viaRelay {
					return false, errors.New("Stealth relay unavailable")
				}
				close(directStarted)
				<-finishDirect
				return false, nil
			}, func(bool) {})
			stealthDone <- err
		}()

		// The relay has failed while Stealth's direct fallback is still in flight.
		<-directStarted
		via, err := dialRelay(ctx, state, "fast", func(_ context.Context, viaRelay bool) (bool, error) {
			return viaRelay, nil
		}, func(bool) {})
		close(finishDirect)
		if err := <-stealthDone; err != nil {
			t.Fatalf("Stealth direct fallback failed: %v", err)
		}
		if err != nil || !via {
			t.Errorf("Fast used relay=%v after Stealth relay failure, err=%v", via, err)
		}
		if !state.retryAt.IsZero() {
			t.Errorf("Stealth direct fallback set a cooldown until %v", state.retryAt)
		}
	})
}

func TestRelayStallCooldownOnDeadline(t *testing.T) {
	for _, test := range []struct {
		name     string
		after    time.Duration
		canceled bool
		cooldown bool
	}{
		{"1.8 second probe deadline", 1800 * time.Millisecond, false, true},
		{"deadline before direct starts", 900 * time.Millisecond, false, false},
		{"caller cancellation after direct starts", 1800 * time.Millisecond, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				state := newRelayState(Relay{Host: "192.0.2.2", Tags: []string{"stealth", "fast"}, StealthPort: 8444, FastPort: 444})
				instance := &Instance{relay: state}
				started := time.Now()
				wantErr := context.DeadlineExceeded
				var ctx context.Context
				var cancel context.CancelFunc
				if test.canceled {
					ctx, cancel = context.WithCancel(t.Context())
					wantErr = context.Canceled
					go func() {
						time.Sleep(test.after)
						cancel()
					}()
				} else {
					ctx, cancel = context.WithTimeout(t.Context(), test.after)
				}
				defer cancel()
				directStarted := make(chan time.Duration, 1)
				_, err := dialRelay(ctx, state, "fast", func(ctx context.Context, viaRelay bool) (string, error) {
					if !viaRelay {
						directStarted <- time.Since(started)
					}
					<-ctx.Done()
					return "", ctx.Err()
				}, func(string) {})
				if !errors.Is(err, wantErr) {
					t.Fatalf("dial ended with %v, want %v", err, wantErr)
				}
				synctest.Wait()
				select {
				case delay := <-directStarted:
					if delay != RelayFallbackDelay || test.after < RelayFallbackDelay {
						t.Errorf("direct started after %v with a %v context", delay, test.after)
					}
				default:
					if test.after > RelayFallbackDelay {
						t.Error("direct was never attempted")
					}
				}
				if got := instance.RelayState("fast"); got != "pending" {
					t.Errorf("incomplete dial published %q", got)
				}
				viaRelay, err := dialRelay(t.Context(), state, "stealth", func(_ context.Context, viaRelay bool) (bool, error) {
					return viaRelay, nil
				}, func(bool) {})
				if err != nil || viaRelay == test.cooldown {
					t.Errorf("next tier dial used relay=%v, err=%v, want cooldown=%v", viaRelay, err, test.cooldown)
				}
			})
		})
	}
}

func TestRelayOnNetworkChangeResetsBeforeCallback(t *testing.T) {
	instance, err := New(t.Context(), Options{
		Config: Object{"outbounds": []Object{{"type": "direct", "tag": "direct"}}},
		VPN:    &VPNOptions{Platform: &testVPNPlatform{network: "{}"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	state := newRelayState(Relay{Host: "192.0.2.2", Tags: []string{"fast", "stealth"}, StealthPort: 8444, FastPort: 444})
	instance.relay = state
	monitor := &instance.vpn.monitor
	state.watchNetwork(monitor)
	failRelay := func(_ context.Context, viaRelay bool) (bool, error) {
		if viaRelay {
			return false, errors.New("relay path failed")
		}
		return false, nil
	}
	closeDial := func(bool) {}
	_, err = dialRelay(t.Context(), state, "stealth", failRelay, closeDial)
	if err != nil || instance.RelayState("stealth") != "direct" {
		t.Fatalf("failed to establish a direct path on the old network: %v", err)
	}
	unregister := instance.OnNetworkChange(func() {
		if got := instance.RelayState("stealth"); got != "pending" {
			t.Errorf("callback saw old path %q", got)
		}
		viaRelay, err := dialRelay(t.Context(), state, "stealth", func(_ context.Context, viaRelay bool) (bool, error) {
			return viaRelay, nil
		}, closeDial)
		if err != nil || !viaRelay {
			t.Errorf("callback's first dial used relay=%v, err=%v", viaRelay, err)
		}
		if _, err := dialRelay(t.Context(), state, "fast", failRelay, closeDial); err != nil {
			t.Fatal(err)
		}
	})
	defer unregister()
	unregisterSecond := instance.OnNetworkChange(func() {
		if got := instance.RelayState("stealth"); got != "via" {
			t.Errorf("second subscriber saw Stealth state %q", got)
		}
	})
	defer unregisterSecond()
	generation := state.generation
	for _, callback := range monitor.callbacks.Array() {
		callback(nil, 0)
	}
	retryAt := state.retryAt
	state.interfaceUpdated("fast")
	state.interfaceUpdated("stealth")
	if state.generation != generation+1 {
		t.Errorf("network change reset relay state %d times", state.generation-generation)
	}
	if fast, stealth := instance.RelayState("fast"), instance.RelayState("stealth"); fast != "direct" || stealth != "via" {
		t.Errorf("interface updates left Fast=%q and Stealth=%q", fast, stealth)
	}
	if retryAt.IsZero() || state.retryAt != retryAt {
		t.Error("interface updates lost the cooldown set by the new network")
	}
}

func TestRelayInterfaceUpdatesWithoutMonitorResetOnce(t *testing.T) {
	for _, tags := range [][]string{{"fast"}, {"stealth"}, {"fast", "stealth"}} {
		state := newRelayState(Relay{Host: "192.0.2.2", Tags: tags, StealthPort: 8444, FastPort: 444})
		instance := &Instance{relay: state}
		state.failed(state.generation)
		for _, tag := range tags {
			state.lastDial[tag] = "direct"
		}
		for _, tag := range tags {
			state.interfaceUpdated(tag)
		}
		if state.generation != 1 || !state.retryAt.IsZero() {
			t.Errorf("%v reset %d times with cooldown %v", tags, state.generation, state.retryAt)
		}
		for _, tag := range tags {
			if got := instance.RelayState(tag); got != "pending" {
				t.Errorf("%v left %s in state %q", tags, tag, got)
			}
		}
	}
}

func TestRelayOldNetworkFailureDoesNotRestartCooldown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		state := newRelayState(Relay{Host: "192.0.2.2", Tags: []string{"stealth"}, StealthPort: 8444})
		started, reset, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			_, _ = dialRelay(t.Context(), state, "stealth", func(_ context.Context, viaRelay bool) (string, error) {
				if viaRelay {
					close(started)
					<-reset
					return "", errors.New("old path failed")
				}
				return "direct", nil
			}, func(string) {})
		}()
		<-started
		state.reset()
		close(reset)
		<-done
		if got := (&Instance{relay: state}).RelayState("stealth"); got != "pending" {
			t.Errorf("old network updated the path to %q", got)
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		if !state.retryAt.IsZero() {
			t.Errorf("old network set a cooldown until %v", state.retryAt)
		}
	})
}

func TestRelayTCPRedirectsOnlyServerEndpoint(t *testing.T) {
	server := M.ParseSocksaddrHostPort("origin.example", 8443)
	relay := M.ParseSocksaddrHostPort("relay.example", 8444)
	var destinations []M.Socksaddr
	dialer := relayTestDialer{dial: func(_ context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
		destinations = append(destinations, destination)
		return new(relayTestConn), nil
	}}
	stealth := &relayTCPOutbound{Dialer: dialer, viaRelay: dialer, server: server, endpoint: relay}
	otherPort := M.ParseSocksaddrHostPort(server.Fqdn, 443)
	otherHost := M.ParseSocksaddrHostPort("destination.example", server.Port)
	for _, dest := range []M.Socksaddr{otherPort, otherHost, server} {
		conn, err := stealth.DialContext(t.Context(), N.NetworkTCP, dest)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	if !slices.Equal(destinations, []M.Socksaddr{otherPort, otherHost, relay}) {
		t.Errorf("physical endpoints = %v, want only the server endpoint redirected", destinations)
	}
}

func TestRelayFastRequiresPinAndTag(t *testing.T) {
	config := Relay{Host: "192.0.2.2", Tags: []string{"fast"}, FastPort: 444}
	state := newRelayState(config)
	options := option.Hysteria2OutboundOptions{OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
		TLS: &option.OutboundTLSOptions{Enabled: true},
	}}
	decoded := option.Options{Outbounds: []option.Outbound{{Tag: "fast", Options: &options}}}
	state.configure(&decoded)
	if got := (&Instance{relay: state}).RelayState("fast"); got != "" {
		t.Errorf("unpinned Fast publishes relay state %q", got)
	}
	options.TLS.CertificatePublicKeySHA256 = [][]byte{make([]byte, 32)}
	state = newRelayState(config)
	state.configure(&decoded)
	instance := &Instance{relay: state}
	if instance.RelayState("fast") != "pending" || instance.RelayState("rescue") != "" || instance.RelayState("direct") != "" {
		t.Error("only the pinned Fast tier should have a pending relay")
	}
	config.Tags = []string{"stealth"}
	config.StealthPort = 8444
	state = newRelayState(config)
	state.configure(&decoded)
	if got := (&Instance{relay: state}).RelayState("fast"); got != "" {
		t.Errorf("Fast port without a Fast tag publishes relay state %q", got)
	}
}
