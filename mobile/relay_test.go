// SPDX-License-Identifier: GPL-3.0-or-later

package mobile

import (
	"context"
	"encoding/json"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"pipe/internal/engine"
)

func TestRelayPreferences(t *testing.T) {
	raw, profile := sampleProfile(t)
	for _, tc := range []struct{ code, host string }{
		{"", ""},
		{"relay.example", "relay.example"},
		{"192.0.2.1:8444", "192.0.2.1"},
		{"2001:db8::1", "2001:db8::1"},
		{"[2001:db8::1]:8444/30000-39999", "2001:db8::1"},
		{"relay.example/444", "relay.example"},
		{"relay.example/30000-39999", "relay.example"},
	} {
		body, err := json.Marshal(map[string]string{"relay": tc.code})
		if err != nil {
			t.Fatal(err)
		}
		settings, err := prepare(raw, string(body))
		if err != nil || settings.client.Relay != tc.code || settings.relayHost != tc.host || ValidateRelay(raw, tc.code) != "" {
			t.Fatalf("relay code %q: got code %q, host %q, error %v", tc.code, settings.client.Relay, settings.relayHost, err)
		}
	}
	for _, code := range []string{
		"https://relay.example", "relay.example:0", "relay.example/path", "relay host", profile.Host,
		profile.Host + ":8444", "2001:db8::1/444", "relay.example:8444/444,30000-39999",
	} {
		body, err := json.Marshal(map[string]string{"relay": code})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := prepare(raw, string(body)); err == nil || ValidateRelay(raw, code) == "" {
			t.Fatalf("invalid relay %q was accepted", code)
		}
	}
	if _, err := prepare(raw, `{"relay":443}`); err == nil {
		t.Fatal("non-string relay was accepted")
	}
	if settings, err := prepare(raw, `{"tier":"stealth"}`); err != nil || settings.client.Relay != "" {
		t.Fatalf("preferences without a relay should leave it off: %v", err)
	}
}

func TestVPNRelayChangeRebuilds(t *testing.T) {
	raw, _ := sampleProfile(t)
	platform := &fakePlatform{statuses: make(chan string, 32)}
	var instances []*fakeEngine
	b := bridge{newEngine: func(_ context.Context, opts engine.Options) (clientEngine, error) {
		instance := &fakeEngine{options: opts}
		instances = append(instances, instance)
		return instance, nil
	}}
	defer b.stop()
	if err := b.start(raw, `{"tier":"stealth","relay":"[2001:db8::1]:8444"}`, platform); err != nil {
		t.Fatal(err)
	}
	if relay := instances[0].options.Relay; relay.Host != "2001:db8::1" || relay.StealthPort != 8444 ||
		!slices.Equal(relay.Tags, []string{"stealth"}) {
		t.Fatalf("relay configuration did not reach the engine: %+v", relay)
	}
	if err := b.applyPreferences(`{"tier":"stealth","relay":"[2001:db8::1]:8444"}`); err != nil || len(instances) != 1 {
		t.Fatalf("unchanged relay rebuilt the VPN: %v", err)
	}
	if err := b.applyPreferences(`{"tier":"stealth","relay":"[2001:db8::1]:0"}`); err == nil || len(instances) != 1 {
		t.Fatal("invalid relay changed the running VPN")
	}
	if err := b.applyPreferences(`{"tier":"stealth","relay":"[2001:db8::1]:8445"}`); err != nil {
		t.Fatal(err)
	}
	if len(instances) != 2 || platform.opened != 2 || !instances[0].closed ||
		instances[1].options.Relay.StealthPort != 8445 || testStatus(t, b.statusJSON()).Relay != "2001:db8::1" {
		t.Fatal("changing the relay port should rebuild and publish the parsed host")
	}
	b.networkChanged(true)
	if len(instances) != 2 || instances[1].resets != 1 {
		t.Fatal("network changes should reset the existing relay-enabled engine")
	}
	if err := b.applyPreferences(`{"tier":"stealth","relay":""}`); err != nil {
		t.Fatal(err)
	}
	if len(instances) != 3 || platform.opened != 3 || !instances[1].closed || instances[2].options.Relay.Host != "" ||
		testStatus(t, b.statusJSON()).Relay != "" {
		t.Fatal("disabling the relay did not rebuild without it")
	}
}

type relayTestEngine struct {
	*fakeEngine
	state atomic.Pointer[string]
}

func (e *relayTestEngine) RelayState(tag string) string {
	if !slices.Contains(e.options.Relay.Tags, tag) {
		return ""
	}
	if state := e.state.Load(); state != nil {
		return *state
	}
	return "pending"
}

func (e *relayTestEngine) RefreshVPNNetwork(reset bool) (bool, error) {
	online, err := e.fakeEngine.RefreshVPNNetwork(reset)
	if online && reset {
		e.state.Store(nil)
	}
	return online, err
}

func TestVPNRelayStatusTracksActiveTier(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw, _ := sampleProfile(t)
		platform := &fakePlatform{statuses: make(chan string, 32)}
		var instance *relayTestEngine
		b := bridge{newEngine: func(_ context.Context, opts engine.Options) (clientEngine, error) {
			instance = &relayTestEngine{fakeEngine: &fakeEngine{options: opts}}
			return instance, nil
		}}
		defer b.stop()
		if err := b.start(raw, `{"tier":"stealth","relay":"relay.example:8444/444"}`, platform); err != nil {
			t.Fatal(err)
		}
		first := <-platform.statuses
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(first), &fields); err != nil || string(fields["relayState"]) != `"pending"` || fields["viaRelay"] != nil {
			t.Fatalf("first status should publish the relay state field: %s, %v", first, err)
		}
		if status := testStatus(t, first); status.Relay != "relay.example" || status.RelayState != "pending" {
			t.Fatalf("unexpected relay status before a successful dial: %+v", status)
		}
		instance.state.Store(new("via"))
		time.Sleep(time.Second)
		synctest.Wait()
		if status := testStatus(t, <-platform.statuses); status.Relay != "relay.example" || status.RelayState != "via" {
			t.Fatalf("relay use was not published: %+v", status)
		}
		for _, tier := range []string{"fast", "rescue"} {
			if err := b.setTier(tier); err != nil {
				t.Fatal(err)
			}
			if status := testStatus(t, b.statusJSON()); status.Tier != tier || status.RelayState != "" {
				t.Fatalf("an ineligible tier reported a relay result: %+v", status)
			}
		}
		if err := b.setTier("stealth"); err != nil {
			t.Fatal(err)
		}
		if status := testStatus(t, b.statusJSON()); status.RelayState != "via" {
			t.Fatal("switching back to Stealth should report its last relay dial")
		}
		instance.state.Store(new("direct"))
		time.Sleep(time.Second)
		synctest.Wait()
		if status := testStatus(t, b.statusJSON()); status.Relay != "relay.example" || status.RelayState != "direct" {
			t.Fatalf("direct fallback was not reported: %+v", status)
		}
		b.networkChanged(false)
		if status := testStatus(t, b.statusJSON()); status.RelayState != "direct" {
			t.Fatalf("metadata refresh lost the last relay result: %+v", status)
		}
		b.networkChanged(true)
		if status := testStatus(t, b.statusJSON()); status.RelayState != "pending" {
			t.Fatalf("network reset kept the old relay result: %+v", status)
		}
		if err := b.setMode("direct"); err != nil {
			t.Fatal(err)
		}
		if status := testStatus(t, b.statusJSON()); status.Tier != "direct" || status.RelayState != "" {
			t.Fatalf("Direct mode reported a relay result: %+v", status)
		}
		b.stop()
		if status := testStatus(t, b.statusJSON()); status.Running || status.Relay != "" || status.RelayState != "" {
			t.Fatalf("stopped VPN kept live relay status: %+v", status)
		}
	})
}

type probeDeadlineEngine struct {
	*fakeEngine
	probeTimes chan time.Duration
}

func (e *probeDeadlineEngine) ProbeLatency(ctx context.Context, _ string, _ bool) (bool, time.Duration, bool, error) {
	deadline, _ := ctx.Deadline()
	e.probeTimes <- time.Until(deadline)
	return false, time.Millisecond, false, nil
}

func TestVPNRelayAutoProbeDeadline(t *testing.T) {
	const base = 1800 * time.Millisecond
	for _, tc := range []struct {
		name  string
		prefs string
		want  time.Duration
	}{
		{"no relay", `{"tier":"auto"}`, base},
		{"with relay", `{"tier":"auto","relay":"relay.example"}`, base + engine.RelayFallbackDelay},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				raw, _ := sampleProfile(t)
				platform := &fakePlatform{statuses: make(chan string, 16)}
				var instance *probeDeadlineEngine
				b := bridge{newEngine: func(_ context.Context, opts engine.Options) (clientEngine, error) {
					instance = &probeDeadlineEngine{fakeEngine: &fakeEngine{options: opts}, probeTimes: make(chan time.Duration, 8)}
					return instance, nil
				}}
				defer b.stop()
				if err := b.start(raw, tc.prefs, platform); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if len(instance.probeTimes) != 1 {
					t.Fatal("expected one connect-time probe")
				}
				<-instance.probeTimes
				instance.options.ObserveTraffic()
				synctest.Wait()
				if len(instance.probeTimes) != 1 {
					t.Fatal("expected one automatic failover probe")
				}
				if got := <-instance.probeTimes; got != tc.want {
					t.Fatalf("automatic failover probe has %v, want %v", got, tc.want)
				}
			})
		})
	}
}
