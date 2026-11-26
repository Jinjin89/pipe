// SPDX-License-Identifier: GPL-3.0-or-later

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"pipe/internal/clientctl"
)

func TestProfileProbeWire(t *testing.T) {
	dns := &fakeSystemDNS{}
	profile := testProfile()
	opts := clientctl.ProbeOptions{Profile: profile, Relay: "[2001:db8::2]/30000-39999", IPv6: true}
	r := startServer(t, func(o *ServeOptions) {
		o.DNS = dns
		o.Session.(*fakeSession).uplink = "en0"
		o.probeProfile = func(ctx context.Context, got clientctl.ProbeOptions) clientctl.ProfileTestResult {
			if got.Profile != profile || got.Relay != opts.Relay || !got.IPv6 || got.Interface != "en0" {
				t.Error("probe did not receive the profile options and physical uplink")
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Error("profile probe has no deadline")
			}
			result := clientctl.ProfileTestResult{Routes: map[string]clientctl.RouteLatency{"fast": {Ms: 22, OK: true, Via: "relay"}}}
			if !got.SkipExitCountry {
				result.ExitCountry = "JP"
			}
			return result
		}
	})
	remote := NewRemote(RemoteOptions{Socket: r.sock, Version: "1.2.3"})
	if info := remote.Info(); info.State != StateOK || ProtocolVersion != 4 {
		t.Fatalf("probe protocol = %d, info = %+v", ProtocolVersion, info)
	}
	for _, wantCountry := range []string{"JP", ""} {
		opts.SkipExitCountry = wantCountry == ""
		res, err := remote.TestProfileResult(t.Context(), opts)
		fast := res.Routes["fast"]
		if err != nil || fast.Ms != 22 || !fast.OK || fast.Via != "relay" || res.ExitCountry != wantCountry {
			t.Fatalf("profile probe = %v, %v, want country %q", res, err, wantCountry)
		}
	}
	opts.Relay = profile.Host + ":8444"
	if _, err := remote.TestProfile(t.Context(), opts); err == nil {
		t.Fatal("accepted a relay pointing to the server host")
	}
	if st := remote.Status(); st.State != clientctl.StateOff {
		t.Fatalf("probe modified the running session: %+v", st)
	}
	if got := dns.recorded(); len(got) != 1 || got[0] != "repair" {
		t.Fatalf("probe modified system DNS: %v", got)
	}
}

func TestProfileProbeRequiresUplink(t *testing.T) {
	r := startServer(t, func(o *ServeOptions) {
		o.DNS = &fakeSystemDNS{}
		o.probeProfile = func(context.Context, clientctl.ProbeOptions) clientctl.ProfileTestResult {
			t.Error("probe started without a physical uplink")
			return clientctl.ProfileTestResult{}
		}
	})
	remote := NewRemote(RemoteOptions{Socket: r.sock, Version: "1.2.3"})
	if _, err := remote.TestProfile(t.Context(), clientctl.ProbeOptions{Profile: testProfile()}); err == nil {
		t.Fatal("helper should report a missing uplink")
	}
}

func TestProfileProbeTimeoutKeepsRoutes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		text, err := testProfile().Encode()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(TestProfileParams{Link: text})
		if err != nil {
			t.Fatal(err)
		}
		s := &server{
			probeSlots: make(chan struct{}, 2),
			opts: ServeOptions{
				Session: &fakeSession{uplink: "en0"},
				probeProfile: func(ctx context.Context, _ clientctl.ProbeOptions) clientctl.ProfileTestResult {
					<-ctx.Done()
					return clientctl.ProfileTestResult{Routes: map[string]clientctl.RouteLatency{"fast": {Ms: 22, OK: true, Via: "relay"}}}
				},
			},
		}
		res, errText := s.testProfile(t.Context(), raw)
		if errText != "" {
			t.Fatalf("expired probe returned %q", errText)
		}
		if fast := res.(clientctl.ProfileTestResult).Routes["fast"]; !fast.OK || fast.Ms != 22 || fast.Via != "relay" {
			t.Fatalf("expired probe returned %+v", res)
		}
	})
}

func TestProfileProbeWaitsForSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &server{probeSlots: make(chan struct{}, 2)}
		s.probeSlots <- struct{}{}
		s.probeSlots <- struct{}{}
		acquire := func(ctx context.Context) <-chan string {
			result := make(chan string, 1)
			go func() { result <- s.acquireProfileSlot(ctx) }()
			return result
		}
		ctx, cancel := context.WithCancel(t.Context())
		canceled := acquire(ctx)
		synctest.Wait()
		cancel()
		if got := <-canceled; got != context.Canceled.Error() {
			t.Errorf("canceled slot wait returned %q", got)
		}
		retry := acquire(t.Context())
		synctest.Wait()
		select {
		case got := <-retry:
			t.Fatalf("slot wait returned before release: %q", got)
		default:
		}
		<-s.probeSlots
		if got := <-retry; got != "" {
			t.Fatalf("retry after release returned %q", got)
		}
	})
}

func TestProfileProbeSocketCancellationAndLimit(t *testing.T) {
	started, ended := make(chan struct{}, 2), make(chan struct{}, 2)
	r := startServer(t, func(o *ServeOptions) {
		o.DNS = &fakeSystemDNS{}
		o.Session.(*fakeSession).uplink = "net0"
		o.probeProfile = func(ctx context.Context, _ clientctl.ProbeOptions) clientctl.ProfileTestResult {
			started <- struct{}{}
			<-ctx.Done()
			ended <- struct{}{}
			return clientctl.ProfileTestResult{}
		}
	})
	remote := NewRemote(RemoteOptions{Socket: r.sock, Version: "1.2.3"})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	launch := func(ctx context.Context, host string) <-chan error {
		result := make(chan error, 1)
		go func() {
			profile := testProfile()
			profile.Host = host
			_, err := remote.TestProfile(ctx, clientctl.ProbeOptions{Profile: profile})
			result <- err
		}()
		select {
		case <-started:
		case err := <-result:
			t.Fatalf("probe returned before starting: %v", err)
		case <-ctx.Done():
			t.Fatal("probe did not start")
		}
		return result
	}
	firstCtx, cancelFirst := context.WithCancel(ctx)
	defer cancelFirst()
	first := launch(firstCtx, "first.example")
	second := launch(ctx, "second.example")
	if _, err := remote.TestProfile(ctx, clientctl.ProbeOptions{Profile: testProfile()}); err == nil || err.Error() != "Two profiles are already being tested." {
		t.Fatalf("third profile returned %v", err)
	}
	cancelFirst()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request returned %v", err)
	}
	select {
	case <-ended:
	case <-ctx.Done():
		t.Fatal("closing the app socket did not cancel the probe")
	}
	cancel()
	if err := <-second; !errors.Is(err, context.Canceled) {
		t.Fatalf("second request returned %v", err)
	}
}
