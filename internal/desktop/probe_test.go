// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/helper"
	"pipe/internal/link"
)

func TestProfileProbeChoosesSessionLocation(t *testing.T) {
	s, local, h, request := profileRelayTestServer(t)
	// A disconnected probe stays local even with TUN enabled in settings.
	if err := s.store.Update(func(d *appData) {
		d.Settings.TUN, d.Settings.IPv6 = true, true
		d.setRelay("phone", ProfileRelay{Code: "relay.example:8444/30000-39999", On: true})
	}); err != nil {
		t.Fatal(err)
	}
	h.info = helper.Info{State: helper.StateOutdated}
	var calls []string
	probe := func(ctx context.Context, options clientctl.ProbeOptions) map[string]clientctl.RouteLatency {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("profile probe has no deadline")
		}
		if options.Profile.Name != "phone" || options.Relay != "relay.example:8444/30000-39999" || !options.IPv6 || options.Interface != "" {
			t.Error("profile probe did not use the saved options")
		}
		return map[string]clientctl.RouteLatency{
			"fast": {Ms: 42, OK: true, Via: "relay"}, "stealth": {Via: "relay"},
		}
	}
	s.cfg.probeProfile = func(ctx context.Context, opts clientctl.ProbeOptions) map[string]clientctl.RouteLatency {
		calls = append(calls, "local")
		return probe(ctx, opts)
	}
	h.probeProfile = func(ctx context.Context, opts clientctl.ProbeOptions) (map[string]clientctl.RouteLatency, error) {
		calls = append(calls, "TUN")
		return probe(ctx, opts), nil
	}
	for _, via := range []string{"", viaProxy, viaTUN} {
		s.setVia(via)
		if via == viaProxy {
			local.state, local.mode = "on", "direct"
		}
		w := request("POST", "/api/profiles/PHONE/test", "")
		if w.Code != http.StatusOK || w.Body.String() != "{\"routes\":{\"fast\":{\"ms\":42,\"ok\":true,\"via\":\"relay\"},\"stealth\":{\"ms\":0,\"ok\":false}}}\n" {
			t.Fatalf("probe via %q returned %d %s", via, w.Code, w.Body)
		}
	}
	if len(calls) != 3 || calls[0] != "local" || calls[1] != "local" || calls[2] != "TUN" {
		t.Fatalf("probe locations = %v", calls)
	}
	if w := request("POST", "/api/profiles/missing/test", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing profile returned %d", w.Code)
	}
}

func TestProfileProbeTimeoutKeepsRoutes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _, h, request := profileRelayTestServer(t)
		probe := func(ctx context.Context, _ clientctl.ProbeOptions) map[string]clientctl.RouteLatency {
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 20*time.Second {
				t.Error("response deadline should allow time for the probe to return")
			}
			<-ctx.Done()
			return map[string]clientctl.RouteLatency{"fast": {Ms: 42, OK: true, Via: "relay"}}
		}
		s.cfg.probeProfile = probe
		h.probeProfile = func(ctx context.Context, opts clientctl.ProbeOptions) (map[string]clientctl.RouteLatency, error) {
			return probe(ctx, opts), ctx.Err()
		}
		for _, via := range []string{viaProxy, viaTUN} {
			s.setVia(via)
			w := request("POST", "/api/profiles/phone/test", "")
			var reply struct{ Routes map[string]profileLatency }
			if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != http.StatusOK ||
				reply.Routes["fast"] != (profileLatency{Ms: 42, OK: true, Via: "relay"}) || len(reply.Routes) != 2 {
				t.Fatalf("expired probe via %s returned %d %s", via, w.Code, w.Body)
			}
		}
	})
}

func TestProfileProbeLimitsAndCancellation(t *testing.T) {
	synctest.Test(t, testProfileProbeLimitsAndCancellation)
}

func testProfileProbeLimitsAndCancellation(t *testing.T) {
	s, _, _, request := profileRelayTestServer(t)
	for _, name := range []string{"tablet", "travel"} {
		if _, err := s.profiles.Save(name, link.Profile{Host: "example.com", Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	started := make(chan string, 2)
	closing, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var firstPhone atomic.Bool
	s.cfg.probeProfile = func(ctx context.Context, opts clientctl.ProbeOptions) map[string]clientctl.RouteLatency {
		started <- opts.Profile.Name
		<-ctx.Done()
		if opts.Profile.Name == "phone" && firstPhone.CompareAndSwap(false, true) {
			close(closing)
			<-release
		}
		return nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	launch := func(ctx context.Context, name string) <-chan error {
		result := make(chan error, 1)
		r := httptest.NewRequestWithContext(ctx, "POST", "/api/profiles/"+name+"/test", nil)
		r.SetPathValue("name", name)
		go func() {
			_, err := s.testProfile(r)
			result <- err
		}()
		return result
	}
	expectStart := func(name string) {
		t.Helper()
		if got := <-started; got != name {
			t.Fatalf("started %s, want %s", got, name)
		}
	}
	firstCtx, cancelFirst := context.WithCancel(ctx)
	defer cancelFirst()
	first := launch(firstCtx, "phone")
	expectStart("phone")
	second := launch(ctx, "tablet")
	expectStart("tablet")
	if w := request("POST", "/api/profiles/PHONE/test", ""); w.Code != http.StatusConflict {
		t.Fatalf("duplicate profile returned %d", w.Code)
	}
	if w := request("POST", "/api/profiles/travel/test", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("third profile returned %d", w.Code)
	}
	cancelFirst()
	<-closing
	queuedCtx, cancelQueued := context.WithCancel(ctx)
	queued := launch(queuedCtx, "travel")
	synctest.Wait()
	cancelQueued()
	if err := <-queued; !errors.Is(err, context.Canceled) {
		t.Errorf("canceled slot wait returned %v", err)
	}
	replacement := launch(ctx, "PHONE")
	synctest.Wait()
	select {
	case got := <-started:
		t.Errorf("replacement started before cleanup: %s", got)
	case err := <-replacement:
		t.Errorf("replacement returned before cleanup: %v", err)
	default:
	}
	close(release)
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled profile result = %v", err)
	}
	if t.Failed() {
		return
	}
	expectStart("phone")
	cancel()
	for _, probe := range []<-chan error{second, replacement} {
		if err := <-probe; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled profile result = %v", err)
		}
	}
}
