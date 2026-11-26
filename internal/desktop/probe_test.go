// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/helper"
	"pipe/internal/link"
)

type measuringController struct {
	*fakeCtl
	probe func(clientctl.ProbeOptions) clientctl.ProfileTestResult
}

func (c *measuringController) MeasureProfile(_ context.Context, opts clientctl.ProbeOptions) (clientctl.ProfileTestResult, bool) {
	return c.probe(opts), true
}

func TestProfileAndRoutingTestsShareSavedMeasurement(t *testing.T) {
	s, local, _, request := profileRelayTestServer(t)
	result := clientctl.ProfileTestResult{
		Routes:        map[string]clientctl.RouteLatency{"fast": {OK: true, Ms: 37}, "stealth": {OK: true, Ms: 105, Via: "relay"}},
		MetricVersion: clientctl.RTTMetricVersion, ExitCountry: "FI", CompletedAt: time.Now().UTC(),
	}
	s.cfg.Controller = &measuringController{fakeCtl: local, probe: func(opts clientctl.ProbeOptions) clientctl.ProfileTestResult {
		if !opts.PreferLive || opts.Profile.Name != "phone" {
			t.Fatal("live measurement did not use the selected profile")
		}
		return result
	}}
	s.cfg.probeProfile = func(context.Context, clientctl.ProbeOptions) clientctl.ProfileTestResult {
		t.Fatal("matching connected profile should not start a temporary engine")
		return clientctl.ProfileTestResult{}
	}
	if w := request("POST", "/api/connect", ""); w.Code != http.StatusOK {
		t.Fatalf("connect returned %d %s", w.Code, w.Body)
	}
	read := func(method, path string, v any) {
		t.Helper()
		w := request(method, path, "")
		if err := json.Unmarshal(w.Body.Bytes(), v); err != nil || w.Code != http.StatusOK {
			t.Fatalf("%s %s returned %d %s", method, path, w.Code, w.Body)
		}
	}
	check := func(got *profileTestResponse, name string) {
		t.Helper()
		fast := result.Routes["fast"]
		want := map[string]profileLatency{"fast": {OK: fast.OK, Ms: fast.Ms}, "stealth": {OK: true, Ms: 105, Via: "relay"}}
		if got == nil || got.Profile != name || got.Rev == "" || !got.CompletedAt.Equal(result.CompletedAt) ||
			got.ExitCountry != "FI" || !maps.Equal(got.Routes, want) {
			t.Fatalf("saved measurement = %+v, want routes %v at %s", got, want, result.CompletedAt)
		}
	}
	for _, path := range []string{"/api/profiles/phone/test", "/api/routes/test"} {
		if path == "/api/routes/test" {
			result.Routes["fast"] = clientctl.RouteLatency{} // A completed No reply replaces 37 ms.
			result.CompletedAt = result.CompletedAt.Add(time.Millisecond)
		}
		var response profileTestResponse
		read("POST", path, &response)
		check(&response, "phone")
		var status StatusResponse
		read("GET", "/api/status", &status)
		check(status.Measurement, "phone")
		var list struct{ Profiles []ProfileInfo }
		read("GET", "/api/profiles", &list)
		check(list.Profiles[0].Measurement, "phone")
	}
	var batch struct{ LastTestedAt time.Time }
	read("POST", "/api/profiles/test-complete", &batch)
	if batch.LastTestedAt.IsZero() {
		t.Fatal("the completed batch did not report a timestamp")
	}
	if w := request("PATCH", "/api/profiles/phone", `{"name":"tablet"}`); w.Code != http.StatusOK {
		t.Fatalf("rename returned %d %s", w.Code, w.Body)
	}

	cfg := s.cfg
	cfg.Controller = &fakeCtl{}
	reopened := NewServer(cfg)
	t.Cleanup(func() { _ = reopened.Close() })
	check(reopened.status().Measurement, "tablet")
	if data := reopened.store.Snapshot(); !batch.LastTestedAt.Equal(data.LastProfileBatch) || len(data.Measurements) != 1 {
		t.Fatal("batch timestamp or renamed measurement was lost")
	}
	if w := request("DELETE", "/api/profiles/tablet", ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete returned %d %s", w.Code, w.Body)
	}
	if saved := openStore(s.store.path, s.profiles).Snapshot().Measurements; len(saved) != 0 {
		t.Fatalf("delete retained the measurement: %+v", saved)
	}
}

func TestProfileProbeLegacyHelperReportsReachability(t *testing.T) {
	s, _, h, request := profileRelayTestServer(t)
	s.setVia(viaTUN)
	h.probeProfile = func(context.Context, clientctl.ProbeOptions) (clientctl.ProfileTestResult, error) {
		return clientctl.ProfileTestResult{Routes: map[string]clientctl.RouteLatency{"fast": {OK: true, Ms: 850, Via: "relay"}}}, nil
	}
	w := request("POST", "/api/profiles/phone/test", "")
	var reply profileTestResponse
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != http.StatusOK ||
		reply.Routes["fast"] != (profileLatency{OK: true, Via: "relay"}) {
		t.Fatalf("legacy helper returned %d %s", w.Code, w.Body)
	}
}

func TestProfileProbeChoosesSessionLocation(t *testing.T) {
	s, local, h, request := profileRelayTestServer(t)
	info, err := s.profiles.Info("phone")
	if err != nil {
		t.Fatal(err)
	}
	// A disconnected probe stays local even with TUN enabled in settings.
	if err := s.store.Update(func(d *appData) {
		d.Settings.TUN, d.Settings.IPv6 = true, true
		d.setRelay("phone", ProfileRelay{Code: "relay.example:8444/30000-39999", On: true})
	}); err != nil {
		t.Fatal(err)
	}
	h.info = helper.Info{State: helper.StateOutdated}
	var calls []string
	probe := func(ctx context.Context, options clientctl.ProbeOptions) clientctl.ProfileTestResult {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("profile probe has no deadline")
		}
		if options.Profile.Name != "phone" || options.Relay != "relay.example:8444/30000-39999" || !options.IPv6 || options.Interface != "" {
			t.Error("profile probe did not use the saved options")
		}
		return clientctl.ProfileTestResult{MetricVersion: clientctl.RTTMetricVersion, Routes: map[string]clientctl.RouteLatency{
			"fast": {Ms: 42, OK: true, Via: "relay"}, "stealth": {Via: "relay"},
		}}
	}
	s.cfg.probeProfile = func(ctx context.Context, opts clientctl.ProbeOptions) clientctl.ProfileTestResult {
		calls = append(calls, "local")
		return probe(ctx, opts)
	}
	h.probeProfile = func(ctx context.Context, opts clientctl.ProbeOptions) (clientctl.ProfileTestResult, error) {
		calls = append(calls, "TUN")
		return probe(ctx, opts), nil
	}
	for _, via := range []string{"", viaProxy, viaTUN} {
		s.setVia(via)
		if via == viaProxy {
			local.state, local.mode = "on", "direct"
		}
		w := request("POST", "/api/profiles/PHONE/test", "")
		var reply profileTestResponse
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != http.StatusOK ||
			reply.Rev == "" || reply.Rev != info.Rev || len(reply.Routes) != 2 ||
			reply.Routes["fast"] != (profileLatency{Ms: 42, OK: true, Via: "relay"}) ||
			reply.Routes["stealth"] != (profileLatency{}) {
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

func TestProfileProbeRevisionUsesTheTestedLink(t *testing.T) {
	s, _, _, request := profileRelayTestServer(t)
	profileInfo := func() ProfileInfo {
		t.Helper()
		w := request("GET", "/api/profiles", "")
		var reply struct{ Profiles []ProfileInfo }
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != http.StatusOK ||
			len(reply.Profiles) != 1 || reply.Profiles[0].Rev == "" {
			t.Fatalf("list profiles returned %d %s", w.Code, w.Body)
		}
		return reply.Profiles[0]
	}
	original := profileInfo()
	var testedPorts []uint16
	s.cfg.probeProfile = func(_ context.Context, opts clientctl.ProbeOptions) clientctl.ProfileTestResult {
		testedPorts = append(testedPorts, opts.Profile.FastEndpointPort())
		if len(testedPorts) == 1 {
			// Emulate a link replacement by another process during the probe.
			replacement := opts.Profile
			replacement.FastPort = 1443
			raw, err := replacement.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := WriteFileAtomic(s.profiles.path("phone"), []byte(raw+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return clientctl.ProfileTestResult{MetricVersion: clientctl.RTTMetricVersion, Routes: map[string]clientctl.RouteLatency{"fast": {OK: true, Ms: 42}}}
	}
	testRevision := func(want string) {
		t.Helper()
		w := request("POST", "/api/profiles/phone/test", "")
		var reply profileTestResponse
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != http.StatusOK || reply.Rev != want {
			t.Fatalf("profile test returned %d %s, want revision %q", w.Code, w.Body, want)
		}
	}
	if w := request("POST", "/api/profiles/phone/test", ""); w.Code != http.StatusConflict {
		t.Fatalf("probe of replaced link returned %d %s", w.Code, w.Body)
	}
	replaced := profileInfo()
	if replaced.Rev == original.Rev || replaced.Server != original.Server || replaced.Fingerprint != original.Fingerprint ||
		!slices.Equal(replaced.Routes, original.Routes) || replaced.Measurement != nil {
		t.Fatal("a Fast port change should update the revision while keeping the same profile summary")
	}
	testRevision(replaced.Rev)
	if !slices.Equal(testedPorts, []uint16{link.DefaultPort, 1443}) {
		t.Fatalf("tested ports = %v", testedPorts)
	}
}

func TestProfileProbeExitCountryCache(t *testing.T) {
	s, _, helper, request := profileRelayTestServer(t)
	var country string
	var skip bool
	probe := func(_ context.Context, options clientctl.ProbeOptions) clientctl.ProfileTestResult {
		if options.SkipExitCountry != skip {
			t.Errorf("skip country lookup = %t, want %t", options.SkipExitCountry, skip)
		}
		return clientctl.ProfileTestResult{
			MetricVersion: clientctl.RTTMetricVersion, Routes: map[string]clientctl.RouteLatency{"fast": {Ms: 42, OK: true}}, ExitCountry: country,
		}
	}
	s.cfg.probeProfile = probe
	helper.probeProfile = func(ctx context.Context, opts clientctl.ProbeOptions) (clientctl.ProfileTestResult, error) {
		return probe(ctx, opts), nil
	}
	test := func(name, want string) {
		t.Helper()
		w := request("POST", "/api/profiles/"+name+"/test", "")
		var reply profileTestResponse
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != http.StatusOK ||
			reply.Routes["fast"] != (profileLatency{Ms: 42, OK: true}) || reply.ExitCountry != want {
			t.Fatalf("profile test = %d %s, want country %q", w.Code, w.Body, want)
		}
		if want == "" && strings.Contains(w.Body.String(), `"exitCountry"`) {
			t.Fatalf("missing country was serialized: %s", w.Body)
		}
	}
	test("phone", "")
	country = "de"
	test("phone", "DE")

	s.setVia(viaTUN)
	if _, err := s.profiles.Save("tablet", link.Profile{Host: "example.com", Name: "tablet", Seed: [32]byte{1}}); err != nil {
		t.Fatal(err)
	}
	country, skip = "", true
	test("tablet", "DE")

	country, skip = "JP", false
	if _, err := s.profiles.Save("phone", link.Profile{Host: "example.com", Name: "phone", FastPort: 1443}); err != nil {
		t.Fatal(err)
	}
	test("phone", "JP")
	country = "XX"
	if _, err := s.profiles.Save("phone", link.Profile{Host: "example.com", Name: "phone", PublicKey: [32]byte{1}}); err != nil {
		t.Fatal(err)
	}
	test("phone", "")
	country = "Ca"
	test("phone", "CA")
}

func TestProfileProbeTimeoutKeepsRoutes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _, h, request := profileRelayTestServer(t)
		probe := func(ctx context.Context, _ clientctl.ProbeOptions) clientctl.ProfileTestResult {
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 20*time.Second {
				t.Error("response deadline should allow time for the probe to return")
			}
			<-ctx.Done()
			return clientctl.ProfileTestResult{MetricVersion: clientctl.RTTMetricVersion, Routes: map[string]clientctl.RouteLatency{"fast": {Ms: 42, OK: true, Via: "relay"}}}
		}
		s.cfg.probeProfile = probe
		h.probeProfile = func(ctx context.Context, opts clientctl.ProbeOptions) (clientctl.ProfileTestResult, error) {
			return probe(ctx, opts), ctx.Err()
		}
		w := request("POST", "/api/profiles/phone/test", "")
		var reply profileTestResponse
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != http.StatusOK ||
			reply.Routes["fast"] != (profileLatency{Ms: 42, OK: true, Via: "relay"}) || len(reply.Routes) != 1 {
			t.Fatalf("completed probe at deadline returned %d %s", w.Code, w.Body)
		}
		s.setVia(viaTUN)
		if w := request("POST", "/api/profiles/phone/test", ""); w.Code != http.StatusInternalServerError {
			t.Fatalf("helper timeout returned %d %s", w.Code, w.Body)
		}
		got := s.store.Snapshot().Measurements["phone"].profileTestResponse
		if got.CompletedAt != reply.CompletedAt || got.Routes["fast"] != reply.Routes["fast"] {
			t.Fatalf("helper timeout changed the saved measurement: %+v", got)
		}
	})
}

func TestProfileProbeHelperErrorHasNoRouteResults(t *testing.T) {
	s, _, helper, request := profileRelayTestServer(t)
	s.setVia(viaTUN)
	for _, failure := range []error{errors.New("Pipe couldn't find the physical network for this test."), context.DeadlineExceeded} {
		helper.probeProfile = func(context.Context, clientctl.ProbeOptions) (clientctl.ProfileTestResult, error) {
			return clientctl.ProfileTestResult{}, failure
		}
		w := request("POST", "/api/profiles/phone/test", "")
		var reply map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != http.StatusInternalServerError ||
			reply["error"] == nil || reply["routes"] != nil {
			t.Fatalf("helper failure returned %d %s", w.Code, w.Body)
		}
	}
}

func TestProfileProbeSetupFailurePreservesMeasurement(t *testing.T) {
	s, _, _, request := profileRelayTestServer(t)
	s.cfg.probeProfile = func(context.Context, clientctl.ProbeOptions) clientctl.ProfileTestResult {
		return clientctl.ProfileTestResult{MetricVersion: clientctl.RTTMetricVersion,
			Routes: map[string]clientctl.RouteLatency{"fast": {Ms: 42, OK: true}}}
	}
	const path = "/api/profiles/phone/test"
	if w := request("POST", path, ""); w.Code != http.StatusOK {
		t.Fatalf("initial measurement returned %d %s", w.Code, w.Body)
	}
	before := s.store.Snapshot().Measurements["phone"].profileTestResponse
	s.cfg.probeProfile = func(ctx context.Context, opts clientctl.ProbeOptions) clientctl.ProfileTestResult {
		opts.Profile.Host = "" // Fail real probe setup before creating or dialing an engine.
		return clientctl.TestProfile(ctx, opts)
	}
	if w := request("POST", path, ""); w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), `"routes"`) || !strings.Contains(w.Body.String(), "Could not configure") {
		t.Errorf("setup failure returned %d %s", w.Code, w.Body)
	}
	after := openStore(s.store.path, s.profiles).Snapshot().Measurements["phone"].profileTestResponse
	if !after.CompletedAt.Equal(before.CompletedAt) || !maps.Equal(after.Routes, before.Routes) {
		t.Fatal("local setup failure replaced the saved measurement")
	}
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
	s.cfg.probeProfile = func(ctx context.Context, opts clientctl.ProbeOptions) clientctl.ProfileTestResult {
		started <- opts.Profile.Name
		<-ctx.Done()
		if opts.Profile.Name == "phone" && firstPhone.CompareAndSwap(false, true) {
			close(closing)
			<-release
		}
		return clientctl.ProfileTestResult{}
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
