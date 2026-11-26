// SPDX-License-Identifier: GPL-3.0-or-later

package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"pipe/internal/engine"
	"pipe/internal/link"
	"pipe/internal/sysdns"
	"pipe/internal/update"
)

func sampleProfile(t *testing.T) (string, link.Profile) {
	t.Helper()
	profile := link.Profile{
		Name: "Phone", Host: "origin.example", CDN: "cdn.example", WSPath: "/private-path",
		SubID: "private-subscription", Seed: [32]byte{1, 2, 3}, PublicKey: [32]byte{4, 5, 6},
	}
	raw, err := profile.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw, profile
}

func TestParseLinkPublicSummary(t *testing.T) {
	raw, profile := sampleProfile(t)
	summary, err := ParseLink(raw)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal([]byte(summary), &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 4 || fields["name"] != profile.Name || fields["domain"] != profile.Host ||
		fields["cdn"] != profile.CDN || !strings.HasPrefix(fields["keyFingerprint"], "SHA-256 ") {
		t.Fatalf("unexpected public summary fields %v", fields)
	}
	for _, secret := range []string{link.EncodeKey(profile.Seed), profile.SubID, profile.WSPath, raw, link.EncodeKey(profile.PublicKey)} {
		if strings.Contains(summary, secret) {
			t.Fatal("summary exposed sensitive profile data")
		}
	}
	if result, err := ParseLink(raw + "\n?invalid"); err == nil || result != "" || strings.Contains(err.Error(), link.EncodeKey(profile.Seed)) {
		t.Fatal("invalid link exposed sensitive profile data")
	}
}

func TestParseLinkShowsCustomPorts(t *testing.T) {
	_, profile := sampleProfile(t)
	profile.Port, profile.CDNPort = 8443, 2053
	raw, err := profile.Encode()
	if err != nil {
		t.Fatal(err)
	}
	summary, err := ParseLink(raw)
	if err != nil {
		t.Fatal(err)
	}
	var fields linkSummary
	if err := json.Unmarshal([]byte(summary), &fields); err != nil || fields.Domain != "origin.example:8443" || fields.CDN != "cdn.example:2053" {
		t.Fatalf("custom endpoints = %q and %q, %v", fields.Domain, fields.CDN, err)
	}
}

func TestParseLinkShowsSharedEndpoints(t *testing.T) {
	_, profile := sampleProfile(t)
	profile.FastPort, profile.StealthPort = 14443, 8443
	profile.FastSNI, profile.RealitySNI = "fast.example", "cover.example"
	raw, err := profile.Encode()
	if err != nil {
		t.Fatal(err)
	}
	summary, err := ParseLink(raw)
	if err != nil {
		t.Fatal(err)
	}
	var fields linkSummary
	if err := json.Unmarshal([]byte(summary), &fields); err != nil ||
		fields.FastEndpoint != "origin.example:14443 (TLS name fast.example)" ||
		fields.StealthEndpoint != "origin.example:8443 (TLS name cover.example)" {
		t.Fatalf("wrong confirmation endpoints: %v", err)
	}
}

func TestUnavailableSavedRescueUsesAuto(t *testing.T) {
	_, profile := sampleProfile(t)
	profile.CDN, profile.WSPath = "", ""
	next, err := prepareProfile(&profile, `{"tier":"rescue"}`)
	if err != nil || next.client.Tier != "auto" {
		t.Fatalf("saved Rescue for a non-CDN profile: %q, %v", next.client.Tier, err)
	}
}

func TestNetworkClientOptionsFollowsNetworkAndUserPreference(t *testing.T) {
	raw, _ := sampleProfile(t)
	next, err := prepare(raw, `{"ipv6":true}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		netIPv6  bool
		wantDial bool
		wantTun  bool
	}{
		{name: "IPv4-only network"},
		{name: "IPv6 network", netIPv6: true, wantDial: true, wantTun: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := networkClientOptions(next.client, test.netIPv6)
			if got.IPv6 != test.wantDial || got.TUNIPv6 != test.wantTun {
				t.Fatalf("network options = (dial IPv6 %v, TUN IPv6 %v), want (%v, %v)",
					got.IPv6, got.TUNIPv6, test.wantDial, test.wantTun)
			}
		})
	}
	next, err = prepare(raw, `{"ipv6":false}`)
	if err != nil {
		t.Fatal(err)
	}
	got := networkClientOptions(next.client, true)
	if got.IPv6 || !got.TUNIPv6 {
		t.Fatal("the IPv6 preference disabled TUN capture or enabled Pipe's IPv6 dials")
	}
}

func TestVPNNetworkIPv6FlipRebuildsAndNoFlipRefreshes(t *testing.T) {
	raw, _ := sampleProfile(t)
	platform := &fakePlatform{
		statuses: make(chan string, 32),
		network:  `{"defaultInterface":"wlan0","defaultIPv6Route":false,"defaultAddresses":["192.0.2.4/24"],"interfaces":[]}`,
	}
	var instances []*fakeEngine
	b := bridge{newEngine: func(_ context.Context, opts engine.Options) (clientEngine, error) {
		instance := &fakeEngine{options: opts}
		instances = append(instances, instance)
		return instance, nil
	}}
	defer b.stop()
	if err := b.start(raw, `{"tier":"fast","ipv6":false}`, platform); err != nil {
		t.Fatal(err)
	}
	if b.active.netIPv6 || !slices.Equal(tunAddresses(instances[0].options), []string{"172.19.0.1/30"}) {
		t.Fatal("an IPv4-only default network enabled IPv6 in the TUN")
	}

	platform.network = `{"defaultInterface":"wlan0","defaultIPv6Route":true,"defaultAddresses":["192.0.2.4/24","fd12:3456::1/64"],"interfaces":[]}`
	b.networkChanged(false)
	if len(instances) != 2 || !instances[0].closed || !b.active.netIPv6 {
		t.Fatal("an IPv6 availability flip did not replace the session")
	}
	if !slices.Equal(tunAddresses(instances[1].options), []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}) {
		t.Fatal("the IPv6 network did not add IPv6 to the TUN")
	}
	dns := instances[1].options.Config["dns"].(engine.Object)
	if dns["strategy"] != "ipv4_only" {
		t.Fatal("the user's IPv6 preference did not keep Pipe DNS IPv4-only")
	}

	platform.network = `{"defaultInterface":"wlan0","defaultIPv6Route":true,"defaultAddresses":["192.0.2.4/24","fd12:3456::2/64"],"interfaces":[]}`
	b.networkChanged(false)
	if len(instances) != 2 || platform.opened != 2 || instances[1].closed ||
		instances[1].refreshes != 1 || instances[1].resets != 0 {
		t.Fatal("replacing the IPv6 address should refresh without reopening the TUN or resetting flows")
	}

	// Offline is not "no IPv6": the TUN stays and the engine only refreshes.
	platform.network = `{"defaultInterface":"","interfaces":[]}`
	b.networkChanged(true)
	if len(instances) != 2 || !b.active.netIPv6 || instances[1].refreshes != 2 {
		t.Fatal("going offline swapped the TUN")
	}
}

func TestMobileSessionUsesLiveLANDNSServers(t *testing.T) {
	raw, _ := sampleProfile(t)
	platform := &fakePlatform{
		statuses: make(chan string, 32),
		network: `{"defaultInterface":"wlan0","interfaces":[{"name":"wlan0","dns":[
			"fe80::53%wlan0","192.168.1.1","invalid","172.19.0.1","` + sysdns.TUNDNSAddress + `"]}]}`,
	}
	var instances []*fakeEngine
	b := bridge{newEngine: func(_ context.Context, opts engine.Options) (clientEngine, error) {
		instance := &fakeEngine{options: opts}
		instances = append(instances, instance)
		return instance, nil
	}}
	defer b.stop()
	if err := b.start(raw, `{"tier":"fast"}`, platform); err != nil {
		t.Fatal(err)
	}
	options := instances[0].options
	if options.LANDNSServers == nil {
		t.Fatal("mobile session did not install a LAN DNS provider")
	}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("[fe80::53%wlan0]:53"),
		netip.MustParseAddrPort("192.168.1.1:53"),
	}
	if got := options.LANDNSServers(); !slices.Equal(got, want) {
		t.Fatalf("mobile LAN DNS servers = %v, want %v", got, want)
	}
	dns := options.Config["dns"].(engine.Object)
	servers := dns["servers"].([]engine.Object)
	foundLAN, foundMDNSSplit := false, false
	for _, server := range servers {
		if server["tag"] == "private-local" {
			foundLAN = server["type"] == engine.LANDNSType
		}
		foundMDNSSplit = foundMDNSSplit || server["tag"] == "local-mdns"
	}
	wantMDNSSplit := runtime.GOOS == "darwin"
	if !foundLAN || foundMDNSSplit != wantMDNSSplit {
		t.Fatalf("mobile private DNS transport or mDNS behavior changed: %v", servers)
	}

	platform.network = `{"defaultInterface":"rmnet0","interfaces":[{"name":"rmnet0","dns":["fe80::53%rmnet0","10.0.0.53"]}]}`
	b.networkChanged(false)
	if len(instances) != 1 || instances[0].refreshes != 1 {
		t.Fatal("changing DNS servers rebuilt the mobile session")
	}
	want = []netip.AddrPort{
		netip.MustParseAddrPort("[fe80::53%rmnet0]:53"),
		netip.MustParseAddrPort("10.0.0.53:53"),
	}
	if got := options.LANDNSServers(); !slices.Equal(got, want) {
		t.Fatalf("LAN DNS provider did not follow the handoff: %v", got)
	}
	for _, state := range []string{
		`{}`,
		`{"defaultInterface":"unknown","interfaces":[{"name":"wlan0","dns":["192.168.1.1"]}]}`,
	} {
		platform.network = state
		if got := options.LANDNSServers(); len(got) != 0 {
			t.Fatalf("unexpected LAN DNS servers for %q: %v", state, got)
		}
	}
}

func tunAddresses(options engine.Options) []string {
	inbounds := options.Config["inbounds"].([]engine.Object)
	return inbounds[0]["address"].([]string)
}

func TestTestOptionsAreBuildGated(t *testing.T) {
	raw, _ := sampleProfile(t)
	prepared, err := prepare(raw, `{"test":{"address":"10.0.2.2","caFile":"/private/ca.pem"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if enableTestHooks {
		if prepared.client.TestAddress.String() != "10.0.2.2" || prepared.client.TestCAFile != "/private/ca.pem" {
			t.Fatal("debug build did not load the test options")
		}
		if _, err := prepare(raw, `{"test":{"address":"8.8.8.8","caFile":"ca.pem"}}`); err == nil {
			t.Fatal("debug build accepted a public test address")
		}
	} else {
		if prepared.client.TestAddress.IsValid() || prepared.client.TestCAFile != "" {
			t.Fatal("release build accepted the test options")
		}
		if _, err := prepare(raw, `{"test":"ignored in release"}`); err != nil {
			t.Fatal("release build parsed the test block")
		}
	}
}

func TestVPNStartCancelsPreviouslySelectedDirectUpdate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		profile, _ := sampleProfile(t)
		platform := &fakePlatform{statuses: make(chan string, 16)}
		b := &bridge{}
		// An unsupported ABI keeps the fixture offline even on regression.
		u := b.newUpdates(t.TempDir(), "fixture")
		defer u.manager.Close()
		u.CancelDirect()
		selected, continueCheck := make(chan struct{}), make(chan struct{})
		resumeCheck := sync.OnceFunc(func() { close(continueCheck) })
		defer resumeCheck()
		u.manager.CheckWithRoute(func() update.Route {
			route := b.updateRoute(false)
			close(selected)
			<-continueCheck
			return route
		}, false)
		<-selected
		b.newEngine = func(_ context.Context, opts engine.Options) (clientEngine, error) {
			resumeCheck()
			synctest.Wait()
			if st := u.manager.Status(); st.State != "error" || st.Error != "The update was cancelled." || st.CheckedAt != nil {
				t.Errorf("selected direct update survived VPN startup: %+v", st)
			}
			return &fakeEngine{options: opts}, nil
		}
		if err := b.start(profile, `{}`, platform); err != nil {
			t.Fatal(err)
		}
		defer b.stop()
		if b.starting {
			t.Fatal("VPN still reports startup after Start returned")
		}
	})
}

func TestVPNLifecycleWithFakePlatform(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw, _ := sampleProfile(t)
		platform := &fakePlatform{statuses: make(chan string, 256)}
		var instances []*fakeEngine
		b := bridge{newEngine: func(_ context.Context, opts engine.Options) (clientEngine, error) {
			instance := &fakeEngine{options: opts, probed: make(chan string, 8)}
			instances = append(instances, instance)
			return instance, nil
		}}
		defer b.stop()
		if err := b.start(raw, `{"tier":"stealth","ipv6":false,"perApp":{"mode":"only","packages":["org.example"]}}`, platform); err != nil {
			t.Fatal(err)
		}
		instance := instances[0]
		if platform.opened != 1 || instance.options.VPN.PerApp != "only" || !slices.Equal(instance.options.VPN.Packages, []string{"org.example"}) {
			t.Fatal("VPN preferences did not reach the platform")
		}
		inbound := instance.options.Config["inbounds"].([]engine.Object)[0]
		if inbound["stack"] != "gvisor" || inbound["mtu"] != 9000 || len(inbound["address"].([]string)) != 1 {
			t.Fatal("unexpected Android TUN options")
		}
		if err := b.setTier("fast"); err != nil || len(instances) != 1 || !slices.Equal(instance.selected, []string{"fast"}) {
			t.Fatalf("tier switch did not reuse the engine: %v", err)
		}
		synctest.Wait()
		if len(instance.probed) != 1 || <-instance.probed != "stealth" {
			t.Fatal("expected exactly one connect-time probe of the active tier")
		}
		instance.options.VPN.CountBytes(100, 200)
		time.Sleep(time.Second)
		synctest.Wait()
		status := testStatus(t, b.statusJSON())
		if !status.Running || status.Tier != "fast" || status.UpBytes != 100 || status.DownBytes != 200 || status.DownRate != 200 {
			t.Fatalf("unexpected running status: %+v", status)
		}
		if err := b.setTier("auto"); err != nil {
			t.Fatal(err)
		}
		instance.options.ObserveTraffic()
		synctest.Wait()
		if len(instance.probed) != 1 || <-instance.probed != "fast" {
			t.Fatal("first automatic traffic should check only the active tier")
		}
		b.networkChanged(false)
		synctest.Wait()
		if len(instance.probed) != 0 {
			t.Fatal("baseline triggered failover probes")
		}
		b.networkChanged(true)
		synctest.Wait()
		if instance.resets != 1 || len(instance.probed) != 3 {
			t.Fatal("network change did not refresh the engine and reset automatic tiers")
		}
		for len(instance.probed) > 0 {
			<-instance.probed
		}
		instance.offline = true
		b.networkChanged(true)
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if instance.resets != 1 || len(instance.probed) != 0 {
			t.Fatal("offline transition caused a network reset or a probe")
		}
		if err := b.setMode("direct"); err != nil || len(instances) != 2 || !instance.closed || !testStatus(t, b.statusJSON()).Running {
			t.Fatalf("mode change did not reopen the VPN: %v", err)
		}
		b.stop()
		b.stop()
		if !instances[1].closed || testStatus(t, b.statusJSON()).Running {
			t.Fatal("VPN did not close cleanly")
		}
		synctest.Wait()
		var final string
		for len(platform.statuses) > 0 {
			final = <-platform.statuses
		}
		if testStatus(t, final).Running {
			t.Fatal("platform did not receive stopped status")
		}
	})
}

func TestVPNReplacesTunnelBeforeClosingPreviousEngine(t *testing.T) {
	raw, _ := sampleProfile(t)
	platform := &fakePlatform{statuses: make(chan string, 32)}
	var events []string
	var count int
	b := bridge{newEngine: func(_ context.Context, opts engine.Options) (clientEngine, error) {
		step := []string{"original", "rejected", "broken", "restored", "replacement"}[count]
		count++
		return &fakeEngine{
			options: opts,
			onStart: func() error {
				events = append(events, "start "+step)
				if step == "rejected" {
					return errors.New("failed before establish")
				}
				return nil
			},
			onEstablished: func() error {
				events = append(events, "establish "+step)
				if step == "broken" {
					return errors.New("failed after establish")
				}
				return nil
			},
			onClose:      func() { events = append(events, "close "+step) },
			onReleaseTun: func() { events = append(events, "release "+step) },
		}, nil
	}}
	defer b.stop()
	if err := b.start(raw, `{"tier":"fast"}`, platform); err != nil {
		t.Fatal(err)
	}
	if err := b.setMode("direct"); err == nil || testStatus(t, b.statusJSON()).Mode != "smart" {
		t.Fatal("pre-establishment failure changed the running mode")
	}
	if testStatus(t, b.statusJSON()).LastError != "" {
		t.Fatal("rejected replacement left an error on the healthy VPN")
	}
	if err := b.applyPreferences(`{"mode":"global","tier":"fast","ipv6":false}`); err == nil ||
		!testStatus(t, b.statusJSON()).Running || testStatus(t, b.statusJSON()).Mode != "smart" {
		t.Fatal("post-establishment failure did not restore the previous mode")
	}
	if testStatus(t, b.statusJSON()).LastError != "" {
		t.Fatal("rollback left an error on the restored VPN")
	}
	if err := b.applyPreferences(`{"mode":"direct","tier":"fast","ipv6":false,"perApp":{"mode":"only","packages":["org.example"]}}`); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"start original", "establish original",
		"start rejected", "close rejected",
		"start broken", "establish broken", "close broken",
		"start restored", "establish restored", "close original", "release original", "release broken",
		"start replacement", "establish replacement", "close restored", "release restored",
	}
	if !slices.Equal(events, want) || b.active.client.IPv6 || b.active.apps.Mode != "only" ||
		testStatus(t, b.statusJSON()).Mode != "direct" {
		t.Fatalf("unexpected replacement sequence: %v", events)
	}
}

func TestVPNFailedRollbackHoldsTunnelUntilExplicitStop(t *testing.T) {
	raw, _ := sampleProfile(t)
	platform := &fakePlatform{statuses: make(chan string, 32)}
	var opened, released int
	var starts int
	b := bridge{newEngine: func(_ context.Context, opts engine.Options) (clientEngine, error) {
		starts++
		attempt := starts
		return &fakeEngine{
			options: opts,
			onStart: func() error {
				if attempt == 3 {
					if released != 0 {
						t.Fatal("the failed replacement TUN closed before rollback")
					}
					return errors.New("restore could not start")
				}
				return nil
			},
			onEstablished: func() error {
				opened++
				if attempt == 2 {
					return errors.New("replacement failed after establish")
				}
				return nil
			},
			onReleaseTun: func() {
				if attempt == 2 {
					released++
				}
			},
		}, nil
	}}
	defer b.stop()
	if err := b.start(raw, `{"tier":"fast"}`, platform); err != nil {
		t.Fatal(err)
	}
	err := b.setMode("global")
	status := testStatus(t, b.statusJSON())
	if err == nil || status.Running || !status.Blocked || status.LastError == "" || opened != 2 || released != 0 {
		t.Fatalf("failed rollback did not retain protection: status=%+v, opened=%d, released=%d", status, opened, released)
	}
	b.stop()
	if released != 1 || testStatus(t, b.statusJSON()).Blocked {
		t.Fatalf("explicit Stop did not release the retained TUN: %d releases", released)
	}
}

func TestVPNStopWaitsForStatusCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw, _ := sampleProfile(t)
		platform := &fakePlatform{statuses: make(chan string)}
		b := bridge{newEngine: func(_ context.Context, opts engine.Options) (clientEngine, error) {
			return &fakeEngine{options: opts}, nil
		}}
		if err := b.start(raw, `{"tier":"fast"}`, platform); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		stopped := make(chan struct{})
		go func() {
			b.stop()
			close(stopped)
		}()
		synctest.Wait()
		if !testStatus(t, b.statusJSON()).Running || !testStatus(t, <-platform.statuses).Running {
			t.Fatal("Stop discarded the in-flight status callback")
		}
		if testStatus(t, <-platform.statuses).Running {
			t.Fatal("final status still indicates that VPN is running")
		}
		<-stopped
	})
}

func TestEngineErrorsDoNotExposeCredentials(t *testing.T) {
	raw, profile := sampleProfile(t)
	platform := &fakePlatform{}
	b := bridge{newEngine: func(context.Context, engine.Options) (clientEngine, error) {
		return nil, errors.New(raw)
	}}
	err := b.start(raw, "{}", platform)
	if err == nil || strings.Contains(err.Error(), link.EncodeKey(profile.Seed)) || strings.Contains(b.statusJSON(), link.EncodeKey(profile.Seed)) {
		t.Fatal("engine failure exposed the link secret")
	}
}

func testStatus(t *testing.T, raw string) vpnStatus {
	t.Helper()
	var status vpnStatus
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		t.Fatal(err)
	}
	return status
}

type fakePlatform struct {
	opened   int
	statuses chan string
	network  string
}

func (p *fakePlatform) OpenTun(string) (int32, error) { p.opened++; return 10, nil }
func (p *fakePlatform) Protect(int32) bool            { return true }
func (p *fakePlatform) NetworkState() string {
	if p.network == "" {
		return "{}"
	}
	return p.network
}
func (p *fakePlatform) OnStatus(json string) { p.statuses <- json }

type fakeEngine struct {
	options       engine.Options
	probed        chan string
	selected      []string
	resets        int
	refreshes     int
	offline       bool
	closed        bool
	onStart       func() error
	onEstablished func() error
	onClose       func()
	onReleaseTun  func()
	blockProbe    bool
}

func (e *fakeEngine) Start() error {
	if e.onStart != nil {
		if err := e.onStart(); err != nil {
			return err
		}
	}
	_, err := e.options.VPN.Platform.OpenTun("{}")
	if err != nil {
		return err
	}
	if hold := e.options.VPN.HoldTun; hold != nil {
		hold(func() {
			if e.onReleaseTun != nil {
				e.onReleaseTun()
			}
		})
	}
	if e.onEstablished != nil {
		return e.onEstablished()
	}
	return nil
}

func (e *fakeEngine) Close() error {
	e.closed = true
	if e.onClose != nil {
		e.onClose()
	}
	return nil
}
func (e *fakeEngine) SelectTier(tier string) error { e.selected = append(e.selected, tier); return nil }
func (e *fakeEngine) RelayState(string) string     { return "" }
func (e *fakeEngine) VPNOnline() bool              { return !e.offline }
func (e *fakeEngine) RefreshVPNNetwork(reset bool) (bool, error) {
	e.refreshes++
	if reset && !e.offline {
		e.resets++
	}
	return !e.offline, nil
}
func (e *fakeEngine) Probe(_ context.Context, tier string, _ bool) (bool, error) {
	if e.probed != nil {
		e.probed <- tier
	}
	return false, nil
}

func (e *fakeEngine) ProbeLatency(ctx context.Context, tier string, burst bool) (bool, time.Duration, bool, error) {
	if e.blockProbe {
		<-ctx.Done()
		if e.closed {
			panic("probe outlived engine.Close")
		}
		return false, 0, false, ctx.Err()
	}
	stalled, err := e.Probe(ctx, tier, burst)
	return stalled, 7 * time.Millisecond, false, err
}

func (e *fakeEngine) MeasureRTT(ctx context.Context, tier string) (time.Duration, bool, error) {
	_, latency, via, err := e.ProbeLatency(ctx, tier, false)
	return latency, via, err
}
