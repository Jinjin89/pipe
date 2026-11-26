// SPDX-License-Identifier: GPL-3.0-or-later

package mobile

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"testing/synctest"

	"pipe/internal/config"
	"pipe/internal/engine"
	"pipe/internal/version"
)

func TestPreferencesRulesAndLogLevel(t *testing.T) {
	raw, _ := sampleProfile(t)
	prefs := `{"logLevel":"info","rules":[
		{"type":"domain","value":"Example.com","action":"proxy"},
		{"type":"suffix","value":"example.org","action":"direct"},
		{"type":"keyword","value":"ads","action":"block"},
		{"type":"ip","value":"192.0.2.0/24","action":"direct"}]}`
	next, err := prepare(raw, prefs)
	if err != nil {
		t.Fatal(err)
	}
	want := []config.Rule{
		{Field: "domain", Match: "example.com", Action: "proxy"},
		{Field: "domain_suffix", Match: "example.org", Action: "direct"},
		{Field: "domain_keyword", Match: "ads", Action: "block"},
		{Field: "ip_cidr", Match: "192.0.2.0/24", Action: "direct"},
	}
	if next.client.LogLevel != "info" || len(next.client.Rules) != len(want) {
		t.Fatalf("got %+v", next.client)
	}
	for i := range want {
		if next.client.Rules[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, next.client.Rules[i], want[i])
		}
	}
	for _, bad := range []string{
		`{"rules":[{"type":"regex","value":"x","action":"proxy"}]}`,
		`{"rules":[{"type":"domain","value":"example.com","action":"maybe"}]}`,
		`{"logLevel":"trace"}`,
		`{"rules":[{"type":"app","value":"org.example.app","action":"proxy"}]}`,
	} {
		if _, err := prepare(raw, bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestDirectModeKeepsRulesButDoesNotUseThem(t *testing.T) {
	raw, _ := sampleProfile(t)
	next, err := prepare(raw, `{"mode":"direct","rules":[{"type":"domain","value":"example.com","action":"proxy"}]}`)
	if err != nil || len(next.client.Rules) != 1 {
		t.Fatalf("%+v, %v", next.client.Rules, err)
	}
	synctest.Test(t, func(t *testing.T) {
		var instances []*fakeEngine
		b := bridge{newEngine: func(_ context.Context, opts engine.Options) (clientEngine, error) {
			instance := &fakeEngine{options: opts, probed: make(chan string, 16)}
			instances = append(instances, instance)
			return instance, nil
		}}
		defer b.stop()
		platform := &fakePlatform{statuses: make(chan string, 256)}
		if err := b.start(raw, `{"mode":"direct","rules":[{"type":"domain","value":"example.com","action":"proxy"}]}`, platform); err != nil {
			t.Fatal(err)
		}
		hasRule := func(e *fakeEngine) bool {
			for _, r := range e.options.Config["route"].(engine.Object)["rules"].([]engine.Object) {
				if r["domain"] == "example.com" {
					return true
				}
			}
			return false
		}
		if hasRule(instances[0]) {
			t.Fatal("direct mode used a rule")
		}
		if err := b.setMode("smart"); err != nil || !hasRule(instances[1]) {
			t.Fatalf("rules lost after direct -> smart: %v", err)
		}
	})
}

func TestStopDuringTestRoutes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw, _ := sampleProfile(t)
		var instance *fakeEngine
		b := bridge{newEngine: func(_ context.Context, opts engine.Options) (clientEngine, error) {
			instance = &fakeEngine{options: opts, probed: make(chan string, 16), blockProbe: true}
			return instance, nil
		}}
		platform := &fakePlatform{statuses: make(chan string, 256)}
		if err := b.start(raw, `{}`, platform); err != nil {
			t.Fatal(err)
		}
		done := make(chan string)
		go func() { done <- b.testRoutes() }()
		synctest.Wait()
		b.stop()
		select {
		case <-done:
		default:
			synctest.Wait()
			<-done
		}
		if !instance.closed {
			t.Fatal("engine not closed")
		}
	})
}

func TestRuleValuesMustMatchType(t *testing.T) {
	raw, _ := sampleProfile(t)
	for _, rule := range []string{
		`{"type":"domain","value":"app:com.foo","action":"proxy"}`,
		`{"type":"domain","value":"process:sh","action":"proxy"}`,
		`{"type":"domain","value":"example.com -> direct","action":"proxy"}`,
		`{"type":"domain","value":"1.2.3.4","action":"proxy"}`,
		`{"type":"ip","value":"example.com","action":"proxy"}`,
		`{"type":"ip","value":"process:sh","action":"proxy"}`,
	} {
		if _, err := prepare(raw, `{"rules":[`+rule+`]}`); err == nil {
			t.Errorf("accepted %s", rule)
		}
	}
	if _, err := prepare(raw, `{"rules":[{"type":"ip","value":"2001:db8::/32","action":"direct"}]}`); err != nil {
		t.Error(err)
	}
}

func TestLogsReplyIsBounded(t *testing.T) {
	ClearLogs()
	for i := 0; i < 500; i++ {
		logs.Add("info", "core", strings.Repeat("x", 2000))
	}
	if reply := Logs(0); len(reply) > 64*1024 || !strings.Contains(reply, `"entries":[{`) {
		t.Fatalf("reply %d bytes", len(reply))
	}
	ClearLogs()
}

func TestStatusLatencyRoutesAndRulesApply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw, _ := sampleProfile(t)
		platform := &fakePlatform{statuses: make(chan string, 256)}
		var instances []*fakeEngine
		b := bridge{newEngine: func(_ context.Context, opts engine.Options) (clientEngine, error) {
			instance := &fakeEngine{options: opts, probed: make(chan string, 16)}
			instances = append(instances, instance)
			return instance, nil
		}}
		defer b.stop()
		if err := b.start(raw, `{}`, platform); err != nil {
			t.Fatal(err)
		}
		status := testStatus(t, b.statusJSON())
		// The connect probe runs in the background, so latency may already be set.
		if status.ConnectedSince == 0 || (status.LatencyMs != nil && *status.LatencyMs != 7) || status.Routes == nil {
			t.Fatalf("fresh status %+v", status)
		}
		if instances[0].options.LogWriter == nil {
			t.Fatal("engine log writer not wired")
		}
		var routes map[string]routeLatency
		if err := json.Unmarshal([]byte(b.testRoutes()), &routes); err != nil || len(routes) != 3 || !routes["fast"].OK || routes["fast"].Ms != 7 {
			t.Fatalf("routes %v, %v", routes, err)
		}
		status = testStatus(t, b.statusJSON())
		if status.LatencyMs == nil || *status.LatencyMs != 7 || len(status.Routes) != 3 {
			t.Fatalf("status after test %+v", status)
		}
		since := status.ConnectedSince
		prefs := `{"rules":[{"type":"domain","value":"example.com","action":"direct"}],"logLevel":"info"}`
		if err := b.applyPreferences(prefs); err != nil || len(instances) != 2 {
			t.Fatalf("rules did not rebuild: %v", err)
		}
		if err := b.applyPreferences(prefs); err != nil || len(instances) != 2 {
			t.Fatalf("identical prefs rebuilt: %v", err)
		}
		if got := testStatus(t, b.statusJSON()); got.ConnectedSince != since || (got.LatencyMs != nil && *got.LatencyMs != 7) {
			t.Fatalf("after replace %+v", got)
		}
		b.stop()
		if got := testStatus(t, b.statusJSON()); got.ConnectedSince != 0 || got.LatencyMs != nil || len(got.Routes) != 0 {
			t.Fatalf("after stop %+v", got)
		}
	})
}

func TestLogsClearVersion(t *testing.T) {
	ClearLogs()
	logs.Add("info", "pipe", "hello")
	var out struct {
		Next    int64 `json:"next"`
		Entries []struct {
			Seq     int64  `json:"seq"`
			Message string `json:"message"`
			Source  string `json:"source"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(Logs(0)), &out); err != nil || len(out.Entries) != 1 || out.Entries[0].Message != "hello" || out.Next != out.Entries[0].Seq {
		t.Fatalf("logs %+v, %v", out, err)
	}
	first := out.Next
	if err := json.Unmarshal([]byte(Logs(first)), &out); err != nil || len(out.Entries) != 0 || out.Next != first {
		t.Fatalf("poll %+v", out)
	}
	ClearLogs()
	if err := json.Unmarshal([]byte(Logs(0)), &out); err != nil || len(out.Entries) != 0 || !strings.Contains(Logs(0), `"entries":[]`) {
		t.Fatalf("clear %+v", out)
	}
	if Version() != version.Version || version.Version != "0.7.5-alpha" {
		t.Fatal(Version())
	}
	if Status() == "" {
		t.Fatal("status")
	}
}

func TestValidateRuleAndMaxRules(t *testing.T) {
	if MaxRules() != 500 {
		t.Fatal(MaxRules())
	}
	if msg := ValidateRule("domain", "example.com", "proxy"); msg != "" {
		t.Fatal(msg)
	}
	for _, c := range [][3]string{
		{"domain", "app:x", "proxy"}, {"domain", "a.com -> direct", "proxy"}, {"ip", "example.com", "proxy"},
		{"domain", "1.2.3.4", "proxy"}, {"regex", "x", "proxy"}, {"domain", "example.com", "maybe"},
	} {
		if ValidateRule(c[0], c[1], c[2]) == "" {
			t.Errorf("accepted %v", c)
		}
	}
}
