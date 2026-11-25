// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pipe/internal/helper"
	"pipe/internal/link"
	"pipe/internal/logring"
	"pipe/internal/sysproxy"
)

func TestProfileRelayStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.json")
	store := OpenStore(path)
	want := ProfileRelay{Code: "[2001:db8::9]:8444/30000-39999", On: true}
	if err := store.Update(func(d *appData) { d.setRelay("phone", want) }); err != nil {
		t.Fatal(err)
	}
	loaded := OpenStore(path).Snapshot()
	if got := loaded.Relays["phone"]; got != want {
		t.Fatalf("loaded relay = %+v, want %+v", got, want)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Relays map[string]struct {
			Host string `json:"host"`
		} `json:"relays"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil || wire.Relays["phone"].Host != want.Code {
		t.Fatalf("saved relay code in host field = %q (%v)", wire.Relays["phone"].Host, err)
	}
	snapshot := store.Snapshot()
	delete(snapshot.Relays, "phone")
	if got := store.Snapshot().Relays["phone"]; got != want {
		t.Fatalf("snapshot changed stored relay to %+v", got)
	}
}

func TestProfileRelayStoreLoadsOlderData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.json")
	old := `{"active":"phone","mode":"global","tier":"stealth","settings":{"listenPort":8989}}`
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	got := OpenStore(path).Snapshot()
	if len(got.Relays) != 0 || got.Active != "phone" || got.Mode != "global" || got.Tier != "stealth" || got.Settings.ListenPort != 8989 {
		t.Fatalf("older app data loaded as %+v", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != old {
		t.Fatalf("loading rewrote app data as %s (%v)", raw, err)
	}
}

func TestProfileRelayStoreSanitizesOnLoad(t *testing.T) {
	dir := t.TempDir()
	profiles := NewProfiles(filepath.Join(dir, "profiles"))
	for _, name := range []string{"phone", "bad-host", "self"} {
		if _, err := profiles.Save(name, link.Profile{Host: "example.com", Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "app.json")
	store := OpenStore(path)
	want := ProfileRelay{Code: "relay.example/444", On: false}
	err := store.Update(func(d *appData) {
		d.Relays = map[string]ProfileRelay{
			"phone":    want,
			"self":     {Code: "example.com:8444/444", On: true},
			"bad-host": {Code: "relay.example:0", On: true},
			"missing":  {Code: "relay.example", On: true},
			"../other": {Code: "relay.example", On: true},
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := openStore(path, profiles).Snapshot().Relays; len(got) != 1 || got["phone"] != want {
		t.Fatalf("sanitized relays = %+v", got)
	}
}

func TestProfileRelayAPIValidationAndLifecycle(t *testing.T) {
	s, _, _, request := profileRelayTestServer(t)
	for _, body := range []string{
		`{"host":"https://relay.example","on":true}`,
		`{"host":"relay.example:0","on":false}`,
		`{"host":"relay.example:8444/444,30000-39999","on":true}`,
		`{"host":"example.com:8444/444","on":true}`,
		`{"host":"","on":true}`,
		`{"host":" \t ","on":true}`,
		`{"host":"relay .example","on":true}`,
	} {
		if w := request("PUT", "/api/profiles/phone/relay", body); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid relay %s returned %d %s", body, w.Code, w.Body)
		}
	}
	if got := s.store.Snapshot().Relays; len(got) != 0 {
		t.Fatalf("invalid relay was stored: %v", got)
	}
	if w := request("PUT", "/api/profiles/missing/relay", `{"host":"relay.example","on":true}`); w.Code != http.StatusNotFound {
		t.Fatalf("missing profile returned %d %s", w.Code, w.Body)
	}
	if w := request("PUT", "/api/profiles/PHONE/relay", `{"host":" \t[2001:0db8:0:0:0:0:0:9]:8444/30000-39999 \n","on":true}`); w.Code != http.StatusOK {
		t.Fatalf("valid relay returned %d %s", w.Code, w.Body)
	}
	w := request("GET", "/api/profiles", "")
	var list struct {
		Profiles []ProfileInfo `json:"profiles"`
	}
	want := ProfileRelay{Code: "[2001:db8::9]:8444/30000-39999", On: true}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Profiles) != 1 || list.Profiles[0].Relay != want {
		t.Fatalf("GET profiles relay = %s (%v)", w.Body, err)
	}
	if w := request("PATCH", "/api/profiles/phone", `{"name":"renamed"}`); w.Code != http.StatusOK {
		t.Fatalf("rename returned %d %s", w.Code, w.Body)
	}
	if got := OpenStore(s.store.path).Snapshot().Relays; len(got) != 1 || got["renamed"] != want {
		t.Fatalf("renaming left relays %+v", got)
	}
	if w := request("DELETE", "/api/profiles/renamed", ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete returned %d %s", w.Code, w.Body)
	}
	if got := OpenStore(s.store.path).Snapshot().Relays; len(got) != 0 {
		t.Fatalf("deleting left relays %+v", got)
	}
}

func TestProfileRelayWhenReplacingLink(t *testing.T) {
	for _, tc := range []struct {
		name, before, after string
		keep                bool
	}{
		{name: "different host", before: "example.com", after: "other.example"},
		{name: "same DNS host", before: "Example.COM", after: "example.com", keep: true},
		{name: "same IPv6 address", before: "2001:0db8:0:0:0:0:0:1", after: "2001:db8::1", keep: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _, request := profileRelayTestServer(t)
			profile := link.Profile{Host: tc.before, Name: "phone", FastSNI: "origin.example"}
			if _, err := s.profiles.Save("phone", profile); err != nil {
				t.Fatal(err)
			}
			if w := request("PUT", "/api/profiles/phone/relay", `{"host":"relay.example","on":true}`); w.Code != http.StatusOK {
				t.Fatalf("set relay returned %d %s", w.Code, w.Body)
			}
			profile.Host = tc.after
			raw, err := profile.Encode()
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(map[string]string{"link": raw, "name": "phone"})
			if err != nil {
				t.Fatal(err)
			}
			w := request("POST", "/api/profiles", string(body))
			if w.Code != http.StatusOK {
				t.Fatalf("replace returned %d %s", w.Code, w.Body)
			}
			var info ProfileInfo
			if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil || info.Server != tc.after {
				t.Fatalf("replacement profile = %s (%v)", w.Body, err)
			}
			want := ProfileRelay{}
			if tc.keep {
				want = ProfileRelay{Code: "relay.example", On: true}
			}
			got := OpenStore(s.store.path).Snapshot().Relays["phone"]
			if info.Relay != want || got != want {
				t.Fatalf("replacement relay = %+v and stored relay = %+v, want %+v", info.Relay, got, want)
			}
		})
	}
}

func TestProfileRelayRemovalFailureKeepsOldLink(t *testing.T) {
	s, _, _, request := profileRelayTestServer(t)
	if w := request("PUT", "/api/profiles/phone/relay", `{"host":"relay.example","on":true}`); w.Code != http.StatusOK {
		t.Fatalf("set relay returned %d %s", w.Code, w.Body)
	}
	oldStorePath := s.store.path
	s.store.path = filepath.Join(oldStorePath, "app.json")
	replacement, err := (link.Profile{Host: "other.example", Name: "phone"}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if w := request("POST", "/api/profiles", `{"link":"`+replacement+`"}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("replace returned %d %s", w.Code, w.Body)
	}
	profile, err := s.profiles.Load("phone")
	if err != nil || profile.Host != "example.com" {
		t.Fatalf("profile after failed relay removal = %q (%v)", profile.Host, err)
	}
	if got := OpenStore(oldStorePath).Snapshot().Relays["phone"]; got != (ProfileRelay{Code: "relay.example", On: true}) {
		t.Fatalf("stored relay after failed removal = %+v", got)
	}
}

func TestProfileRelayConnectAndApply(t *testing.T) {
	for _, mode := range []string{"local", "helper"} {
		t.Run(mode, func(t *testing.T) {
			s, local, h, request := profileRelayTestServer(t)
			ctl := local
			if mode == "helper" {
				ctl = h.fakeCtl
				if err := s.store.Update(func(d *appData) { d.Settings.TUN = true }); err != nil {
					t.Fatal(err)
				}
			}
			save := func(body string) *httptest.ResponseRecorder {
				t.Helper()
				w := request("PUT", "/api/profiles/phone/relay", body)
				if w.Code != http.StatusOK {
					t.Fatalf("save returned %d %s", w.Code, w.Body)
				}
				return w
			}
			const startCode = "relay.example:8443/443"
			const nextCode = "relay.example:8444/30000-39999"
			save(`{"host":"` + startCode + `","on":true}`)
			if w := request("POST", "/api/connect", ""); w.Code != http.StatusOK {
				t.Fatalf("connect returned %d %s", w.Code, w.Body)
			}
			if len(ctl.started) != 1 || ctl.started[0].Relay != startCode || ctl.started[0].TUN != (mode == "helper") {
				t.Fatalf("start options %+v", ctl.started)
			}
			ctl.relayState = "via"
			w := save(`{"host":"` + nextCode + `","on":true}`)
			var result struct {
				Status StatusResponse `json:"status"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Status.RelayState != "via" || result.Status.Relay != "relay.example" {
				t.Fatalf("relay status = %s (%v)", w.Body, err)
			}
			for _, state := range []string{"", "pending", "via", "direct"} {
				ctl.relayState = state
				w := request("GET", "/api/status", "")
				var status map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || status["relay"] != "relay.example" || status["relayState"] != state {
					t.Fatalf("GET status for %q = %s (%v)", state, w.Body, err)
				}
			}
			save(`{"host":"` + nextCode + `","on":true}`)
			save(`{"host":"` + nextCode + `","on":false}`)
			if len(ctl.applied) != 2 || ctl.applied[0].Relay != nextCode || ctl.applied[1].Relay != "" {
				t.Fatalf("applied options %+v", ctl.applied)
			}
			if got := s.store.Snapshot().Relays["phone"]; got.Code != nextCode || got.On {
				t.Fatalf("disabled setting was %+v", got)
			}
		})
	}
}

func TestProfileRelayRequestsHelperUpdate(t *testing.T) {
	for _, stage := range []string{"info", "handshake"} {
		t.Run(stage, func(t *testing.T) {
			s, _, h, request := profileRelayTestServer(t)
			if stage == "info" {
				h.info = helper.Info{State: helper.StateOutdated, Note: helper.ErrOutdated.Error()}
			} else {
				h.failure = helper.ErrOutdated
			}
			if err := s.store.Update(func(d *appData) { d.Settings.TUN = true }); err != nil {
				t.Fatal(err)
			}
			if w := request("POST", "/api/connect", ""); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"code":"needHelper"`) {
				t.Fatalf("old helper returned %d %s", w.Code, w.Body)
			}
			if len(h.started) != 0 {
				t.Fatal("started a session on the old helper")
			}
		})
	}
}

func profileRelayTestServer(t *testing.T) (*Server, *fakeCtl, *fakeHelper, func(string, string, string) *httptest.ResponseRecorder) {
	t.Helper()
	dir := t.TempDir()
	ctl := &fakeCtl{}
	helperCtl := &fakeHelper{fakeCtl: &fakeCtl{}, info: helper.Info{State: helper.StateOK}}
	s := NewServer(Config{
		Dir: dir, ProfilesDir: filepath.Join(dir, "profiles"), Controller: ctl, Helper: helperCtl,
		Logs: logring.New(0), Proxy: sysproxy.New(&memProxy{state: "orig"}, filepath.Join(dir, "proxy.armed")),
	})
	if _, err := s.profiles.Save("phone", link.Profile{Host: "example.com", Name: "phone"}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.Update(func(d *appData) { d.Active = "phone" }); err != nil {
		t.Fatal(err)
	}
	const serverHost = "127.0.0.1:9000"
	s.SetHost(serverHost)
	token, ok := s.sess.Redeem(s.NewNonce())
	if !ok {
		t.Fatal("could not make a session")
	}
	handler := s.Handler()
	return s, ctl, helperCtl, func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://"+serverHost+path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		r.Header.Set("Origin", "http://"+serverHost)
		r.Header.Set("X-Pipe-CSRF", "1")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
}
