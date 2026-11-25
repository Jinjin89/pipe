// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/config"
	"pipe/internal/helper"
	"pipe/internal/link"
	"pipe/internal/logring"
	"pipe/internal/sysproxy"
)

type fakeCtl struct {
	mu                sync.Mutex
	state             string
	started           []clientctl.Options
	applied           []clientctl.Options
	mode              string
	tier              string
	relay             string
	relayState        string
	failure           error
	applyErr, tierErr error
}

func (f *fakeCtl) Start(o clientctl.Options) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != nil {
		return f.failure
	}
	f.state, f.mode, f.relay = "on", o.Mode, o.Relay
	f.started = append(f.started, o)
	return nil
}
func (f *fakeCtl) Stop() error { f.mu.Lock(); f.state = "off"; f.mu.Unlock(); return nil }
func (f *fakeCtl) Status() clientctl.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.state
	if st == "" {
		st = "off"
	}
	relay, _ := config.ParseRelay(f.relay, "")
	status := clientctl.Status{State: st, Mode: f.mode, Listen: "127.0.0.1:7890", Relay: relay.Host}
	if status.Relay != "" {
		status.RelayState = f.relayState
	}
	return status
}
func (f *fakeCtl) SetMode(m string) error { f.mu.Lock(); f.mode = m; f.mu.Unlock(); return nil }
func (f *fakeCtl) SetTier(t string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tierErr != nil {
		return f.tierErr
	}
	f.tier = t
	return nil
}
func (f *fakeCtl) Apply(o clientctl.Options) error {
	f.mu.Lock()
	if f.applyErr != nil {
		f.mu.Unlock()
		return f.applyErr
	}
	f.applied = append(f.applied, o)
	f.relay = o.Relay
	f.mu.Unlock()
	return nil
}
func (f *fakeCtl) TestRoutes(context.Context) map[string]clientctl.RouteLatency {
	return map[string]clientctl.RouteLatency{"fast": {Ms: 42, OK: true}}
}

type memProxy struct{ state string }

func (m *memProxy) Capture() (json.RawMessage, error) { return json.Marshal(m.state) }
func (m *memProxy) IsApplied(string, int) bool        { return m.state == "pipe" }
func (m *memProxy) Apply(string, int) error           { m.state = "pipe"; return nil }
func (m *memProxy) Restore(raw json.RawMessage) error { return json.Unmarshal(raw, &m.state) }

type fakeAuto struct{ on bool }

func (a *fakeAuto) Enable(string) error { a.on = true; return nil }
func (a *fakeAuto) Disable() error      { a.on = false; return nil }

type env struct {
	t      *testing.T
	srv    *Server
	ts     *httptest.Server
	ctl    *fakeCtl
	proxy  *memProxy
	auto   *fakeAuto
	dir    string
	origin string
	quit   chan struct{}
	client *http.Client
	cookie *http.Cookie
}

func newEnv(t *testing.T) *env {
	dir := t.TempDir()
	e := &env{t: t, ctl: &fakeCtl{}, proxy: &memProxy{state: "orig"}, auto: &fakeAuto{}, dir: dir, quit: make(chan struct{}, 1)}
	e.srv = NewServer(Config{
		Dir: dir, ProfilesDir: filepath.Join(dir, "profiles"), Controller: e.ctl, Logs: logring.New(100),
		ParseRule: config.ParseRule,
		Proxy:     sysproxy.New(e.proxy, filepath.Join(dir, "proxy.armed")),
		Autostart: e.auto, Version: "9.9.9-test", Exe: "/opt/pipe",
		OnQuit: func() { e.quit <- struct{}{} },
	})
	e.ts = httptest.NewServer(e.srv.Handler())
	t.Cleanup(e.ts.Close)
	host := strings.TrimPrefix(e.ts.URL, "http://")
	e.srv.SetHost(host)
	e.origin = e.ts.URL
	e.client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return e
}

// do sends a request with optional overrides applied.
func (e *env) do(method, path, body string, mutate ...func(*http.Request)) *http.Response {
	e.t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	for _, m := range mutate {
		m(req)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

// login does the real nonce flow.
func (e *env) login() {
	e.t.Helper()
	nonce := e.srv.NewNonce()
	resp := e.do("POST", "/api/session", `{"nonce":"`+nonce+`"}`, func(r *http.Request) { r.Header.Set("Origin", e.origin); r.Header.Set("X-Pipe-CSRF", "1") })
	resp.Body.Close()
	if resp.StatusCode != 204 {
		e.t.Fatalf("session status %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			e.cookie = c
		}
	}
	if e.cookie == nil || !e.cookie.HttpOnly || e.cookie.SameSite != http.SameSiteStrictMode || e.cookie.Path != "/" || len(e.cookie.Value) < 40 {
		e.t.Fatalf("bad cookie %+v", e.cookie)
	}
}

// api sends an authenticated call with all CSRF headers.
func (e *env) api(method, path, body string) (*http.Response, map[string]any) {
	e.t.Helper()
	resp := e.do(method, path, body, func(r *http.Request) {
		r.AddCookie(e.cookie)
		r.Header.Set("Origin", e.origin)
		r.Header.Set("X-Pipe-CSRF", "1")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	})
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp, out
}

func testLink(t *testing.T, name string, cdn string) string {
	t.Helper()
	raw, err := link.Profile{Host: "example.com", CDN: cdn, WSPath: "/ws", Name: name}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAuthRules(t *testing.T) {
	e := newEnv(t)
	e.login()
	cookie := func(r *http.Request) { r.AddCookie(e.cookie) }

	if r := e.do("GET", "/api/status", ""); r.StatusCode != 401 {
		t.Errorf("no cookie: %d", r.StatusCode)
	}
	if r := e.do("GET", "/api/status", "", cookie); r.StatusCode != 200 {
		t.Errorf("cookie GET: %d", r.StatusCode)
	}
	if r := e.do("GET", "/api/status", "", cookie, func(r *http.Request) { r.Host = "evil.example:80" }); r.StatusCode != 403 {
		t.Errorf("wrong host: %d", r.StatusCode)
	}
	if r := e.do("GET", "/", "", func(r *http.Request) { r.Host = "localhost:" + strings.Split(e.srv.hostValue(), ":")[1] }); r.StatusCode != 403 {
		t.Errorf("localhost host (rebinding): %d", r.StatusCode)
	}
	if r := e.do("GET", "/api/status", "", cookie, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }); r.StatusCode != 403 {
		t.Errorf("cross-site GET: %d", r.StatusCode)
	}
	if r := e.do("GET", "/api/status", "", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: cookieName, Value: "forged"}) }); r.StatusCode != 401 {
		t.Errorf("forged cookie: %d", r.StatusCode)
	}
	post := func(mut ...func(*http.Request)) int {
		return e.do("PUT", "/api/mode", `{"mode":"global"}`, append([]func(*http.Request){cookie}, mut...)...).StatusCode
	}
	good := func(r *http.Request) { r.Header.Set("Origin", e.origin); r.Header.Set("X-Pipe-CSRF", "1") }
	if c := post(good); c != 200 {
		t.Errorf("good PUT: %d", c)
	}
	if c := post(); c != 403 {
		t.Errorf("PUT without origin/csrf: %d", c)
	}
	if c := post(func(r *http.Request) { r.Header.Set("Origin", e.origin) }); c != 403 {
		t.Errorf("PUT without csrf: %d", c)
	}
	if c := post(func(r *http.Request) { r.Header.Set("X-Pipe-CSRF", "1") }); c != 403 {
		t.Errorf("PUT without origin: %d", c)
	}
	if c := post(good, func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }); c != 403 {
		t.Errorf("cross-origin PUT: %d", c)
	}
	if c := post(good, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }); c != 403 {
		t.Errorf("cross-site PUT: %d", c)
	}
	if c := post(good, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "") }); c != 403 {
		t.Errorf("empty Sec-Fetch-Site PUT: %d", c)
	}
	if r := e.do("GET", "/api/nothing", "", cookie); r.StatusCode != 404 {
		t.Errorf("unknown api: %d", r.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	resp := e.do("GET", "/favicon.svg", "")
	h := resp.Header
	if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") || !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
		h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers %v", h)
	}
	// Errors carry them too.
	if r := e.do("GET", "/api/status", ""); r.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP on error")
	}
}

func TestNonceSingleUseAndExpiry(t *testing.T) {
	e := newEnv(t)
	csrf := func(r *http.Request) { r.Header.Set("Origin", e.origin); r.Header.Set("X-Pipe-CSRF", "1") }
	nonce := e.srv.NewNonce()
	session := func(n string) int {
		return e.do("POST", "/api/session", `{"nonce":"`+n+`"}`, csrf).StatusCode
	}
	if c := session(nonce); c != 204 {
		t.Fatalf("first use: %d", c)
	}
	if c := session(nonce); c != 401 {
		t.Fatalf("reuse: %d", c)
	}
	if c := session("made-up"); c != 401 {
		t.Fatalf("unknown nonce: %d", c)
	}
	now := time.Now()
	e.srv.sess.now = func() time.Time { return now }
	old := e.srv.NewNonce()
	e.srv.sess.now = func() time.Time { return now.Add(nonceTTL + time.Second) }
	if c := session(old); c != 401 {
		t.Fatalf("expired: %d", c)
	}
	// Session endpoint also refuses cross-origin and wrong host.
	fresh := e.srv.NewNonce()
	if c := e.do("POST", "/api/session", `{"nonce":"`+fresh+`"}`, func(r *http.Request) { csrf(r); r.Header.Set("Origin", "http://evil.example") }).StatusCode; c != 403 {
		t.Fatalf("cross-origin session: %d", c)
	}
	if c := e.do("POST", "/api/session", `{"nonce":"`+fresh+`"}`, func(r *http.Request) { csrf(r); r.Host = "evil.example" }).StatusCode; c != 403 {
		t.Fatalf("wrong-host session: %d", c)
	}
	if c := e.do("POST", "/api/session", `{"nonce":"`+fresh+`"}`, func(r *http.Request) { r.Header.Set("Origin", e.origin) }).StatusCode; c != 403 {
		t.Fatalf("session without CSRF header: %d", c)
	}
	if c := session(fresh); c != 204 {
		t.Fatalf("failed attempts must not burn the nonce: %d", c)
	}
}

func TestShowEndpoint(t *testing.T) {
	e := newEnv(t)
	shown := make(chan struct{}, 1)
	e.srv.cfg.OnShow = func() { shown <- struct{}{} }
	if c := e.do("POST", "/internal/show", "", func(r *http.Request) {
		r.Header.Set("X-Pipe-Show", e.srv.ShowSecret())
		r.Header.Set("Origin", e.origin)
	}).StatusCode; c != 403 {
		t.Fatalf("show with Origin: %d", c)
	}
	secret := func(v string) func(*http.Request) { return func(r *http.Request) { r.Header.Set("X-Pipe-Show", v) } }
	if c := e.do("POST", "/internal/show", "", secret("nope")).StatusCode; c != 403 {
		t.Fatalf("wrong secret: %d", c)
	}
	if c := e.do("POST", "/internal/show", "", secret(e.srv.ShowSecret())).StatusCode; c != 204 {
		t.Fatalf("right secret: %d", c)
	}
	select {
	case <-shown:
	case <-time.After(time.Second):
		t.Fatal("OnShow not called")
	}
}

func TestProfilesLifecycleNeverReturnsLink(t *testing.T) {
	e := newEnv(t)
	e.login()
	_, out := e.api("GET", "/api/profiles", "")
	if out["active"] != "" || len(out["profiles"].([]any)) != 0 {
		t.Fatalf("expected empty: %v", out)
	}
	raw := testLink(t, "Phone", "cdn.example.com")
	_, prev := e.api("POST", "/api/profiles/preview", `{"link":"`+raw+`"}`)
	if resp, st := e.api("GET", "/api/status", ""); resp.StatusCode != 200 || st["routes"] == nil {
		t.Fatalf("routes must be an object: %v", st)
	}
	if prev["name"] != "phone" || prev["server"] != "example.com" || prev["exists"] != false || len(prev["routes"].([]any)) != 3 {
		t.Fatalf("preview %v", prev)
	}
	if resp, _ := e.api("POST", "/api/profiles/preview", `{"link":"nonsense"}`); resp.StatusCode != 400 {
		t.Fatal("bad link accepted")
	}
	resp, added := e.api("POST", "/api/profiles", `{"link":"`+raw+`","name":"My-Phone"}`)
	if resp.StatusCode != 200 || added["name"] != "my-phone" {
		t.Fatalf("add %d %v", resp.StatusCode, added)
	}
	path := filepath.Join(e.dir, "profiles", "my-phone.link")
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("profile file %v %v", err, info)
	}
	if resp, _ := e.api("POST", "/api/profiles", `{"link":"`+raw+`","name":"../x"}`); resp.StatusCode != 400 {
		t.Fatal("bad name accepted")
	}
	// Every profile endpoint must not echo the link.
	for _, p := range []string{"/api/profiles", "/api/status", "/api/routing"} {
		r := e.do("GET", p, "", func(r *http.Request) { r.AddCookie(e.cookie) })
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte("pipe://")) {
			t.Fatalf("%s leaked a link", p)
		}
	}
	_, list := e.api("GET", "/api/profiles", "")
	if list["active"] != "my-phone" {
		t.Fatalf("first profile should become active: %v", list)
	}
	// Rename keeps active.
	if resp, _ := e.api("PATCH", "/api/profiles/my-phone", `{"name":"home"}`); resp.StatusCode != 200 {
		t.Fatal("rename failed")
	}
	_, list = e.api("GET", "/api/profiles", "")
	if list["active"] != "home" {
		t.Fatalf("active after rename: %v", list)
	}
	e.api("POST", "/api/profiles", `{"link":"`+testLink(t, "Other", "")+`"}`)
	if resp, _ := e.api("PATCH", "/api/profiles/other", `{"name":"home"}`); resp.StatusCode != 409 {
		t.Fatalf("rename onto existing: %d", resp.StatusCode)
	}
	if resp, _ := e.api("POST", "/api/profiles/nope/activate", ""); resp.StatusCode != 404 {
		t.Fatal("activate missing")
	}
	// Connect, then delete the active profile: disconnects first.
	if resp, st := e.api("POST", "/api/connect", ""); resp.StatusCode != 200 || st["state"] != "on" {
		t.Fatalf("connect %d %v", resp.StatusCode, st)
	}
	if resp, _ := e.api("DELETE", "/api/profiles/home", ""); resp.StatusCode != 204 {
		t.Fatalf("delete %d", resp.StatusCode)
	}
	if e.ctl.Status().State != "off" || e.proxy.state != "orig" {
		t.Fatalf("delete should disconnect and restore proxy: %v %v", e.ctl.Status().State, e.proxy.state)
	}
	_, list = e.api("GET", "/api/profiles", "")
	if list["active"] != "other" {
		t.Fatalf("active falls to the remaining profile: %v", list)
	}
}

func TestConnectDisconnectAndSystemProxy(t *testing.T) {
	e := newEnv(t)
	e.login()
	if resp, out := e.api("POST", "/api/connect", ""); resp.StatusCode != 400 || out["error"] == "" {
		t.Fatalf("connect without profile: %d %v", resp.StatusCode, out)
	}
	e.api("POST", "/api/profiles", `{"link":"`+testLink(t, "phone", "")+`"}`)
	e.api("PUT", "/api/routing", `{"mode":"global","tier":"stealth","rules":[{"type":"suffix","value":"example.org","action":"direct"}]}`)
	_, st := e.api("POST", "/api/connect", "")
	if st["state"] != "on" || st["systemProxy"] != "on" || e.proxy.state != "pipe" {
		t.Fatalf("status %v proxy %q", st, e.proxy.state)
	}
	opts := e.ctl.started[0]
	if opts.Mode != "global" || opts.Tier != "stealth" || opts.Listen != "127.0.0.1:7890" || opts.LogLevel != "warn" || len(opts.Rules) != 1 || opts.Profile.Host != "example.com" {
		t.Fatalf("options %+v", opts)
	}
	// Turning the system proxy setting off while connected restores it.
	e.api("PUT", "/api/settings", `{"systemProxy":false,"listenPort":7890,"ipv6":true,"logDetail":"connections","theme":"dark"}`)
	if e.proxy.state != "orig" || len(e.ctl.applied) == 0 || e.ctl.applied[len(e.ctl.applied)-1].LogLevel != "info" {
		t.Fatalf("settings not applied: proxy=%q applied=%d", e.proxy.state, len(e.ctl.applied))
	}
	_, st = e.api("GET", "/api/status", "")
	if st["systemProxy"] != "off" {
		t.Fatalf("%v", st)
	}
	e.api("PUT", "/api/settings", `{"systemProxy":true,"listenPort":7891}`)
	if e.proxy.state != "pipe" {
		t.Fatal("proxy should be set again")
	}
	_, st = e.api("POST", "/api/disconnect", "")
	if st["state"] != "off" || st["systemProxy"] != "off" || e.proxy.state != "orig" {
		t.Fatalf("disconnect %v %q", st, e.proxy.state)
	}
	// Engine dying on its own is noticed on the next status poll.
	e.api("POST", "/api/connect", "")
	e.ctl.mu.Lock()
	e.ctl.state = "error"
	e.ctl.mu.Unlock()
	_, st = e.api("GET", "/api/status", "")
	if st["systemProxy"] != "off" || e.proxy.state != "orig" {
		t.Fatalf("proxy must be restored when the engine fails: %v %q", st, e.proxy.state)
	}
}

func TestUnsupportedProxyIsReported(t *testing.T) {
	e := newEnv(t)
	e.srv.cfg.Proxy = sysproxy.New(nil, filepath.Join(e.dir, "x"))
	e.login()
	e.api("POST", "/api/profiles", `{"link":"`+testLink(t, "phone", "")+`"}`)
	_, st := e.api("POST", "/api/connect", "")
	if st["state"] != "on" || st["systemProxy"] != "unsupported" || !strings.Contains(st["systemProxyNote"].(string), "127.0.0.1:7890") {
		t.Fatalf("%v", st)
	}
}

func TestModeTierRoutingValidation(t *testing.T) {
	e := newEnv(t)
	e.login()
	if resp, _ := e.api("PUT", "/api/mode", `{"mode":"turbo"}`); resp.StatusCode != 400 {
		t.Fatal("bad mode")
	}
	if resp, _ := e.api("PUT", "/api/tier", `{"tier":"x"}`); resp.StatusCode != 400 {
		t.Fatal("bad tier")
	}
	e.api("PUT", "/api/mode", `{"mode":"direct"}`)
	e.api("PUT", "/api/tier", `{"tier":"rescue"}`)
	_, r := e.api("GET", "/api/routing", "")
	if r["mode"] != "direct" || r["tier"] != "rescue" {
		t.Fatalf("%v", r)
	}
	resp, out := e.api("PUT", "/api/routing", `{"mode":"smart","tier":"auto","rules":[{"type":"domain","value":"a.example.com","action":"proxy"},{"type":"keyword","value":"a b","action":"proxy"}]}`)
	if resp.StatusCode != 400 || out["index"] != float64(1) || out["error"] == "" {
		t.Fatalf("bad rule: %d %v", resp.StatusCode, out)
	}
	for _, body := range []string{
		`{"mode":"smart","tier":"auto","rules":[{"type":"domain","value":"","action":"proxy"}]}`,
		`{"mode":"smart","tier":"auto","rules":[{"type":"domain","value":"192.0.2.1","action":"proxy"}]}`,
		`{"mode":"smart","tier":"auto","rules":[{"type":"ip","value":"example.com","action":"proxy"}]}`,
		`{"mode":"smart","tier":"auto","rules":[{"type":"wat","value":"x","action":"proxy"}]}`,
		`{"mode":"smart","tier":"auto","rules":[{"type":"domain","value":"x.example","action":"maybe"}]}`,
	} {
		if resp, _ := e.api("PUT", "/api/routing", body); resp.StatusCode != 400 {
			t.Errorf("accepted %s", body)
		}
	}
	// Nothing was saved by the failed calls.
	_, r = e.api("GET", "/api/routing", "")
	if r["mode"] != "direct" {
		t.Fatalf("failed PUT changed state: %v", r)
	}
	var many []string
	for i := 0; i < 501; i++ {
		many = append(many, `{"type":"domain","value":"a.example.com","action":"proxy"}`)
	}
	if resp, _ := e.api("PUT", "/api/routing", `{"mode":"smart","tier":"auto","rules":[`+strings.Join(many, ",")+`]}`); resp.StatusCode != 400 {
		t.Fatal("501 rules accepted")
	}
}

func TestRuleText(t *testing.T) {
	cases := map[RuleObject]string{
		{"domain", "a.example.com", "proxy"}: "a.example.com -> proxy",
		{"suffix", "example.com", "direct"}:  "suffix:example.com -> direct",
		{"keyword", "ads", "block"}:          "keyword:ads -> block",
		{"ip", "192.0.2.0/24", "direct"}:     "192.0.2.0/24 -> direct",
		{"app", "firefox", "proxy"}:          "process:firefox -> proxy",
	}
	for in, want := range cases {
		if got, err := RuleText(in); err != nil || got != want {
			t.Errorf("%+v: %q %v", in, got, err)
		}
	}
}

func TestSettingsPersistAndAutostart(t *testing.T) {
	e := newEnv(t)
	e.login()
	_, s := e.api("GET", "/api/settings", "")
	if s["systemProxy"] != true || s["listenPort"] != float64(7890) || s["theme"] != "system" || s["logDetail"] != "normal" {
		t.Fatalf("defaults %v", s)
	}
	if resp, _ := e.api("PUT", "/api/settings", `{"listenPort":80}`); resp.StatusCode != 400 {
		t.Fatal("privileged port accepted")
	}
	if resp, _ := e.api("PUT", "/api/settings", `{"listenPort":8000,"theme":"neon","logDetail":"normal"}`); resp.StatusCode != 400 {
		t.Fatal("bad theme accepted")
	}
	e.api("PUT", "/api/settings", `{"startAtLogin":true,"connectOnLaunch":true,"listenPort":8123,"ipv6":false,"logDetail":"connections","theme":"light","systemProxy":true}`)
	if !e.auto.on {
		t.Fatal("autostart not enabled")
	}
	info, err := os.Stat(filepath.Join(e.dir, "app.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("app.json: %v %v", err, info)
	}
	again := OpenStore(filepath.Join(e.dir, "app.json")).Snapshot().Settings
	if again.ListenPort != 8123 || again.IPv6 || !again.ConnectOnLaunch || again.Theme != "light" {
		t.Fatalf("not persisted: %+v", again)
	}
}

func TestDamagedAppJSONFallsBackToDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.json")
	os.WriteFile(path, []byte(`{"mode":"weird","settings":{"listenPort":99999}}`), 0600)
	d := OpenStore(path).Snapshot()
	if d.Mode != "smart" || d.Settings.ListenPort != 7890 {
		t.Fatalf("%+v", d)
	}
}

func TestLogsAboutRoutesQuit(t *testing.T) {
	e := newEnv(t)
	e.login()
	e.srv.cfg.Logs.Add("warn", "pipe", "hello")
	_, logs := e.api("GET", "/api/logs?after=0&limit=10", "")
	if len(logs["entries"].([]any)) != 1 || logs["next"] == nil {
		t.Fatalf("%v", logs)
	}
	if resp, _ := e.api("DELETE", "/api/logs", ""); resp.StatusCode != 204 {
		t.Fatal("clear logs")
	}
	_, logs = e.api("GET", "/api/logs", "")
	if len(logs["entries"].([]any)) != 0 {
		t.Fatalf("not cleared: %v", logs)
	}
	_, about := e.api("GET", "/api/about", "")
	if about["version"] != "9.9.9-test" || about["configDir"] != e.dir || !strings.Contains(about["cliCommand"].(string), "pipe run --tun") {
		t.Fatalf("%v", about)
	}
	if resp, _ := e.api("POST", "/api/routes/test", ""); resp.StatusCode != 409 {
		t.Fatal("test routes while off must be refused")
	}
	e.api("POST", "/api/profiles", `{"link":"`+testLink(t, "phone", "")+`"}`)
	e.api("POST", "/api/connect", "")
	_, rt := e.api("POST", "/api/routes/test", "")
	if rt["routes"].(map[string]any)["fast"].(map[string]any)["ms"] != float64(42) {
		t.Fatalf("%v", rt)
	}
	if resp, _ := e.api("POST", "/api/quit", ""); resp.StatusCode != 204 {
		t.Fatal("quit")
	}
	select {
	case <-e.quit:
	case <-time.After(time.Second):
		t.Fatal("OnQuit not called")
	}
}

func TestFailedLiveApplyIsNotPersisted(t *testing.T) {
	e := newEnv(t)
	e.login()
	e.api("POST", "/api/profiles", `{"link":"`+testLink(t, "phone", "")+`"}`)
	e.api("POST", "/api/connect", "")
	e.ctl.tierErr = errors.New("no rescue route")
	if resp, _ := e.api("PUT", "/api/tier", `{"tier":"rescue"}`); resp.StatusCode != 500 {
		t.Fatalf("tier failure: %d", resp.StatusCode)
	}
	if _, r := e.api("GET", "/api/routing", ""); r["tier"] != "auto" {
		t.Fatalf("tier persisted despite failure: %v", r)
	}
	e.ctl.tierErr = nil
	e.ctl.applyErr = errors.New("address in use")
	if resp, _ := e.api("PUT", "/api/settings", `{"startAtLogin":true,"listenPort":7999,"systemProxy":true}`); resp.StatusCode != 500 {
		t.Fatalf("settings failure: %d", resp.StatusCode)
	}
	if _, s := e.api("GET", "/api/settings", ""); s["listenPort"] != float64(7890) || s["startAtLogin"] != false {
		t.Fatalf("settings persisted despite failure: %v", s)
	}
	if e.auto.on {
		t.Fatal("autostart must be reverted")
	}
	if resp, _ := e.api("PUT", "/api/routing", `{"mode":"global","tier":"auto","rules":[]}`); resp.StatusCode != 500 {
		t.Fatal("routing failure")
	}
	if _, r := e.api("GET", "/api/routing", ""); r["mode"] != "smart" {
		t.Fatalf("routing persisted despite failure: %v", r)
	}
}

func TestActivateFailureClearsProxy(t *testing.T) {
	e := newEnv(t)
	e.login()
	e.api("POST", "/api/profiles", `{"link":"`+testLink(t, "phone", "")+`"}`)
	e.api("POST", "/api/profiles", `{"link":"`+testLink(t, "other", "")+`"}`)
	e.api("POST", "/api/connect", "")
	if e.proxy.state != "pipe" {
		t.Fatal("proxy should be set")
	}
	e.ctl.failure = errors.New("boom")
	if resp, _ := e.api("POST", "/api/profiles/other/activate", ""); resp.StatusCode == 200 {
		t.Fatal("activate should fail")
	}
	if e.proxy.state != "orig" {
		t.Fatalf("proxy left pointing at pipe: %q", e.proxy.state)
	}
	if _, l := e.api("GET", "/api/profiles", ""); l["active"] != "phone" {
		t.Fatalf("active changed despite failure: %v", l)
	}
}

func TestProfileNamesCanonical(t *testing.T) {
	e := newEnv(t)
	e.login()
	dir := filepath.Join(e.dir, "profiles")
	os.MkdirAll(dir, 0700)
	long := strings.Repeat("a", 64)
	for _, n := range []string{"Phone", long} {
		os.WriteFile(filepath.Join(dir, n+".link"), []byte(testLink(t, "x", "")+"\n"), 0600)
	}
	_, l := e.api("GET", "/api/profiles", "")
	if len(l["profiles"].([]any)) != 2 {
		t.Fatalf("CLI profiles hidden: %v", l)
	}
	e.api("POST", "/api/profiles/phone/activate", "")
	e.api("POST", "/api/connect", "")
	if resp, _ := e.api("DELETE", "/api/profiles/PHONE", ""); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if e.ctl.Status().State != "off" {
		t.Fatal("deleting the active profile under another case must disconnect")
	}
	if _, err := os.Stat(filepath.Join(dir, "Phone.link")); !os.IsNotExist(err) {
		t.Fatal("file not deleted")
	}
	if resp, _ := e.api("DELETE", "/api/profiles/..%2Fx", ""); resp.StatusCode != 404 {
		t.Fatal("traversal name")
	}
}

func TestOpenStoreRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	os.WriteFile(real, []byte(`{"mode":"global"}`), 0600)
	os.Symlink(real, filepath.Join(dir, "app.json"))
	if OpenStore(filepath.Join(dir, "app.json")).Snapshot().Mode != "smart" {
		t.Fatal("followed a symlink")
	}
}

func (m *memProxy) RestoreIfApplied(raw json.RawMessage, _ string, _ int) error {
	if m.state != "pipe" {
		return nil
	}
	return m.Restore(raw)
}

// ---------- TUN through Pipe Helper (§8.5) ----------

type fakeHelper struct {
	*fakeCtl
	imu       sync.Mutex
	info      helper.Info
	installed int
	removed   int
	installE  error
	removeE   error
	stops     int
	onChange  func()

	probeProfile func(context.Context, clientctl.ProbeOptions) (map[string]clientctl.RouteLatency, error)
}

func (h *fakeHelper) SyncLogs()         {}
func (h *fakeHelper) OnChange(f func()) { h.onChange = f }

func (h *fakeHelper) TestProfile(ctx context.Context, opts clientctl.ProbeOptions) (map[string]clientctl.RouteLatency, error) {
	return h.probeProfile(ctx, opts)
}

func (h *fakeHelper) Info() helper.Info { h.imu.Lock(); defer h.imu.Unlock(); return h.info }
func (h *fakeHelper) Install() error {
	h.imu.Lock()
	defer h.imu.Unlock()
	h.installed++
	if h.installE != nil {
		return h.installE
	}
	h.info = helper.Info{State: helper.StateOK, Version: "9.9.9-test"}
	return nil
}
func (h *fakeHelper) Remove() error {
	h.imu.Lock()
	defer h.imu.Unlock()
	if h.removeE != nil {
		return h.removeE
	}
	h.removed++
	h.fakeCtl.Stop() // stopping the service ends the session
	h.info = helper.Info{State: helper.StateMissing, Note: "Pipe Helper isn't installed."}
	return nil
}
func (h *fakeHelper) Stop() error {
	h.imu.Lock()
	h.stops++
	h.imu.Unlock()
	return h.fakeCtl.Stop()
}

func newTUNEnv(t *testing.T, state string) (*env, *fakeHelper) {
	e := newEnv(t)
	h := &fakeHelper{fakeCtl: &fakeCtl{}, info: helper.Info{State: state}}
	if state == helper.StateMissing {
		h.info.Note = "Pipe Helper isn't installed."
	}
	e.srv.cfg.Helper = h
	e.login()
	e.api("POST", "/api/profiles", `{"link":"`+testLink(t, "phone", "")+`"}`)
	return e, h
}

func TestConnectViaTUNAndViaProxy(t *testing.T) {
	e, h := newTUNEnv(t, helper.StateOK)
	if _, out := e.api("PUT", "/api/settings", `{"tun":true,"systemProxy":true,"listenPort":7890}`); out["tun"] != true {
		t.Fatalf("settings %v", out)
	}
	_, st := e.api("POST", "/api/connect", "")
	if st["state"] != "on" || st["via"] != "tun" || st["systemProxy"] != "off" || e.proxy.state != "orig" {
		t.Fatalf("tun status %v proxy %q", st, e.proxy.state)
	}
	if len(h.started) != 1 || !h.started[0].TUN || len(e.ctl.started) != 0 {
		t.Fatalf("helper %+v local %+v", h.started, e.ctl.started)
	}
	if hs, _ := st["helper"].(map[string]any); hs["state"] != "ok" {
		t.Fatalf("helper info %v", st["helper"])
	}
	// Mode, tier, routes and live settings go to the helper session.
	e.api("PUT", "/api/mode", `{"mode":"global"}`)
	e.api("PUT", "/api/tier", `{"tier":"fast"}`)
	if h.mode != "global" || h.tier != "fast" || e.ctl.mode == "global" {
		t.Fatalf("helper %q %q local %q", h.mode, h.tier, e.ctl.mode)
	}
	if _, out := e.api("POST", "/api/routes/test", ""); out["routes"] == nil {
		t.Fatalf("routes %v", out)
	}
	// systemProxy is saved but not applied in TUN mode.
	e.api("PUT", "/api/settings", `{"tun":true,"systemProxy":false,"listenPort":7890}`)
	e.api("PUT", "/api/settings", `{"tun":true,"systemProxy":true,"listenPort":7890}`)
	if e.proxy.state != "orig" || len(h.applied) == 0 {
		t.Fatalf("proxy %q applied %d", e.proxy.state, len(h.applied))
	}
	if !e.srv.Settings().SystemProxy {
		t.Fatal("systemProxy must be saved")
	}
	// Switching tun off while connected reconnects through the local path.
	_, out := e.api("PUT", "/api/settings", `{"tun":false,"systemProxy":true,"listenPort":7890}`)
	if out["tun"] != false {
		t.Fatalf("settings %v", out)
	}
	_, st = e.api("GET", "/api/status", "")
	if st["via"] != "proxy" || st["systemProxy"] != "on" || e.proxy.state != "pipe" || h.stops != 1 || len(e.ctl.started) != 1 || e.ctl.started[0].TUN {
		t.Fatalf("after switch %v proxy %q stops %d local %+v", st, e.proxy.state, h.stops, e.ctl.started)
	}
	// And back on: the local session and the proxy go away.
	e.api("PUT", "/api/settings", `{"tun":true,"systemProxy":true,"listenPort":7890}`)
	_, st = e.api("GET", "/api/status", "")
	if st["via"] != "tun" || e.proxy.state != "orig" || e.ctl.state != "off" || len(h.started) != 2 {
		t.Fatalf("back to tun %v proxy %q", st, e.proxy.state)
	}
	_, st = e.api("POST", "/api/disconnect", "")
	if st["state"] != "off" || st["via"] != "" {
		t.Fatalf("disconnect %v", st)
	}
}

func TestChangesSignal(t *testing.T) {
	e, h := newTUNEnv(t, helper.StateOK)
	got := func() bool {
		select {
		case <-e.srv.Changes():
			return true
		default:
			return false
		}
	}
	h.OnChange(e.srv.notify) // the test swapped the helper in after NewServer
	got()                    // drain
	e.api("POST", "/api/connect", "")
	if !got() {
		t.Fatal("connect gave no change")
	}
	if got() {
		t.Fatal("changes must coalesce")
	}
	h.onChange() // the helper session ended by itself
	if !got() {
		t.Fatal("helper change not forwarded")
	}
	e.api("PUT", "/api/mode", `{"mode":"global"}`)
	if !got() {
		t.Fatal("mode gave no change")
	}
}

func TestNeedHelperSavesNothing(t *testing.T) {
	e, h := newTUNEnv(t, helper.StateMissing)
	resp, out := e.api("PUT", "/api/settings", `{"tun":true,"listenPort":7890}`)
	if resp.StatusCode != 409 || out["code"] != "needHelper" || out["error"] != "Pipe Helper isn't installed." {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
	if e.srv.Settings().TUN {
		t.Fatal("nothing may be saved")
	}
	// A saved tun with a helper that went away fails to connect with needHelper.
	h.imu.Lock()
	h.info = helper.Info{State: helper.StateOK}
	h.imu.Unlock()
	e.api("PUT", "/api/settings", `{"tun":true,"listenPort":7890}`)
	h.imu.Lock()
	h.info = helper.Info{State: helper.StateOutdated, Note: "Update Pipe Helper."}
	h.imu.Unlock()
	if resp, out := e.api("POST", "/api/connect", ""); resp.StatusCode != 409 || out["code"] != "needHelper" || len(h.started) != 0 {
		t.Fatalf("connect %d %v", resp.StatusCode, out)
	}
}

func TestInstallCanceledAndRemove(t *testing.T) {
	e, h := newTUNEnv(t, helper.StateMissing)
	h.installE = helper.ErrCanceled
	resp, out := e.api("POST", "/api/helper/install", "")
	if resp.StatusCode != 400 || out["code"] != "canceled" || out["error"] != "Cancelled." {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
	h.installE = nil
	if resp, out := e.api("POST", "/api/helper/install", ""); resp.StatusCode != 200 || out["state"] != "ok" {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
	if _, out := e.api("GET", "/api/helper", ""); out["state"] != "ok" {
		t.Fatalf("%v", out)
	}
	e.api("PUT", "/api/settings", `{"tun":true,"listenPort":7890}`)
	e.api("POST", "/api/connect", "")
	// A dismissed prompt changes nothing: still connected through TUN.
	h.removeE = helper.ErrCanceled
	resp, out = e.api("POST", "/api/helper/remove", "")
	if resp.StatusCode != 400 || out["code"] != "canceled" || h.stops != 0 || !e.srv.Settings().TUN {
		t.Fatalf("canceled remove: %d %v stops %d", resp.StatusCode, out, h.stops)
	}
	if _, st := e.api("GET", "/api/status", ""); st["state"] != "on" || st["via"] != "tun" {
		t.Fatalf("canceled remove changed %v", st)
	}
	h.removeE = nil
	// Removing while connected ends the session and turns tun off.
	resp, out = e.api("POST", "/api/helper/remove", "")
	if resp.StatusCode != 200 || out["state"] != "missing" || h.removed != 1 {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
	_, st := e.api("GET", "/api/status", "")
	if st["state"] != "off" || st["via"] != "" || e.srv.Settings().TUN {
		t.Fatalf("%v tun=%v", st, e.srv.Settings().TUN)
	}
	// The new endpoints keep the usual security checks.
	for _, c := range [][2]string{{"GET", "/api/helper"}, {"POST", "/api/helper/install"}, {"POST", "/api/helper/remove"}} {
		if r := e.do(c[0], c[1], ""); r.StatusCode != 401 {
			t.Errorf("%v without cookie: %d", c, r.StatusCode)
		}
		if c[0] == "POST" {
			if r := e.do(c[0], c[1], "", func(r *http.Request) { r.AddCookie(e.cookie) }); r.StatusCode != 403 {
				t.Errorf("%v without csrf: %d", c, r.StatusCode)
			}
		}
	}
	if h.installed != 2 || h.removed != 1 {
		t.Fatalf("installed %d removed %d", h.installed, h.removed)
	}
}

func TestShutdownStopsBothSessions(t *testing.T) {
	e, h := newTUNEnv(t, helper.StateOK)
	e.api("PUT", "/api/settings", `{"tun":true,"listenPort":7890}`)
	e.api("POST", "/api/connect", "")
	e.ctl.mu.Lock()
	e.ctl.state = "on" // a stray local session
	e.ctl.mu.Unlock()
	if err := e.srv.Close(); err != nil {
		t.Fatal(err)
	}
	if h.stops != 1 || e.ctl.state != "off" || h.Status().State != "off" || e.srv.getVia() != "" {
		t.Fatalf("helper stops %d local %q", h.stops, e.ctl.state)
	}
	if !e.srv.StateIsOff() {
		t.Fatal("should be off")
	}
}

func TestSetTUNInstallsFirst(t *testing.T) {
	e, h := newTUNEnv(t, helper.StateMissing)
	if err := e.srv.SetTUN(true); err != nil || h.installed != 1 || !e.srv.Settings().TUN {
		t.Fatalf("err %v installed %d", err, h.installed)
	}
	h.installE = helper.ErrCanceled
	h.Remove()
	if err := e.srv.SetTUN(true); !errors.Is(err, helper.ErrCanceled) {
		t.Fatalf("err %v", err)
	}
	if err := e.srv.SetSystemProxy(true); err != nil || !e.srv.Settings().SystemProxy {
		t.Fatal(err)
	}
}

func TestNilHelperIsUnsupported(t *testing.T) {
	e := newEnv(t)
	e.login()
	_, st := e.api("GET", "/api/status", "")
	if hs, _ := st["helper"].(map[string]any); hs["state"] != "unsupported" || st["via"] != "" {
		t.Fatalf("%v", st)
	}
	if _, out := e.api("GET", "/api/helper", ""); out["state"] != "unsupported" {
		t.Fatalf("%v", out)
	}
	if resp, _ := e.api("PUT", "/api/settings", `{"tun":true,"listenPort":7890}`); resp.StatusCode != 400 {
		t.Fatalf("tun without helper: %d", resp.StatusCode)
	}
	if resp, _ := e.api("POST", "/api/helper/install", ""); resp.StatusCode != 400 {
		t.Fatalf("install without helper: %d", resp.StatusCode)
	}
}

func TestProfileSecretEndpoint(t *testing.T) {
	e := newEnv(t)
	e.login()

	withProxyProfile := link.Profile{
		Host: "example.com", HTTPSProxy: "proxy.example.com:9443", CDN: "cdn.example.com", WSPath: "/ws", Name: "My Phone",
	}
	withProxyProfile.Seed[0], withProxyProfile.PublicKey[0] = 11, 22
	withProxyRaw, err := withProxyProfile.Encode()
	if err != nil {
		t.Fatal(err)
	}
	wantProxy, ok := link.ProxyURL(withProxyProfile)
	if !ok {
		t.Fatal("expected ProxyURL")
	}

	noProxyRaw := testLink(t, "Plain", "")
	if resp, _ := e.api("POST", "/api/profiles", `{"link":"`+withProxyRaw+`","name":"phone"}`); resp.StatusCode != 200 {
		t.Fatalf("add phone: %d", resp.StatusCode)
	}
	if resp, _ := e.api("POST", "/api/profiles", `{"link":"`+noProxyRaw+`","name":"plain"}`); resp.StatusCode != 200 {
		t.Fatalf("add plain: %d", resp.StatusCode)
	}

	// GET /api/profiles must never contain link text or derived proxy passwords.
	listResp := e.do("GET", "/api/profiles", "", func(r *http.Request) { r.AddCookie(e.cookie) })
	listBody, _ := io.ReadAll(listResp.Body)
	listResp.Body.Close()
	if bytes.Contains(listBody, []byte("pipe://")) ||
		bytes.Contains(listBody, []byte(link.EncodeKey(withProxyProfile.Seed))) ||
		bytes.Contains(listBody, []byte(link.Derive(withProxyProfile.Seed).HTTPSProxyPassword)) {
		t.Fatal("GET /api/profiles leaked secret material")
	}

	// Auth, CSRF, Host, Origin, and Sec-Fetch-Site checks.
	cookie := func(r *http.Request) { r.AddCookie(e.cookie) }
	good := func(r *http.Request) {
		r.AddCookie(e.cookie)
		r.Header.Set("Origin", e.origin)
		r.Header.Set("X-Pipe-CSRF", "1")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	if r := e.do("POST", "/api/profiles/phone/secret", ""); r.StatusCode != 401 || r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("no cookie: %d cc=%q", r.StatusCode, r.Header.Get("Cache-Control"))
	}
	if r := e.do("POST", "/api/profiles/phone/secret", "", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: cookieName, Value: "forged"})
		r.Header.Set("Origin", e.origin)
		r.Header.Set("X-Pipe-CSRF", "1")
	}); r.StatusCode != 401 {
		t.Errorf("forged cookie: %d", r.StatusCode)
	}
	if r := e.do("POST", "/api/profiles/phone/secret", "", cookie, func(r *http.Request) { r.Header.Set("Origin", e.origin) }); r.StatusCode != 403 {
		t.Errorf("without csrf: %d", r.StatusCode)
	}
	if r := e.do("POST", "/api/profiles/phone/secret", "", cookie, func(r *http.Request) { r.Header.Set("X-Pipe-CSRF", "1") }); r.StatusCode != 403 {
		t.Errorf("without origin: %d", r.StatusCode)
	}
	if r := e.do("POST", "/api/profiles/phone/secret", "", good, func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }); r.StatusCode != 403 {
		t.Errorf("wrong origin: %d", r.StatusCode)
	}
	if r := e.do("POST", "/api/profiles/phone/secret", "", good, func(r *http.Request) { r.Host = "evil.example:80" }); r.StatusCode != 403 {
		t.Errorf("wrong host: %d", r.StatusCode)
	}
	if r := e.do("POST", "/api/profiles/phone/secret", "", good, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }); r.StatusCode != 403 {
		t.Errorf("cross-site: %d", r.StatusCode)
	}
	if r := e.do("POST", "/api/profiles/phone/secret", "", good, func(r *http.Request) { r.Header.Add("Sec-Fetch-Site", "cross-site") }); r.StatusCode != 403 {
		t.Errorf("multi Sec-Fetch-Site: %d", r.StatusCode)
	}
	if r := e.do("GET", "/api/profiles/phone/secret", "", cookie); r.StatusCode == 200 {
		t.Errorf("GET must not serve secret: %d", r.StatusCode)
	}
	if resp, _ := e.api("POST", "/api/profiles/missing/secret", ""); resp.StatusCode != 404 {
		t.Errorf("missing profile: %d", resp.StatusCode)
	}
	if resp, _ := e.api("POST", "/api/profiles/..%2Fx/secret", ""); resp.StatusCode != 404 {
		t.Errorf("traversal name: %d", resp.StatusCode)
	}

	// Valid profile with HTTPS proxy (also case-insensitive name lookup).
	resp, out := e.api("POST", "/api/profiles/PHONE/secret", "")
	if resp.StatusCode != 200 {
		t.Fatalf("secret with proxy: %d %v", resp.StatusCode, out)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("missing Cache-Control: no-store: %q", resp.Header.Get("Cache-Control"))
	}
	if out["link"] != withProxyRaw || out["proxy"] != wantProxy {
		t.Fatalf("unexpected secret payload: link match=%v proxy match=%v", out["link"] == withProxyRaw, out["proxy"] == wantProxy)
	}
	if qrSVG, _ := out["qr"].(string); !strings.HasPrefix(qrSVG, "<svg ") || !strings.HasSuffix(qrSVG, "</svg>") {
		t.Fatalf("unexpected qr SVG: %q", qrSVG[:min(80, len(qrSVG))])
	}

	// Valid profile without HTTPS proxy.
	resp, out = e.api("POST", "/api/profiles/plain/secret", "")
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("secret without proxy: %d cc=%q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	if out["link"] != noProxyRaw || out["proxy"] != "" {
		t.Fatalf("unexpected plain secret payload: %v", out)
	}
	if qrSVG, _ := out["qr"].(string); !strings.HasPrefix(qrSVG, "<svg ") {
		t.Fatalf("missing qr SVG for plain profile")
	}
}
