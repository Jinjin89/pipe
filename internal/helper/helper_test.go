// SPDX-License-Identifier: GPL-3.0-or-later

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/config"
	"pipe/internal/link"
	"pipe/internal/logring"
	"pipe/internal/version"
)

func testProfile() link.Profile {
	p := link.Profile{Host: "example.test", Name: "phone", CDN: "cdn.example.test", WSPath: "/ws"}
	p.Seed[0], p.PublicKey[31] = 7, 9
	return p
}

func testOptions(t *testing.T) clientctl.Options {
	t.Helper()
	return clientctl.Options{
		Profile: testProfile(), Mode: "smart", Tier: "auto", IPv6: true,
		Rules:  []config.Rule{{Field: "domain_suffix", Match: "example.com", Action: "direct"}},
		Listen: "127.0.0.1:7890", LogLevel: "info",
	}
}

type fakeSession struct {
	mu          sync.Mutex
	started     *clientctl.Options
	stops       int
	mode        string
	tier        string
	relayState  string
	gate        chan struct{} // when set, Start blocks until it is closed
	startProbes func()
	dns         func() []netip.AddrPort
	onStop      func()
	stopOnMode  bool
	applyOff    bool
	uplink      string
}

type fakeSystemDNS struct {
	mu        sync.Mutex
	calls     []string
	onSet     func() error
	onRestore func()
}

func (d *fakeSystemDNS) call(name string) error {
	d.mu.Lock()
	d.calls = append(d.calls, name)
	d.mu.Unlock()
	return nil
}
func (d *fakeSystemDNS) Set() error {
	_ = d.call("set")
	if d.onSet != nil {
		return d.onSet()
	}
	return nil
}
func (d *fakeSystemDNS) Restore() error {
	if d.onRestore != nil {
		d.onRestore()
	}
	return d.call("restore")
}
func (d *fakeSystemDNS) Repair() error { return d.call("repair") }
func (d *fakeSystemDNS) Servers() []netip.AddrPort {
	return []netip.AddrPort{netip.MustParseAddrPort("192.168.1.1:53")}
}
func (d *fakeSystemDNS) recorded() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

func (f *fakeSession) StartWithReady(o clientctl.Options, ready func() error) error {
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	f.started = &o
	f.mu.Unlock()
	if ready != nil {
		if err := ready(); err != nil {
			_ = f.Stop()
			return err
		}
	}
	if f.startProbes != nil {
		f.startProbes()
	}
	return nil
}
func (f *fakeSession) Apply(o clientctl.Options) error {
	f.mu.Lock()
	applyOff := f.applyOff
	f.mu.Unlock()
	if applyOff {
		return nil
	}
	return f.StartWithReady(o, nil)
}
func (f *fakeSession) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.started != nil {
		f.stops++
	}
	f.started = nil
	return nil
}
func (f *fakeSession) Status() clientctl.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.started == nil {
		return clientctl.Status{State: clientctl.StateOff}
	}
	relay, _ := config.ParseRelay(f.started.Relay, f.started.Profile.Host)
	status := clientctl.Status{
		State: clientctl.StateOn, Profile: f.started.Profile.Name, Mode: f.started.Mode,
		Relay: relay.Host,
	}
	if status.Relay != "" {
		status.RelayState = f.relayState
	}
	return status
}
func (f *fakeSession) SetMode(m string) error {
	f.mu.Lock()
	f.mode = m
	if f.stopOnMode {
		f.started = nil
	}
	f.mu.Unlock()
	return nil
}
func (f *fakeSession) SetTier(t string) error { f.mu.Lock(); f.tier = t; f.mu.Unlock(); return nil }
func (f *fakeSession) TestRoutes(context.Context) map[string]clientctl.RouteLatency {
	return map[string]clientctl.RouteLatency{"fast": {Ms: 12, OK: true}}
}
func (f *fakeSession) DefaultInterface() string { return f.uplink }
func (f *fakeSession) SetLANDNSServers(provider func() []netip.AddrPort) {
	f.mu.Lock()
	f.dns = provider
	f.mu.Unlock()
}
func (f *fakeSession) SetOnStopped(callback func()) {
	f.mu.Lock()
	f.onStop = callback
	f.mu.Unlock()
}
func (f *fakeSession) endUnexpectedly() {
	f.mu.Lock()
	f.started = nil
	callback := f.onStop
	f.mu.Unlock()
	if callback != nil {
		callback()
	}
}
func (f *fakeSession) running() bool  { f.mu.Lock(); defer f.mu.Unlock(); return f.started != nil }
func (f *fakeSession) stopCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.stops }

type rig struct {
	sock string
	ses  *fakeSession
	ring *logring.Ring
}

func startServer(t *testing.T, mutate func(*ServeOptions)) rig {
	t.Helper()
	dir, err := os.MkdirTemp("", "ph")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if os.Getuid() != 0 {
		old := chownSocket
		chownSocket = func(string, int, int) error { return nil } // fake owners, no root
		t.Cleanup(func() { chownSocket = old })
	}
	r := rig{sock: filepath.Join(dir, "h.sock"), ses: &fakeSession{}, ring: logring.New(50)}
	opts := ServeOptions{Socket: r.sock, OwnerUID: os.Getuid(), Version: "1.2.3", Logs: r.ring, Session: r.ses,
		FirstHold: 150 * time.Millisecond, LastHold: 150 * time.Millisecond}
	if mutate != nil {
		mutate(&opts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, opts) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return")
		}
	})
	for i := 0; i < 200; i++ {
		if c, err := net.Dial("unix", r.sock); err == nil {
			c.Close()
			return r
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not start")
	return r
}

func rawCall(t *testing.T, sock string, line string) Response {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte(line))
	var resp Response
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil || (len(buf) > 0 && buf[len(buf)-1] == '\n') {
			break
		}
	}
	if err := json.Unmarshal(buf, &resp); err != nil {
		t.Fatalf("bad response %q: %v", buf, err)
	}
	return resp
}

func call(t *testing.T, sock, method string, params any) Response {
	t.Helper()
	req := Request{Method: method}
	if params != nil {
		req.Params, _ = json.Marshal(params)
	}
	line, _ := json.Marshal(req)
	return rawCall(t, sock, string(line)+"\n")
}

func openHold(t *testing.T, sock string) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte(`{"method":"hold"}` + "\n"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if n, err := c.Read(buf); err != nil || !strings.Contains(string(buf[:n]), "result") {
		t.Fatalf("hold answer %q %v", buf[:n], err)
	}
	c.SetReadDeadline(time.Time{})
	return c
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ---- wire ----

func TestOptionsRoundTrip(t *testing.T) {
	in := testOptions(t)
	wire, err := EncodeOptions(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire.Rules) != 1 || wire.Rules[0] != "suffix:example.com -> direct" {
		t.Fatalf("rules %v", wire.Rules)
	}
	out, err := DecodeOptions(wire)
	if err != nil {
		t.Fatal(err)
	}
	in.TUN, in.TUNOnly = true, true
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip differs:\n%+v\n%+v", in, out)
	}
	// Empty fields take their defaults and TUN is always on.
	wire.Mode, wire.Tier, wire.Listen, wire.LogLevel = "", "", "", ""
	out, err = DecodeOptions(wire)
	if err != nil || !out.TUN || out.Mode != "smart" || out.Tier != "auto" || out.Listen != config.DefaultListen || out.LogLevel != "warn" {
		t.Fatalf("defaults: %+v %v", out, err)
	}
}

func TestDecodeRefusals(t *testing.T) {
	good, _ := EncodeOptions(testOptions(t))
	many := make([]string, 501)
	for i := range many {
		many[i] = "example.com -> direct"
	}
	cases := map[string]func(*SessionOptions){
		"bad link":      func(s *SessionOptions) { s.Link = "https://example.com" },
		"empty link":    func(s *SessionOptions) { s.Link = "" },
		"bad mode":      func(s *SessionOptions) { s.Mode = "turbo" },
		"bad tier":      func(s *SessionOptions) { s.Tier = "warp" },
		"too many":      func(s *SessionOptions) { s.Rules = many },
		"long rule":     func(s *SessionOptions) { s.Rules = []string{strings.Repeat("a", 2000) + ".com -> direct"} },
		"bad rule":      func(s *SessionOptions) { s.Rules = []string{"nonsense"} },
		"public listen": func(s *SessionOptions) { s.Listen = "0.0.0.0:7890" },
		"name listen":   func(s *SessionOptions) { s.Listen = "localhost:7890" },
		"low port":      func(s *SessionOptions) { s.Listen = "127.0.0.1:80" },
		"high port":     func(s *SessionOptions) { s.Listen = "127.0.0.1:65536" },
		"no port":       func(s *SessionOptions) { s.Listen = "127.0.0.1" },
		"log level":     func(s *SessionOptions) { s.LogLevel = "trace" },
	}
	for name, mutate := range cases {
		s := good
		mutate(&s)
		if _, err := DecodeOptions(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s := good
	s.Rules = many[:500]
	if _, err := DecodeOptions(s); err != nil {
		t.Errorf("500 rules refused: %v", err)
	}
}

// ---- server ----

func TestServerRoundTrips(t *testing.T) {
	r := startServer(t, nil)
	var hello struct {
		Version  string `json:"version"`
		Protocol int    `json:"protocol"`
	}
	resp := call(t, r.sock, "hello", nil)
	json.Unmarshal(resp.Result, &hello)
	if hello.Version != "1.2.3" || hello.Protocol != ProtocolVersion {
		t.Fatalf("hello %s", resp.Result)
	}
	wire, _ := EncodeOptions(testOptions(t))
	hold := openHold(t, r.sock)
	defer hold.Close()
	resp = call(t, r.sock, "start", wire)
	var st clientctl.Status
	json.Unmarshal(resp.Result, &st)
	if resp.Error != "" || st.State != clientctl.StateOn || !r.ses.started.TUN {
		t.Fatalf("start: %+v %+v", resp, st)
	}
	resp = call(t, r.sock, "status", nil)
	json.Unmarshal(resp.Result, &st)
	if st.Profile != "phone" {
		t.Fatalf("status %s", resp.Result)
	}
	if resp = call(t, r.sock, "setMode", map[string]string{"mode": "global"}); resp.Error != "" || r.ses.mode != "global" {
		t.Fatalf("setMode %+v", resp)
	}
	if resp = call(t, r.sock, "setTier", map[string]string{"tier": "fast"}); resp.Error != "" || r.ses.tier != "fast" {
		t.Fatalf("setTier %+v", resp)
	}
	if resp = call(t, r.sock, "setMode", map[string]string{"mode": "x"}); resp.Error == "" {
		t.Fatal("bad mode accepted")
	}
	if resp = call(t, r.sock, "testRoutes", nil); !strings.Contains(string(resp.Result), `"fast"`) {
		t.Fatalf("testRoutes %+v", resp)
	}
	r.ring.Add("info", "engine", "hello world")
	resp = call(t, r.sock, "logs", map[string]int{"after": 0, "limit": 10})
	var logs struct {
		Entries []logring.Entry `json:"entries"`
		Next    uint64          `json:"next"`
	}
	json.Unmarshal(resp.Result, &logs)
	if len(logs.Entries) != 1 || logs.Entries[0].Source != "engine" || logs.Next != 1 {
		t.Fatalf("logs %s", resp.Result)
	}
	if resp = call(t, r.sock, "stop", nil); resp.Error != "" || r.ses.running() {
		t.Fatalf("stop %+v", resp)
	}
}

func TestServerRefusals(t *testing.T) {
	r := startServer(t, nil)
	good, _ := EncodeOptions(testOptions(t))
	bad := good
	bad.Link = "nope"
	pub := good
	pub.Listen = "0.0.0.0:7890"
	pub2 := good
	pub2.Rules = make([]string, 501)
	for name, resp := range map[string]Response{
		"invalid link": call(t, r.sock, "start", bad),
		"non-loopback": call(t, r.sock, "start", pub),
		"many rules":   call(t, r.sock, "apply", pub2),
		"unknown":      call(t, r.sock, "reboot", nil),
		"not json":     rawCall(t, r.sock, "garbage\n"),
		"oversized":    rawCall(t, r.sock, `{"method":"`+strings.Repeat("a", maxRequestLine+10)+"\"}\n"),
	} {
		if resp.Error == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	if r.ses.running() {
		t.Fatal("a refused request started a session")
	}
}

func TestPeerCheck(t *testing.T) {
	var peer int
	var mu sync.Mutex
	r := startServer(t, func(o *ServeOptions) {
		o.OwnerUID = 4242
		o.PeerUID = func(*net.UnixConn) (int, error) { mu.Lock(); defer mu.Unlock(); return peer, nil }
	})
	for _, tc := range []struct {
		uid    int
		refuse bool
	}{{4242, false}, {0, false}, {1000, true}, {4243, true}} {
		mu.Lock()
		peer = tc.uid
		mu.Unlock()
		resp := call(t, r.sock, "hello", nil)
		if refused := resp.Error == msgOtherUser; refused != tc.refuse || (!tc.refuse && resp.Error != "") {
			t.Errorf("uid %d: %+v", tc.uid, resp)
		}
	}
	// A refused peer cannot start a session either.
	mu.Lock()
	peer = 1000
	mu.Unlock()
	wire, _ := EncodeOptions(testOptions(t))
	if resp := call(t, r.sock, "start", wire); resp.Error != msgOtherUser || r.ses.running() {
		t.Fatalf("stranger started a session: %+v", resp)
	}
}

// The real kernel lookup, both ways: it reports our own uid, so an owner
// record of another user is refused unless we are root.
func TestRealPeerCredentials(t *testing.T) {
	other := os.Getuid() + 1000
	r := startServer(t, func(o *ServeOptions) { o.OwnerUID = other })
	c, err := net.Dial("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	resp := call(t, r.sock, "hello", nil)
	if os.Getuid() == 0 {
		if resp.Error != "" {
			t.Fatalf("root refused: %+v", resp)
		}
	} else if resp.Error != msgOtherUser {
		t.Fatalf("other user's helper answered: %+v", resp)
	}
	own := startServer(t, nil) // OwnerUID is our own uid
	if resp := call(t, own.sock, "hello", nil); resp.Error != "" {
		t.Fatalf("owner refused: %+v", resp)
	}
}

func TestSocketSetup(t *testing.T) {
	r := startServer(t, nil)
	fi, err := os.Stat(r.sock)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket: %v %v", fi, err)
	}
	// A regular file in the way is not removed.
	file := filepath.Join(t.TempDir(), "x")
	os.WriteFile(file, []byte("keep"), 0o600)
	err = Serve(context.Background(), ServeOptions{Socket: file, OwnerUID: os.Getuid(), Session: &fakeSession{}})
	if err == nil {
		t.Fatal("served over a regular file")
	}
	if b, _ := os.ReadFile(file); string(b) != "keep" {
		t.Fatal("file was touched")
	}
	// A stale socket is replaced.
	stale := filepath.Join(t.TempDir(), "s.sock")
	l, _ := net.Listen("unix", stale)
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ServeOptions{Socket: stale, OwnerUID: os.Getuid(), Session: &fakeSession{}})
	}()
	waitFor(t, "stale socket replaced", func() bool {
		c, err := net.Dial("unix", stale)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); err == nil {
		t.Fatal("socket left behind")
	}
}

func TestStatusAnswersDuringStart(t *testing.T) {
	r := startServer(t, nil)
	r.ses.gate = make(chan struct{})
	wire, _ := EncodeOptions(testOptions(t))
	started := make(chan Response, 1)
	go func() { started <- call(t, r.sock, "start", wire) }()
	time.Sleep(100 * time.Millisecond)
	if resp := call(t, r.sock, "status", nil); resp.Error != "" {
		t.Fatalf("status blocked or failed: %+v", resp)
	}
	close(r.ses.gate)
	if resp := <-started; resp.Error != "" {
		t.Fatalf("start: %+v", resp)
	}
}

func TestLease(t *testing.T) {
	r := startServer(t, nil)
	wire, _ := EncodeOptions(testOptions(t))

	// No hold ever arrives: the session stops after the first-hold wait.
	call(t, r.sock, "start", wire)
	if !r.ses.running() {
		t.Fatal("not running after start")
	}
	waitFor(t, "stop without a hold", func() bool { return !r.ses.running() })

	// A hold keeps it alive past both waits; closing it stops the session.
	hold := openHold(t, r.sock)
	call(t, r.sock, "start", wire)
	time.Sleep(450 * time.Millisecond)
	if !r.ses.running() {
		t.Fatal("stopped while held")
	}
	hold.Close()
	waitFor(t, "stop after the hold closed", func() bool { return !r.ses.running() })

	// A second hold taken before the grace period ends keeps it running.
	h1 := openHold(t, r.sock)
	call(t, r.sock, "start", wire)
	h1.Close()
	h2 := openHold(t, r.sock)
	time.Sleep(400 * time.Millisecond)
	if !r.ses.running() {
		t.Fatal("stopped although a hold was open")
	}
	h2.Close()
	waitFor(t, "stop after the last hold", func() bool { return !r.ses.running() })

	// An explicit stop is not followed by a second stop from the timer.
	call(t, r.sock, "start", wire)
	before := r.ses.stopCount()
	call(t, r.sock, "stop", nil)
	time.Sleep(350 * time.Millisecond)
	if r.ses.stopCount() != before+1 {
		t.Fatalf("stops: %d -> %d", before, r.ses.stopCount())
	}
}

func TestServeStopsSessionOnExit(t *testing.T) {
	ses := &fakeSession{}
	sock := filepath.Join(t.TempDir(), "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ServeOptions{Socket: sock, OwnerUID: os.Getuid(), Session: ses, FirstHold: time.Hour})
	}()
	waitFor(t, "socket", func() bool { _, err := os.Stat(sock); return err == nil })
	wire, _ := EncodeOptions(testOptions(t))
	call(t, sock, "start", wire)
	hold := openHold(t, sock)
	defer hold.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if ses.running() {
		t.Fatal("session survived shutdown")
	}
}

func TestHelperSystemDNSLifecycle(t *testing.T) {
	dns := &fakeSystemDNS{}
	ses := &fakeSession{}
	opts := ServeOptions{Session: ses, DNS: dns, FirstHold: time.Hour, LastHold: time.Hour}
	prepareSystemDNS(&opts)
	if got := dns.recorded(); !reflect.DeepEqual(got, []string{"repair"}) {
		t.Fatalf("startup DNS repair: %v", got)
	}
	ses.mu.Lock()
	provider := ses.dns
	ses.mu.Unlock()
	if provider == nil || !reflect.DeepEqual(provider(), dns.Servers()) {
		t.Fatal("helper did not pass the system DNS provider to its session")
	}
	s := &server{opts: opts}
	wire, _ := EncodeOptions(testOptions(t))
	params, _ := json.Marshal(wire)
	start := func() {
		t.Helper()
		if _, errText := s.dispatch(context.Background(), Request{Method: "start", Params: params}); errText != "" {
			t.Fatal(errText)
		}
	}
	start()
	if got := dns.recorded(); !reflect.DeepEqual(got, []string{"repair", "set"}) {
		t.Fatalf("DNS was not set after TUN start: %v", got)
	}
	if _, errText := s.dispatch(context.Background(), Request{Method: "stop"}); errText != "" {
		t.Fatal(errText)
	}
	if got := dns.recorded(); !reflect.DeepEqual(got, []string{"repair", "set", "restore"}) {
		t.Fatalf("DNS was not restored on stop: %v", got)
	}
	start()
	s.lmu.Lock()
	gen := s.gen
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.lmu.Unlock()
	s.expire(gen)
	if got := dns.recorded(); !reflect.DeepEqual(got, []string{"repair", "set", "restore", "set", "restore"}) {
		t.Fatalf("DNS was not restored at lease expiry: %v", got)
	}
	start()
	s.shutdown()
	if got := dns.recorded(); !reflect.DeepEqual(got, []string{"repair", "set", "restore", "set", "restore", "set", "restore"}) {
		t.Fatalf("DNS was not restored on helper shutdown: %v", got)
	}
}

func TestHelperSetsDNSBeforeStartupProbes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setErr error
		calls  []string
	}{
		{"success", nil, []string{"set", "probe", "restore"}},
		{"failed set", errors.New("set failed"), []string{"set", "restore"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ses := &fakeSession{}
			dns := &fakeSystemDNS{
				onSet: func() error {
					if !ses.running() {
						t.Error("DNS was set before the engine started")
					}
					return tc.setErr
				},
				onRestore: func() {
					if ses.running() {
						t.Error("DNS was restored before the engine closed")
					}
				},
			}
			ses.startProbes = func() { _ = dns.call("probe") }
			s := &server{opts: ServeOptions{Session: ses, DNS: dns, FirstHold: time.Hour}}
			defer s.disarmLease()
			wire, err := EncodeOptions(testOptions(t))
			if err != nil {
				t.Fatal(err)
			}
			params, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			_, errText := s.dispatch(t.Context(), Request{Method: "start", Params: params})
			if tc.setErr != nil {
				if errText != "Could not set system DNS: set failed" {
					t.Fatalf("start error %q", errText)
				}
			} else {
				if errText != "" {
					t.Fatal(errText)
				}
				if _, errText := s.dispatch(t.Context(), Request{Method: "stop"}); errText != "" {
					t.Fatal(errText)
				}
			}
			if got := dns.recorded(); !reflect.DeepEqual(got, tc.calls) {
				t.Fatalf("calls %v, want %v", got, tc.calls)
			}
			s.lmu.Lock()
			armed := s.active
			s.lmu.Unlock()
			if armed || ses.running() || s.dnsTUN {
				t.Fatal("engine, DNS override, or lease survived shutdown")
			}
		})
	}
}

func TestHelperApplyWithoutTUNRestoresDNS(t *testing.T) {
	dns := &fakeSystemDNS{}
	s := &server{opts: ServeOptions{DNS: dns}, dnsTUN: true}
	if err := s.updateDNS(false); err != nil {
		t.Fatal(err)
	}
	if got := dns.recorded(); !reflect.DeepEqual(got, []string{"restore"}) || s.dnsTUN {
		t.Fatalf("DNS state after non-TUN apply: %v, dnsTUN=%v", got, s.dnsTUN)
	}
}

func TestHelperSetModeLossRestoresDNS(t *testing.T) {
	dns := &fakeSystemDNS{}
	ses := &fakeSession{}
	s := &server{opts: ServeOptions{Session: ses, DNS: dns, FirstHold: time.Hour, LastHold: time.Hour}}
	opts := testOptions(t)
	opts.TUN = true
	wire, _ := EncodeOptions(opts)
	params, _ := json.Marshal(wire)
	if _, errText := s.dispatch(context.Background(), Request{Method: "start", Params: params}); errText != "" {
		t.Fatal(errText)
	}
	ses.mu.Lock()
	ses.stopOnMode = true
	ses.mu.Unlock()
	mode, _ := json.Marshal(map[string]string{"mode": "global"})
	if _, errText := s.dispatch(context.Background(), Request{Method: "setMode", Params: mode}); errText != "" {
		t.Fatal(errText)
	}
	if got := dns.recorded(); !reflect.DeepEqual(got, []string{"set", "restore"}) {
		t.Fatalf("DNS after failed mode rebuild: %v", got)
	}
}

func TestHelperApplyDoesNotSetDNSWhenSessionIsOff(t *testing.T) {
	dns := &fakeSystemDNS{}
	ses := &fakeSession{applyOff: true}
	s := &server{opts: ServeOptions{Session: ses, DNS: dns, FirstHold: time.Hour}, dnsTUN: true}
	opts := testOptions(t)
	opts.TUN = true
	wire, _ := EncodeOptions(opts)
	params, _ := json.Marshal(wire)
	if _, errText := s.dispatch(context.Background(), Request{Method: "apply", Params: params}); errText == "" {
		t.Fatal("off session accepted TUN apply")
	}
	if got := dns.recorded(); !reflect.DeepEqual(got, []string{"restore"}) || s.dnsTUN {
		t.Fatalf("DNS after applying to an off session: calls=%v dnsTUN=%v", got, s.dnsTUN)
	}
}

func TestUnexpectedSessionStopHookRestoresDNS(t *testing.T) {
	dns := &fakeSystemDNS{}
	ses := &fakeSession{}
	opts := ServeOptions{Session: ses, DNS: dns, FirstHold: time.Hour, LastHold: time.Hour}
	prepareSystemDNS(&opts)
	s := &server{opts: opts}
	s.setSessionStopHook()
	if err := s.updateDNS(true); err != nil {
		t.Fatal(err)
	}
	s.armLease()
	s.lmu.Lock()
	gen := s.gen
	s.lmu.Unlock()
	ses.endUnexpectedly()
	waitFor(t, "DNS restore after unexpected stop", func() bool {
		return reflect.DeepEqual(dns.recorded(), []string{"repair", "set", "restore"})
	})
	s.lmu.Lock()
	active := s.active
	s.lmu.Unlock()
	if active {
		t.Fatal("unexpected session stop left its lease armed")
	}
	s.expire(gen)
	time.Sleep(20 * time.Millisecond)
	if got := dns.recorded(); !reflect.DeepEqual(got, []string{"repair", "set", "restore"}) {
		t.Fatalf("unexpected stop was not disarmed: %v", got)
	}
}

// A start that takes the lock before a late stop hook keeps its DNS and lease.
func TestLateSessionStopHookKeepsANewSession(t *testing.T) {
	dns := &fakeSystemDNS{}
	ses := &fakeSession{}
	opts := ServeOptions{Session: ses, DNS: dns, FirstHold: time.Hour, LastHold: time.Hour}
	prepareSystemDNS(&opts)
	s := &server{opts: opts}
	if err := s.updateDNS(true); err != nil {
		t.Fatal(err)
	}
	s.armLease()
	ses.mu.Lock()
	ses.started = &clientctl.Options{}
	ses.mu.Unlock()
	s.sessionStopped()
	s.lmu.Lock()
	active := s.active
	s.lmu.Unlock()
	if got := dns.recorded(); !active || !reflect.DeepEqual(got, []string{"repair", "set"}) {
		t.Fatalf("late stop hook undid a live session: lease=%v dns=%v", active, got)
	}
}

// ---- install files ----

func TestRenderPlist(t *testing.T) {
	got := RenderPlist("/Library/PrivilegedHelperTools/io.pipe.helper")
	for _, want := range []string{
		"<key>Label</key>\n\t<string>io.pipe.helper</string>",
		"<string>/Library/PrivilegedHelperTools/io.pipe.helper</string>\n\t\t<string>helper</string>\n\t\t<string>run</string>",
		"<key>RunAtLoad</key>\n\t<true/>", "<key>KeepAlive</key>\n\t<true/>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("plist lacks %q:\n%s", want, got)
		}
	}
	if !strings.Contains(RenderPlist("/a&b/<x>"), "/a&amp;b/&lt;x&gt;") {
		t.Error("plist does not escape")
	}
}

func TestRenderUnit(t *testing.T) {
	got := RenderUnit("/usr/local/lib/pipe/pipe-helper")
	for _, want := range []string{
		"ExecStart=/usr/local/lib/pipe/pipe-helper helper run\n", "Restart=always\n", "RestartSec=2\n",
		"RuntimeDirectory=pipe-helper\n", "NoNewPrivileges=yes\n", "ProtectHome=yes\n", "PrivateTmp=yes\n",
		"WantedBy=multi-user.target\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("unit lacks %q:\n%s", want, got)
		}
	}
}

func fakeEnv(t *testing.T) (env, *[]string, string) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "pipe")
	os.WriteFile(exe, []byte("binary"), 0o700)
	var cmds []string
	return env{
		paths: Paths{
			Binary:  filepath.Join(dir, "lib", "pipe-helper"),
			Service: filepath.Join(dir, "svc", "pipe-helper.service"),
			Owner:   filepath.Join(dir, "etc", "owner"),
			Socket:  filepath.Join(dir, "run", "helper.sock"),
		},
		svcctl: "ctl",
		exe:    func() (string, error) { return exe, nil },
		run: func(name string, args ...string) error {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			return nil
		},
		chown: func(*os.File) error { return nil },
	}, &cmds, dir
}

func TestInstallAndRemoveFiles(t *testing.T) {
	e, cmds, dir := fakeEnv(t)
	os.MkdirAll(filepath.Dir(e.paths.Service), 0o755)
	os.MkdirAll(filepath.Dir(e.paths.Socket), 0o755)
	os.WriteFile(e.paths.Socket, nil, 0o600)
	bystander := filepath.Join(dir, "etc", "other")
	if err := install(e, "linux", 1000); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(e.paths.Binary)
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("binary: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(e.paths.Binary); string(b) != "binary" {
		t.Fatal("binary content")
	}
	if b, _ := os.ReadFile(e.paths.Owner); string(b) != "1000\n" {
		t.Fatalf("owner %q", b)
	}
	if b, _ := os.ReadFile(e.paths.Service); string(b) != RenderUnit(e.paths.Binary) {
		t.Fatal("unit content")
	}
	want := []string{"ctl daemon-reload", "ctl enable pipe-helper.service", "ctl restart pipe-helper.service"}
	if got := *cmds; !reflect.DeepEqual(got, want) {
		t.Fatalf("commands %v", *cmds)
	}
	if entries, _ := os.ReadDir(filepath.Dir(e.paths.Binary)); len(entries) != 1 {
		t.Fatalf("temp files left: %v", entries)
	}

	os.WriteFile(bystander, nil, 0o600)
	if err := remove(e, "linux"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{e.paths.Binary, e.paths.Service, e.paths.Owner, e.paths.Socket} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s remains", p)
		}
	}
	if _, err := os.Stat(bystander); err != nil {
		t.Fatal("removed something else")
	}
	os.Remove(bystander)
	// With the owner dir empty it goes too.
	install(e, "linux", 1000)
	remove(e, "linux")
	if _, err := os.Stat(filepath.Dir(e.paths.Owner)); err == nil {
		t.Fatal("empty owner dir remains")
	}
}

func TestInstallChecksInstalledHelperRelease(t *testing.T) {
	for _, tc := range []struct {
		name, installed string
		newer           bool
	}{
		{"newer", "9999.0.0-alpha", true},
		{"older", "0.0.1-alpha", false},
		{"same", version.Version, false},
		{"unmarked", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, cmds, _ := fakeEnv(t)
			if err := install(e, "linux", 1000); err != nil {
				t.Fatal(err)
			}
			prefix := strings.TrimSuffix(version.ReleaseIdentity, version.Version+"\x00")
			installed := "fixture installed helper"
			if tc.installed != "" {
				installed += prefix + tc.installed + "\x00"
			}
			if err := os.WriteFile(e.paths.Binary, []byte(installed), 0755); err != nil {
				t.Fatal(err)
			}
			*cmds = nil
			wantBinary, wantOwner := "binary", "1001\n"
			err := install(e, "linux", 1001)
			if tc.newer {
				if !errors.Is(err, ErrNewer) || len(*cmds) != 0 {
					t.Fatalf("downgrade returned %v and ran %v", err, *cmds)
				}
				wantBinary, wantOwner = installed, "1000\n"
			} else if err != nil {
				t.Fatalf("eligible install failed: %v", err)
			}
			for path, want := range map[string]string{e.paths.Binary: wantBinary, e.paths.Owner: wantOwner} {
				if got, err := os.ReadFile(path); err != nil || string(got) != want {
					t.Errorf("%s = %q, %v, want %q", path, got, err, want)
				}
			}
		})
	}
}

func TestInstallDarwinCommands(t *testing.T) {
	e, cmds, _ := fakeEnv(t)
	if err := install(e, "darwin", 501); err != nil {
		t.Fatal(err)
	}
	want := []string{"ctl bootout system/io.pipe.helper", "ctl bootstrap system " + e.paths.Service}
	if got := *cmds; !reflect.DeepEqual(got, want) {
		t.Fatalf("commands %v", *cmds)
	}
	if b, _ := os.ReadFile(e.paths.Service); string(b) != RenderPlist(e.paths.Binary) {
		t.Fatal("plist content")
	}
	e.run = func(string, ...string) error { return errors.New("x") }
	if err := install(e, "darwin", 501); err == nil {
		t.Fatal("bootstrap failure ignored")
	}
}

func TestRemoveDarwinRestoresAndRemovesArmedDNS(t *testing.T) {
	e, cmds, dir := fakeEnv(t)
	for _, path := range []string{e.paths.Binary, e.paths.Owner, e.paths.Service, e.paths.Socket} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("helper"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	armed := filepath.Join(dir, "support", "io.pipe.helper", "dns.armed")
	if err := os.MkdirAll(filepath.Dir(armed), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(armed, []byte("saved"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldPath, oldRestore := helperDNSArmedPath, restoreHelperDNS
	helperDNSArmedPath = func() string { return armed }
	defer func() { helperDNSArmedPath, restoreHelperDNS = oldPath, oldRestore }()
	called := false
	restoreHelperDNS = func() error {
		called = true
		if _, err := os.Stat(armed); err != nil {
			t.Fatalf("armed snapshot missing before restore: %v", err)
		}
		if len(*cmds) == 0 || (*cmds)[0] != "ctl bootout system/"+Label {
			t.Fatalf("DNS restore ran before bootout: %v", *cmds)
		}
		return nil
	}
	if err := remove(e, "darwin"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("DNS restore was not called")
	}
	if _, err := os.Stat(armed); !os.IsNotExist(err) {
		t.Fatalf("armed snapshot remains: %v", err)
	}
	for _, path := range []string{e.paths.Binary, e.paths.Owner, e.paths.Service, e.paths.Socket} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("helper file remains: %s (%v)", path, err)
		}
	}
}

func TestInstallRefusesBadUID(t *testing.T) {
	for _, uid := range []int{0, -1, 999999999} {
		if err := checkUID(uid); err == nil {
			t.Errorf("uid %d accepted", uid)
		}
	}
}
