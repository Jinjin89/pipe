// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"pipe/internal/clientctl"
	"pipe/internal/config"
	"pipe/internal/failover"
	"pipe/internal/helper"
	"pipe/internal/link"
	"pipe/internal/logring"
	"pipe/internal/sysproxy"
	"pipe/internal/webview"
)

// Config wires the server to its collaborators.
type Config struct {
	Dir         string // config dir (app.json, ui-profile, ...)
	ProfilesDir string
	Controller  Controller
	Helper      Helper // nil when this OS has no Pipe Helper (TUN unavailable)
	Logs        *logring.Ring
	ParseRule   func(text string) (config.Rule, error)
	Proxy       *sysproxy.Manager
	Autostart   Autostart
	Version     string
	Exe         string // path used for start-at-login
	ShowSecret  string // X-Pipe-Show secret; random when empty
	OnShow      func() // called for a valid /internal/show
	OnQuit      func() // called after /api/quit has answered

	probeProfile  func(context.Context, clientctl.ProbeOptions) clientctl.ProfileTestResult
	copySensitive func(string) error
	extractUpdate func(string) (*os.File, string, func(), error)
	applyPortable func(*os.File, string) error
}

// Server is the local HTTP API and static UI.
type Server struct {
	cfg      Config
	store    *Store
	profiles *Profiles
	sess     *sessions
	updates  *desktopUpdates
	host     atomic.Value // "127.0.0.1:PORT"

	mu            sync.Mutex // serializes connect/disconnect and proxy state
	closed        bool
	proxyOn       bool
	proxyErr      string
	proxyRestore  proxyRestoreAction
	appliedUpdate string       // version installed for the next launch
	via           atomic.Value // "", "proxy" or "tun": which controller owns the session; written under mu
	changes       chan struct{}

	profileTests     map[string]bool           // saved names with probes in flight, true for invalidated results, under mu
	profileTestDone  chan struct{}             // closed and replaced when a probe releases its slot, under mu
	profileCountries map[profileExitKey]string // session cache under mu
	liveProfile      profileIdentity           // under mu
}

func NewServer(cfg Config) *Server {
	if cfg.ShowSecret == "" {
		cfg.ShowSecret = randomToken()
	}
	if cfg.probeProfile == nil {
		cfg.probeProfile = clientctl.TestProfile
	}
	if cfg.copySensitive == nil {
		cfg.copySensitive = webview.CopySensitive
	}
	profiles := NewProfiles(cfg.ProfilesDir)
	s := &Server{
		cfg:      cfg,
		store:    openStore(cfg.Dir+string(os.PathSeparator)+"app.json", profiles),
		profiles: profiles,
		sess:     newSessions(),
		changes:  make(chan struct{}, 1),

		profileTests:     make(map[string]bool),
		profileTestDone:  make(chan struct{}),
		profileCountries: make(map[profileExitKey]string),
	}
	s.updates = newDesktopUpdates(s)
	s.host.Store("")
	if cfg.Helper != nil {
		cfg.Helper.OnChange(s.notify)
		s.reattachTUNLocked()
	}
	return s
}

// SetHost records the exact Host header value (127.0.0.1:PORT) the server accepts.
func (s *Server) SetHost(host string) { s.host.Store(host) }
func (s *Server) hostValue() string   { return s.host.Load().(string) }

// NewNonce makes a boot nonce for the window URL fragment.
func (s *Server) NewNonce() string { return s.sess.NewNonce() }

// ShowSecret is shared with later instances through app.instance.
func (s *Server) ShowSecret() string { return s.cfg.ShowSecret }

// Settings returns the saved settings.
func (s *Server) Settings() Settings { return s.store.Snapshot().Settings }

// StateIsOff reports whether the app can exit when its window closes.
func (s *Server) StateIsOff() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proxyRestore != proxyRestoreNone {
		return false
	}
	if _, reattached := s.reattachTUNLocked(); reattached {
		return false
	}
	st := s.active().Status()
	if s.getVia() == viaTUN && s.cfg.Helper != nil {
		return tunStopped(st)
	}
	return !running(st)
}

// Changes fires (coalesced) after every state transition: connect,
// disconnect, mode, tier, settings, Pipe Helper changes, a helper session
// ending. Front ends wait on it instead of polling Snapshot. One reader.
func (s *Server) Changes() <-chan struct{} { return s.changes }

func (s *Server) notify() {
	select {
	case s.changes <- struct{}{}:
	default:
	}
}

const (
	viaProxy = "proxy"
	viaTUN   = "tun"
)

type proxyRestoreAction int

const (
	proxyRestoreNone proxyRestoreAction = iota
	proxyRestoreOnly
	proxyRestoreAndDisconnect
)

func (s *Server) getVia() string { v, _ := s.via.Load().(string); return v }
func (s *Server) setVia(v string) {
	s.via.Store(v)
	if v == "" {
		s.liveProfile = profileIdentity{}
	}
}

func tunStopped(st clientctl.Status) bool { return st.State == clientctl.StateOff && !st.Guarded }

func (s *Server) holdHelperSession(st clientctl.Status) {
	if st.Guarded || running(st) {
		if h, ok := s.cfg.Helper.(interface{ HoldSession() }); ok {
			h.HoldSession()
		}
	}
}

// reattachTUNLocked checks for a session left by a previous app instance.
func (s *Server) reattachTUNLocked() (clientctl.Status, bool) {
	h := s.cfg.Helper
	if s.closed || s.getVia() != "" || h == nil {
		return clientctl.Status{}, false
	}
	st := h.Status()
	if tunStopped(st) {
		return st, false
	}
	if !st.Guarded && !running(st) {
		// An installed Helper with indeterminate status can still own capture.
		switch h.Info().State {
		case helper.StateOK, helper.StateOutdated, helper.StateNewer, helper.StateError:
		default:
			return st, false
		}
	}
	s.setVia(viaTUN)
	s.holdHelperSession(st)
	return st, true
}

// active is the controller that owns the current session: Pipe Helper while
// the session runs through TUN, otherwise the local one (§8.5).
func (s *Server) active() Controller {
	if s.getVia() == viaTUN && s.cfg.Helper != nil {
		return s.cfg.Helper
	}
	return s.cfg.Controller
}

// helperInfo is Pipe Helper's state, unsupported when this OS has none.
func (s *Server) helperInfo() helper.Info {
	if s.cfg.Helper == nil {
		return helper.Info{State: helper.StateUnsupported, Note: "TUN isn't available on this system yet."}
	}
	return s.cfg.Helper.Info()
}

type apiError struct {
	status int
	msg    string
	index  *int
	code   string
}

func (e *apiError) Error() string { return e.msg }

func bad(msg string) *apiError { return &apiError{status: http.StatusBadRequest, msg: msg} }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	api := func(method, path string, h func(*http.Request) (any, error)) {
		mux.HandleFunc(method+" "+path, func(w http.ResponseWriter, r *http.Request) {
			v, err := h(r)
			if err != nil {
				writeError(w, err)
				return
			}
			if v == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeJSON(w, http.StatusOK, v)
		})
	}
	mux.HandleFunc("POST /api/session", s.handleSession)
	mux.HandleFunc("POST /internal/show", s.handleShow)
	api("POST", "/api/session/end", s.endSession)
	api("GET", "/api/status", func(*http.Request) (any, error) { return s.status(), nil })
	api("POST", "/api/connect", func(*http.Request) (any, error) { return s.connect() })
	api("POST", "/api/disconnect", func(*http.Request) (any, error) { return s.disconnect() })
	api("PUT", "/api/mode", s.putMode)
	api("PUT", "/api/tier", s.putTier)
	api("POST", "/api/routes/test", s.testRoutes)
	api("GET", "/api/profiles", func(*http.Request) (any, error) { return s.listProfiles(), nil })
	api("POST", "/api/profiles/test-complete", s.completeProfileBatch)
	api("POST", "/api/profiles/preview", s.previewProfile)
	api("POST", "/api/profiles", s.addProfile)
	api("PATCH", "/api/profiles/{name}", s.renameProfile)
	api("DELETE", "/api/profiles/{name}", s.deleteProfile)
	api("PUT", "/api/profiles/{name}/relay", s.putProfileRelay)
	api("POST", "/api/profiles/{name}/activate", s.activateProfile)
	api("POST", "/api/profiles/{name}/test", s.testProfile)
	api("POST", "/api/profiles/{name}/secret", s.profileSecret)
	api("POST", "/api/profiles/{name}/copy", s.copyProfileSecret)
	api("GET", "/api/routing", func(*http.Request) (any, error) { return s.routing(), nil })
	api("PUT", "/api/routing", s.putRouting)
	api("GET", "/api/settings", func(*http.Request) (any, error) { return s.store.Snapshot().Settings, nil })
	api("PUT", "/api/settings", s.putSettings)
	api("GET", "/api/updates", s.updateStatus)
	api("POST", "/api/updates/check", s.checkUpdate)
	api("POST", "/api/updates/download", s.downloadUpdate)
	api("POST", "/api/updates/reveal", s.revealUpdate)
	api("POST", "/api/updates/apply", s.applyUpdate)
	api("GET", "/api/logs", s.getLogs)
	api("DELETE", "/api/logs", func(*http.Request) (any, error) { s.cfg.Logs.Clear(); return nil, nil })
	api("GET", "/api/helper", func(*http.Request) (any, error) { return s.helperInfo(), nil })
	api("POST", "/api/helper/install", func(*http.Request) (any, error) { return s.installHelper() })
	api("POST", "/api/helper/remove", func(*http.Request) (any, error) { return s.removeHelper() })
	api("GET", "/api/about", func(*http.Request) (any, error) { return s.about(), nil })
	mux.HandleFunc("POST /api/quit", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Close(); err != nil {
			writeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if s.cfg.OnQuit != nil {
			go s.cfg.OnQuit()
		}
	})
	mux.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, &apiError{status: http.StatusNotFound, msg: "Not found."})
	}))
	mux.Handle("/", staticHandler())
	return s.guard(mux)
}

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		want := s.hostValue()
		if want == "" || r.Host != want {
			writeError(w, &apiError{status: http.StatusForbidden, msg: "Forbidden."})
			return
		}
		origin := "http://" + want
		switch {
		case r.URL.Path == "/internal/show":
			// Called by another pipe process, never by a browser: no Origin.
			if _, has := r.Header["Origin"]; has {
				writeError(w, &apiError{status: http.StatusForbidden, msg: "Forbidden."})
				return
			}
		case r.URL.Path == "/api/session":
			if r.Header.Get("Origin") != origin || r.Header.Get("X-Pipe-CSRF") != "1" || !sameOrigin(r, origin) {
				writeError(w, &apiError{status: http.StatusForbidden, msg: "Forbidden."})
				return
			}
		case strings.HasPrefix(r.URL.Path, "/api/"):
			if code := s.authorize(r, origin); code != 0 {
				msg := "Forbidden."
				if code == http.StatusUnauthorized {
					msg = "Open Pipe again from your apps."
				}
				writeError(w, &apiError{status: code, msg: msg})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin enforces Origin (required on POST) and Sec-Fetch-Site.
func sameOrigin(r *http.Request, origin string) bool {
	for _, site := range r.Header.Values("Sec-Fetch-Site") {
		if site != "same-origin" {
			return false
		}
	}
	got := r.Header.Get("Origin")
	if got == "" {
		return r.Method == http.MethodGet || r.Method == http.MethodHead
	}
	return got == origin
}

// authorize checks the bearer (401) and origin and CSRF rules (403).
func (s *Server) authorize(r *http.Request, origin string) int {
	if !s.sess.ValidBearer(r) {
		return http.StatusUnauthorized
	}
	if !sameOrigin(r, origin) {
		return http.StatusForbidden
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if r.Header.Get("X-Pipe-CSRF") != "1" || r.Header.Get("Origin") != origin {
			return http.StatusForbidden
		}
	}
	s.updateWindowSession(r, false)
	return 0
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Nonce string `json:"nonce"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, err)
		return
	}
	token, ok := s.sess.Redeem(body.Nonce)
	if !ok {
		writeError(w, &apiError{status: http.StatusUnauthorized, msg: "Open Pipe again from your apps."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *Server) endSession(r *http.Request) (any, error) {
	s.updateWindowSession(r, true)
	return nil, nil
}

// updateWindowSession records activity or revokes the bearer after the request
// has passed both authentication and the origin checks.
func (s *Server) updateWindowSession(r *http.Request, end bool) {
	_, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	s.sess.mu.Lock()
	defer s.sess.mu.Unlock()
	until := s.sess.now().Add(sessionTTL)
	for i, session := range s.sess.tokens {
		if subtle.ConstantTimeCompare([]byte(session.value), []byte(token)) == 1 {
			if end {
				s.sess.tokens[i] = sessionToken{}
			} else {
				s.sess.tokens[i].until = until
			}
		}
	}
}

func (s *Server) handleShow(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Pipe-Show")), []byte(s.cfg.ShowSecret)) != 1 {
		writeError(w, &apiError{status: http.StatusForbidden, msg: "Forbidden."})
		return
	}
	if s.cfg.OnShow != nil {
		go s.cfg.OnShow()
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		switch {
		case errors.Is(err, helper.ErrOutdated):
			ae = &apiError{status: http.StatusConflict, msg: err.Error(), code: "needHelper"}
		case errors.Is(err, helper.ErrNewer):
			ae = &apiError{status: http.StatusConflict, msg: err.Error(), code: "helperNewer"}
		default:
			ae = &apiError{status: http.StatusInternalServerError, msg: friendly(err)}
		}
	}
	body := map[string]any{"error": ae.msg}
	if ae.code != "" {
		body["code"] = ae.code
	}
	if ae.index != nil {
		body["index"] = *ae.index
	}
	writeJSON(w, ae.status, body)
}

func friendly(err error) string {
	msg := err.Error()
	if msg == "" {
		return "Something went wrong."
	}
	return strings.ToUpper(msg[:1]) + msg[1:]
}

const (
	maxBody      = 64 << 10
	maxRulesBody = 256 << 10
)

func readJSON(r *http.Request, v any, limit ...int64) error {
	max := int64(maxBody)
	if len(limit) > 0 {
		max = limit[0]
	}
	data, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, max))
	if err != nil {
		return bad("That request was too large.")
	}
	if len(data) == 0 {
		data = []byte("{}")
	}
	if err := json.Unmarshal(data, v); err != nil {
		return bad("That request wasn't understood.")
	}
	return nil
}

// StatusResponse is the desktop-wrapped status (§2.4, §8.5).
type StatusResponse struct {
	clientctl.Status
	SystemProxy     string               `json:"systemProxy"`
	SystemProxyNote string               `json:"systemProxyNote"`
	Via             string               `json:"via"`    // proxy|tun while a session runs, else ""
	Helper          helper.Info          `json:"helper"` // always set; unsupported when Config.Helper is nil
	Measurement     *profileTestResponse `json:"measurement,omitempty"`
}

func (s *Server) status() StatusResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked()
}

func (s *Server) statusLocked() StatusResponse {
	switch s.proxyRestore {
	case proxyRestoreOnly:
		_ = s.clearProxyLocked()
	case proxyRestoreAndDisconnect:
		_ = s.Shutdown()
	}
	st, reattached := s.reattachTUNLocked()
	if !reattached {
		st = s.active().Status()
	}
	via := s.getVia()
	if via == viaTUN {
		// A failed status RPC leaves the Helper's session indeterminate.
		if s.cfg.Helper == nil || tunStopped(st) {
			s.setVia("")
			via = ""
		} else if !reattached {
			s.holdHelperSession(st)
		}
	} else if !running(st) && s.proxyRestore == proxyRestoreNone && (via != "" || s.proxyOn) {
		if !s.proxyOn || s.clearProxyLocked() == nil {
			s.setVia("")
			via = ""
		}
	}
	savedMode, savedTier, savedPort, measurement := s.store.StatusFields(s.profiles)
	if st.Mode == "" || st.TierPreference == "" {
		// While off the controller has no choice yet; show the saved ones.
		if st.Mode == "" {
			st.Mode = savedMode
		}
		if st.TierPreference == "" {
			st.TierPreference = savedTier
		}
	}
	if st.Routes == nil {
		st.Routes = map[string]clientctl.RouteLatency{}
	}
	resp := StatusResponse{Status: st, SystemProxy: "off", Via: via, Helper: s.helperInfo(), Measurement: measurement}
	listen := st.Listen
	if listen == "" {
		listen = fmt.Sprintf("127.0.0.1:%d", savedPort)
	}
	switch {
	case via == viaTUN:
		// The system proxy isn't used in TUN mode.
	case s.proxyErr != "":
		resp.SystemProxy, resp.SystemProxyNote = "error", s.proxyErr
	case s.proxyOn:
		resp.SystemProxy = "on"
	case !s.cfg.Proxy.Supported() && (st.State == "on" || st.State == "connecting"):
		resp.SystemProxy = "unsupported"
		resp.SystemProxyNote = "Local proxy only: set your apps to " + listen
	}
	return resp
}

func (s *Server) options(name string) (clientctl.Options, string, error) {
	data := s.store.Snapshot()
	profile, rev, err := s.profiles.load(name)
	if err != nil {
		return clientctl.Options{}, "", bad("Add your server first.")
	}
	opts := clientctl.Options{
		Profile: profile, Mode: data.Mode, Tier: failover.Tier(data.Tier),
		IPv6: data.Settings.IPv6, TUN: s.getVia() == viaTUN, Listen: fmt.Sprintf("127.0.0.1:%d", data.Settings.ListenPort),
		LogLevel: logLevel(data.Settings), Relay: data.relayFor(name, profile.Host).enabledCode(),
	}
	for i, r := range data.Rules {
		rule, err := s.parseRule(r)
		if err != nil {
			return opts, "", &apiError{status: 400, msg: err.Error(), index: &i}
		}
		opts.Rules = append(opts.Rules, rule)
	}
	return opts, rev, nil
}

func logLevel(st Settings) string {
	if st.LogDetail == "connections" {
		return "info"
	}
	return "warn"
}

func (s *Server) parseRule(r RuleObject) (config.Rule, error) {
	text, err := RuleText(r)
	if err != nil {
		return config.Rule{}, err
	}
	rule, err := s.cfg.ParseRule(text)
	if err != nil || !fieldMatches(r.Type, rule.Field) {
		return config.Rule{}, errors.New("That rule isn't valid: check the value.")
	}
	return rule, nil
}

// fieldMatches makes sure the parser read the value as the type the user chose.
func fieldMatches(typ, field string) bool {
	switch typ {
	case "domain":
		return field == "domain"
	case "suffix":
		return field == "domain_suffix"
	case "keyword":
		return field == "domain_keyword"
	case "ip":
		return field == "ip_cidr"
	case "app":
		return field == "process_name" || field == "process_path"
	}
	return false
}

func running(st clientctl.Status) bool { return st.State == "on" || st.State == "connecting" }

func (s *Server) connect() (any, error) {
	defer s.notify()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connectLocked()
}

// connectLocked starts the saved profile through Pipe Helper (TUN) or the
// local controller, stopping the other one first. s.mu is held.
func (s *Server) connectLocked() (any, error) {
	if s.closed {
		return nil, errors.New("Pipe is quitting")
	}
	s.reattachTUNLocked()
	data := s.store.Snapshot()
	if data.Active == "" {
		return nil, bad("Add your server first.")
	}
	opts, rev, err := s.options(data.Active)
	if err != nil {
		return nil, err
	}
	if data.Settings.TUN {
		if s.cfg.Helper == nil {
			return nil, bad("TUN isn't available on this system yet.")
		}
		if err := s.needHelper(); err != nil {
			return nil, err
		}
		if s.getVia() != viaTUN {
			if err := s.clearProxyLocked(); err != nil {
				return nil, err
			}
			if err := s.cfg.Controller.Stop(); err != nil {
				return nil, err
			}
			s.setVia("")
		}
		opts.TUN = true
		s.setVia(viaTUN)
		s.updates.CancelDirect()
		if err := s.cfg.Helper.Start(opts); err != nil {
			st := s.cfg.Helper.Status()
			if tunStopped(st) {
				s.setVia("")
			} else {
				s.holdHelperSession(st)
			}
			if errors.Is(err, helper.ErrOutdated) || errors.Is(err, helper.ErrNewer) {
				return nil, err
			}
			return nil, &apiError{status: http.StatusBadGateway, msg: friendly(err)}
		}
		s.liveProfile = profileIdentity{data.Active, rev}
		return s.statusLocked(), nil
	}
	if s.proxyRestore != proxyRestoreNone {
		if err := s.clearProxyLocked(); err != nil {
			return nil, err
		}
	}
	if err := s.stopHelperLocked(); err != nil {
		return nil, err
	}
	s.setVia("")
	opts.TUN = false
	s.updates.CancelDirect()
	if err := s.cfg.Controller.Start(opts); err != nil {
		return nil, &apiError{status: http.StatusBadGateway, msg: friendly(err)}
	}
	s.setVia(viaProxy)
	s.liveProfile = profileIdentity{data.Active, rev}
	if data.Settings.SystemProxy {
		s.setProxyLocked(data.Settings.ListenPort)
	}
	return s.statusLocked(), nil
}

// needHelper reports which component needs an update when the Helper is incompatible.
func (s *Server) needHelper() error {
	if s.cfg.Helper == nil {
		return bad("TUN isn't available on this system yet.")
	}
	info := s.cfg.Helper.Info()
	switch info.State {
	case helper.StateOK:
		return nil
	case helper.StateNewer:
		return helper.ErrNewer
	}
	msg := info.Note
	if msg == "" {
		msg = "Pipe Helper isn't ready."
	}
	return &apiError{status: http.StatusConflict, msg: msg, code: "needHelper"}
}

func (s *Server) setProxyLocked(port int) {
	s.proxyErr = ""
	err := s.cfg.Proxy.Set("127.0.0.1", port)
	switch {
	case err == nil:
		s.proxyOn = true
	case errors.Is(err, sysproxy.ErrUnsupported):
		s.proxyOn = false
	default:
		s.proxyOn = false
		s.proxyErr = "Couldn't change the system proxy. Set your apps to 127.0.0.1:" + strconv.Itoa(port)
	}
}

func (s *Server) clearProxyLocked() error {
	if err := s.cfg.Proxy.Clear(); err != nil {
		if s.proxyRestore == proxyRestoreNone {
			s.proxyRestore = proxyRestoreOnly
		}
		err = fmt.Errorf("couldn't restore the system proxy: %w", err)
		s.proxyErr = friendly(err)
		return err
	}
	s.proxyOn, s.proxyErr = false, ""
	s.proxyRestore = proxyRestoreNone
	return nil
}

func (s *Server) stopHelperLocked() error {
	if s.getVia() != viaTUN {
		return nil
	}
	if h := s.cfg.Helper; h != nil {
		if err := h.Stop(); err != nil {
			return fmt.Errorf("couldn't stop Pipe Helper: %w", err)
		}
		// An externally removed Helper can no longer send an Off status.
		if !tunStopped(h.Status()) {
			state := h.Info().State
			if state != helper.StateMissing && state != helper.StateUnsupported {
				return errors.New("couldn't confirm that Pipe Helper stopped")
			}
		}
	}
	s.setVia("")
	return nil
}

func (s *Server) disconnect() (any, error) {
	defer s.notify()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.Shutdown(); err != nil {
		return nil, err
	}
	return s.statusLocked(), nil
}

// Shutdown disconnects both the local session and Pipe Helper's, and
// restores the system proxy. The caller holds s.mu or is the only user
// (process exit).
func (s *Server) Shutdown() error {
	s.reattachTUNLocked()
	if err := s.clearProxyLocked(); err != nil {
		s.proxyRestore = proxyRestoreAndDisconnect
		return err
	}
	if err := s.stopHelperLocked(); err != nil {
		return err
	}
	if err := s.cfg.Controller.Stop(); err != nil {
		return err
	}
	s.setVia("")
	return nil
}

// Close is Shutdown for callers that don't hold the lock.
func (s *Server) Close() error {
	defer s.notify()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if err := s.Shutdown(); err != nil {
		return err
	}
	s.closed = true
	s.sess.close()
	s.updates.Close()
	return nil
}

// ConnectIfConfigured connects at launch when the user asked for it.
func (s *Server) ConnectIfConfigured() error {
	if s.getVia() == viaTUN || !s.store.Snapshot().Settings.ConnectOnLaunch {
		return nil
	}
	_, err := s.connect()
	return err
}

// transact saves a change and applies it live while holding s.mu. If the live
// step fails the saved data is rolled back and, best effort, re-applied.
func (s *Server) transact(mutate func(*appData), live func() error) error {
	old := s.store.Snapshot()
	if err := s.store.Update(mutate); err != nil {
		return err
	}
	if live == nil {
		return nil
	}
	if err := live(); err != nil {
		_ = s.store.Update(func(d *appData) { *d = old })
		if running(s.active().Status()) {
			_ = s.applyLiveLocked(true)
		}
		return err
	}
	return nil
}

func (s *Server) putMode(r *http.Request) (any, error) {
	var body struct {
		Mode string `json:"mode"`
	}
	if err := readJSON(r, &body); err != nil {
		return nil, err
	}
	return s.setMode(body.Mode)
}

func (s *Server) setMode(mode string) (any, error) {
	defer s.notify()
	body := struct{ Mode string }{mode}
	if !validMode(body.Mode) {
		return nil, bad("Mode must be Smart, Global or Direct.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.transact(func(d *appData) { d.Mode = body.Mode }, func() error {
		if running(s.active().Status()) {
			return s.active().SetMode(body.Mode)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.statusLocked(), nil
}

func (s *Server) putTier(r *http.Request) (any, error) {
	var body struct {
		Tier string `json:"tier"`
	}
	if err := readJSON(r, &body); err != nil {
		return nil, err
	}
	return s.setTier(body.Tier)
}

func (s *Server) setTier(tier string) (any, error) {
	defer s.notify()
	body := struct{ Tier string }{tier}
	if !validTier(body.Tier) {
		return nil, bad("Route must be Auto, Fast, Stealth or Rescue.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.transact(func(d *appData) { d.Tier = body.Tier }, func() error {
		if running(s.active().Status()) {
			return s.active().SetTier(body.Tier)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.statusLocked(), nil
}

func (s *Server) testRoutes(r *http.Request) (any, error) {
	return s.measureProfile(r, true)
}

func (s *Server) listProfiles() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	data := s.store.Snapshot()
	profiles := s.profiles.List()
	for i := range profiles {
		profiles[i].Relay = data.relayFor(profiles[i].Name, profiles[i].Server)
		profiles[i].Measurement = data.measurementFor(profiles[i])
	}
	result := map[string]any{"active": data.Active, "profiles": profiles}
	if !data.LastProfileBatch.IsZero() {
		result["lastTestedAt"] = data.LastProfileBatch
	}
	return result
}

func (s *Server) previewProfile(r *http.Request) (any, error) {
	var body struct {
		Link string `json:"link"`
	}
	if err := readJSON(r, &body); err != nil {
		return nil, err
	}
	profile, info, err := Preview(body.Link)
	if err != nil {
		return nil, bad(err.Error())
	}
	result := map[string]any{"name": info.Name, "server": info.Server, "cdn": profile.CDNEndpoint(), "routes": info.Routes,
		"fingerprint": info.Fingerprint, "exists": s.profiles.Exists(info.Name)}
	if profile.HTTPSProxy != "" {
		result["httpsProxy"] = profile.HTTPSProxy
	}
	if port := profile.FastEndpointPort(); port != link.DefaultPort {
		result["fast"] = net.JoinHostPort(profile.Host, strconv.Itoa(int(port)))
	}
	if port := profile.StealthEndpointPort(); port != link.DefaultPort {
		result["stealth"] = net.JoinHostPort(profile.Host, strconv.Itoa(int(port)))
	}
	return result, nil
}

func (s *Server) addProfile(r *http.Request) (any, error) {
	var body struct{ Link, Name string }
	if err := readJSON(r, &body); err != nil {
		return nil, err
	}
	profile, _, err := Preview(body.Link)
	if err != nil {
		return nil, bad(err.Error())
	}
	name := DefaultName(profile)
	if strings.TrimSpace(body.Name) != "" {
		var ok bool
		if name, ok = NormalizeName(body.Name); !ok {
			return nil, bad("Use 1 to 64 letters, numbers, - or _ for the name.")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if stored, ok := s.profiles.Resolve(name); ok {
		name = stored
	}
	previousRelay, hasRelay := s.store.Snapshot().Relays[name]
	clearRelay := false
	if hasRelay {
		previous, err := s.profiles.Load(name)
		clearRelay = err != nil || !sameServerHost(previous.Host, profile.Host)
	}
	if clearRelay {
		// Save the relay removal before the new link can refer to another server.
		if err := s.store.Update(func(d *appData) { delete(d.Relays, name) }); err != nil {
			return nil, err
		}
	}
	info, err := s.profiles.Save(name, profile)
	if err != nil {
		if clearRelay {
			err = errors.Join(err, s.store.Update(func(d *appData) { d.setRelay(name, previousRelay) }))
		}
		return nil, err
	}
	s.invalidateProfileTest(name)
	err = s.store.Update(func(d *appData) {
		info.Relay = d.relayFor(info.Name, profile.Host)
		d.setRelay(info.Name, info.Relay)
		if d.Measurements[info.Name].Rev != info.Rev {
			delete(d.Measurements, info.Name)
		}
		if d.Active == "" {
			d.Active = info.Name
		}
	})
	return info, err
}

var errNoProfile = &apiError{status: http.StatusNotFound, msg: "That profile doesn't exist."}

// storedName maps the {name} path value to the one name used everywhere.
func (s *Server) storedName(r *http.Request) (string, error) {
	name, ok := s.profiles.Resolve(r.PathValue("name"))
	if !ok {
		return "", errNoProfile
	}
	return name, nil
}

func (s *Server) renameProfile(r *http.Request) (any, error) {
	var body struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &body); err != nil {
		return nil, err
	}
	to, ok := NormalizeName(body.Name)
	if !ok {
		return nil, bad("Use 1 to 64 letters, numbers, - or _ for the name.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.Err(); err != nil {
		return nil, err
	}
	from, err := s.storedName(r)
	if err != nil {
		return nil, err
	}
	info, err := s.profiles.Rename(from, to)
	switch {
	case errors.Is(err, os.ErrExist):
		return nil, &apiError{status: http.StatusConflict, msg: "A profile with that name already exists."}
	case errors.Is(err, os.ErrNotExist):
		return nil, errNoProfile
	case err != nil:
		return nil, err
	}
	if from != to {
		s.invalidateProfileTest(from)
	}
	err = s.store.Update(func(d *appData) {
		info.Relay = d.relayFor(from, info.Server)
		if from != to {
			d.setRelay(to, info.Relay)
			delete(d.Relays, from)
			if measurement, ok := d.Measurements[from]; ok {
				measurement.Profile = to
				d.setMeasurement(to, measurement)
				delete(d.Measurements, from)
			}
		}
		info.Measurement = d.measurementFor(info)
		if d.Active == from {
			d.Active = to
		}
	})
	if err == nil && s.liveProfile.name == from {
		s.liveProfile.name = to
	}
	return info, err
}

func (s *Server) deleteProfile(r *http.Request) (any, error) {
	defer s.notify()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.Err(); err != nil {
		return nil, err
	}
	name, err := s.storedName(r)
	if err != nil {
		return nil, err
	}
	if s.store.Snapshot().Active == name {
		if err := s.Shutdown(); err != nil {
			return nil, err
		}
	}
	if err := s.profiles.Delete(name); err != nil {
		return nil, err
	}
	s.invalidateProfileTest(name)
	return nil, s.store.Update(func(d *appData) {
		delete(d.Relays, name)
		delete(d.Measurements, name)
		if d.Active == name {
			d.Active = ""
			if left := s.profiles.List(); len(left) > 0 {
				d.Active = left[0].Name
			}
		}
	})
}

func (s *Server) activateProfile(r *http.Request) (any, error) {
	defer s.notify()
	s.mu.Lock()
	defer s.mu.Unlock()
	name, err := s.storedName(r)
	if err != nil {
		return nil, err
	}
	if _, err := s.profiles.Info(name); err != nil {
		return nil, errNoProfile
	}
	err = s.transact(func(d *appData) { d.Active = name }, func() error {
		if !running(s.active().Status()) {
			return nil
		}
		opts, rev, err := s.options(name)
		if err == nil {
			err = s.active().Start(opts)
		}
		if err != nil {
			return errors.Join(err, s.clearProxyLocked())
		}
		s.liveProfile = profileIdentity{name, rev}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.statusLocked(), nil
}

type profileSecretResponse struct {
	Link   string `json:"link"`
	QR     string `json:"qr"`
	Proxy  string `json:"proxy"`
	Export string `json:"export"`
	Rev    string `json:"rev"`
}

func (s *Server) secretProfile(r *http.Request) (link.Profile, string, error) {
	name, err := s.storedName(r)
	if err != nil {
		return link.Profile{}, "", err
	}
	profile, rev, err := s.profiles.load(name)
	if errors.Is(err, os.ErrNotExist) {
		return link.Profile{}, "", errNoProfile
	}
	return profile, rev, err
}

func (s *Server) profileSecret(r *http.Request) (any, error) {
	profile, rev, err := s.secretProfile(r)
	if err != nil {
		return nil, err
	}
	raw, err := profile.Encode()
	if err != nil {
		return nil, err
	}
	proxy, _ := link.ProxyURL(profile)
	return profileSecretResponse{
		Link: raw, QR: link.QRSVG(raw), Proxy: proxy, Export: link.ProxyExport(proxy), Rev: rev,
	}, nil
}

func (s *Server) copyProfileSecret(r *http.Request) (any, error) {
	var body struct{ Format, Rev string }
	if err := readJSON(r, &body, 1024); err != nil {
		return nil, err
	}
	profile, rev, err := s.secretProfile(r)
	if err != nil {
		return nil, err
	}
	if rev != body.Rev {
		return nil, &apiError{status: http.StatusConflict, msg: "The profile changed. Open its device link again."}
	}
	var value string
	switch body.Format {
	case "link":
		value, err = profile.Encode()
	case "proxy", "export":
		value, _ = link.ProxyURL(profile)
		if body.Format == "export" {
			value = link.ProxyExport(value)
		}
	default:
		return nil, bad("Choose a device link, HTTPS proxy, or terminal command.")
	}
	if err != nil || value == "" {
		return nil, bad("That value is unavailable for this profile.")
	}
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	if err := s.cfg.copySensitive(value); errors.Is(err, webview.ErrUnsupported) {
		return map[string]bool{"fallback": true}, nil
	} else if err != nil {
		return nil, errors.New("Couldn't copy the value to the clipboard.")
	}
	return nil, nil
}

type routingBody struct {
	Mode  string       `json:"mode"`
	Tier  string       `json:"tier"`
	Rules []RuleObject `json:"rules"`
}

func (s *Server) routing() routingBody {
	d := s.store.Snapshot()
	return routingBody{Mode: d.Mode, Tier: d.Tier, Rules: d.Rules}
}

func (s *Server) putRouting(r *http.Request) (any, error) {
	defer s.notify()
	var body routingBody
	if err := readJSON(r, &body, maxRulesBody); err != nil {
		return nil, err
	}
	if !validMode(body.Mode) || !validTier(body.Tier) {
		return nil, bad("Choose a valid mode and route.")
	}
	if len(body.Rules) > maxRules {
		return nil, bad("You can have at most 500 rules.")
	}
	if body.Rules == nil {
		body.Rules = []RuleObject{}
	}
	for i, rule := range body.Rules {
		body.Rules[i].Value = strings.TrimSpace(rule.Value)
		if _, err := s.parseRule(body.Rules[i]); err != nil {
			idx := i
			return nil, &apiError{status: 400, msg: err.Error(), index: &idx}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.transact(func(d *appData) { d.Mode, d.Tier, d.Rules = body.Mode, body.Tier, body.Rules },
		func() error { return s.applyLiveLocked(true) })
	if err != nil {
		return nil, err
	}
	return s.routing(), nil
}

// applyLiveLocked pushes saved settings into a running session. s.mu is held.
func (s *Server) applyLiveLocked(modeAndTier bool) error {
	ctl := s.active()
	if !running(ctl.Status()) {
		return nil
	}
	data := s.store.Snapshot()
	opts, rev, err := s.options(data.Active)
	if err != nil {
		return err
	}
	if err := ctl.Apply(opts); err != nil {
		return err
	}
	s.liveProfile = profileIdentity{data.Active, rev}
	if modeAndTier {
		if err := ctl.SetMode(data.Mode); err != nil {
			return err
		}
		if err := ctl.SetTier(data.Tier); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) putSettings(r *http.Request) (any, error) {
	next := s.store.Snapshot().Settings
	if err := readJSON(r, &next); err != nil {
		return nil, err
	}
	return s.updateSettings(next)
}

// updateSettings validates, saves and applies new settings (PUT /api/settings
// and the in-process setters).
func (s *Server) updateSettings(next Settings) (any, error) {
	defer s.notify()
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.store.Snapshot().Settings
	switch {
	case next.ListenPort < 1024 || next.ListenPort > 65535:
		return nil, bad("Choose a port between 1024 and 65535.")
	case !validLogDetail(next.LogDetail), !validTheme(next.Theme):
		return nil, bad("That setting isn't valid.")
	}
	if next.TUN && !before.TUN {
		// Nothing is saved when Pipe Helper isn't ready.
		if err := s.needHelper(); err != nil {
			return nil, err
		}
	}
	if next.StartAtLogin != before.StartAtLogin && s.cfg.Autostart != nil {
		var err error
		if next.StartAtLogin {
			err = s.cfg.Autostart.Enable(s.cfg.Exe)
		} else {
			err = s.cfg.Autostart.Disable()
		}
		if err != nil {
			return nil, fmt.Errorf("couldn't change start at login: %w", err)
		}
	}
	status := s.active().Status()
	ownedTUN := s.getVia() == viaTUN && !tunStopped(status)
	switched := next.TUN != before.TUN && (running(status) || ownedTUN)
	var err error
	clearedOldProxy := false
	if !switched && s.getVia() == viaProxy && before.ListenPort != next.ListenPort && (s.proxyOn || s.cfg.Proxy.Armed()) {
		// Restore the OS proxy before Apply can close the old listener.
		err = s.clearProxyLocked()
		clearedOldProxy = err == nil
	}
	apply := func() error {
		if switched {
			// Reconnect through the other path (also arms or clears the proxy).
			_, err := s.connectLocked()
			return err
		}
		// Re-checked under the lock: a concurrent disconnect can't be
		// followed by re-arming the proxy.
		if !running(s.active().Status()) {
			return nil
		}
		if err := s.applyLiveLocked(false); err != nil {
			return err
		}
		if s.getVia() == viaTUN {
			return nil // saved, but the system proxy isn't used in TUN mode
		}
		switch {
		case !next.SystemProxy:
			return s.clearProxyLocked()
		case !before.SystemProxy || before.ListenPort != next.ListenPort || !s.proxyOn:
			s.setProxyLocked(next.ListenPort)
		}
		return nil
	}
	if err == nil {
		err = s.transact(func(d *appData) { d.Settings = next }, apply)
	}
	if err != nil {
		if clearedOldProxy && before.SystemProxy && s.getVia() == viaProxy {
			st := s.cfg.Controller.Status()
			if running(st) && st.Listen == fmt.Sprintf("127.0.0.1:%d", before.ListenPort) {
				s.setProxyLocked(before.ListenPort)
			}
		}
		if switched && s.getVia() == "" && !running(s.active().Status()) {
			_, _ = s.connectLocked() // the saved settings are the old ones again
		}
		if next.StartAtLogin != before.StartAtLogin && s.cfg.Autostart != nil {
			if before.StartAtLogin {
				_ = s.cfg.Autostart.Enable(s.cfg.Exe)
			} else {
				_ = s.cfg.Autostart.Disable()
			}
		}
		return nil, err
	}
	return next, nil
}

// installHelper installs Pipe Helper. It blocks on the OS password prompt and
// does not hold s.mu, so the app stays responsive meanwhile.
func (s *Server) installHelper() (any, error) {
	if s.cfg.Helper == nil {
		return nil, bad("TUN isn't available on this system yet.")
	}
	defer s.notify()
	if err := s.cfg.Helper.Install(); err != nil {
		if errors.Is(err, helper.ErrCanceled) {
			return nil, &apiError{status: http.StatusBadRequest, msg: err.Error(), code: "canceled"}
		}
		return nil, err
	}
	return s.helperInfo(), nil
}

// removeHelper removes Pipe Helper. Stopping its service ends a TUN session,
// so nothing changes here until the OS password prompt succeeds: a cancel
// leaves the connection and the saved TUN choice alone.
func (s *Server) removeHelper() (any, error) {
	if s.cfg.Helper == nil {
		return nil, bad("TUN isn't available on this system yet.")
	}
	defer s.notify()
	if err := s.cfg.Helper.Remove(); err != nil {
		if errors.Is(err, helper.ErrCanceled) {
			return nil, &apiError{status: http.StatusBadRequest, msg: err.Error(), code: "canceled"}
		}
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getVia() == viaTUN {
		s.setVia("")
	}
	if err := s.store.Update(func(d *appData) { d.Settings.TUN = false }); err != nil {
		return nil, err
	}
	return s.helperInfo(), nil
}

func (s *Server) getLogs(r *http.Request) (any, error) {
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit < 1 || limit > 1000 {
		limit = 500
	}
	if s.cfg.Helper != nil && s.getVia() == viaTUN {
		s.cfg.Helper.SyncLogs()
	}
	entries, next := s.cfg.Logs.Since(after, limit)
	if entries == nil {
		entries = []logring.Entry{}
	}
	return map[string]any{"next": next, "entries": entries}, nil
}

func (s *Server) about() map[string]string {
	cli := "pipe run --tun <your pipe:// link>"
	if runtime.GOOS != "windows" {
		cli = "sudo " + cli
	}
	return map[string]string{"version": s.cfg.Version, "os": runtime.GOOS, "arch": runtime.GOARCH,
		"configDir": s.cfg.Dir, "cliCommand": cli}
}
