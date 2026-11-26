// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"pipe/internal/localfile"
)

const (
	nonceTTL    = 30 * time.Second
	sessionTTL  = 30 * time.Minute
	maxSessions = 16
)

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// sessions holds single-use boot nonces and the bearer tokens they create.
type sessions struct {
	mu     sync.Mutex
	now    func() time.Time
	nonces map[string]bootNonce
	tokens []sessionToken
	closed bool
}

type bootNonce struct {
	until    time.Time
	path     string
	redeemed chan struct{}
}

type browserBootstrap struct {
	path, nonce string
	redeemed    <-chan struct{}
}

func (b *browserBootstrap) wasRedeemed() bool {
	select {
	case <-b.redeemed:
		return true
	default:
		return false
	}
}

type sessionToken struct {
	value string
	until time.Time
}

func newSessions() *sessions {
	return &sessions{now: time.Now, nonces: map[string]bootNonce{}}
}

// NewNonce returns a nonce that works once, within nonceTTL.
func (s *sessions) NewNonce() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ""
	}
	now := s.now()
	nonce := randomToken()
	s.addNonce(nonce, bootNonce{until: now.Add(nonceTTL)})
	return nonce
}

func (s *sessions) addNonce(nonce string, boot bootNonce) {
	for n, existing := range s.nonces {
		if !s.now().Before(existing.until) {
			s.removeNonce(n, existing)
		}
	}
	s.nonces[nonce] = boot
}

// newBootstrap writes a one-use redirect to the app's exact loopback origin.
// The launcher sees only the independent filename.
func (s *sessions) newBootstrap(dir, origin string) (*browserBootstrap, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	nonce := randomToken()
	path := filepath.Join(abs, "Pipe-open-"+randomToken()+".html")
	url := origin + "/#boot=" + nonce
	destination := html.EscapeString(url)
	scriptURL, _ := json.Marshal(url)
	page := `<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer">` +
		`<meta http-equiv="refresh" content="0;url=` + destination + `"><title>Pipe</title>` +
		`<script>location.replace(` + string(scriptURL) + `)</script>` +
		`<a href="` + destination + `">Open Pipe</a>`
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	if err := localfile.WritePrivate(path, []byte(page)); err != nil {
		return nil, err
	}
	boot := bootNonce{until: s.now().Add(nonceTTL), path: path, redeemed: make(chan struct{})}
	s.addNonce(nonce, boot)
	time.AfterFunc(nonceTTL, func() { s.discardNonce(nonce) })
	return &browserBootstrap{path: path, nonce: nonce, redeemed: boot.redeemed}, nil
}

func (s *sessions) discardNonce(nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeNonce(nonce, s.nonces[nonce])
}

func (s *sessions) discardBootstrap(b *browserBootstrap, crashed bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || (!crashed && b.wasRedeemed()) {
		return false
	}
	s.removeNonce(b.nonce, s.nonces[b.nonce])
	return true
}

func (s *sessions) hasLive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, token := range s.tokens {
		if token.value != "" && now.Before(token.until) {
			return true
		}
	}
	return false
}

func (s *sessions) revokeWindow(nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = nil
	s.removeNonce(nonce, s.nonces[nonce])
}

func (s *sessions) removeNonce(nonce string, boot bootNonce) {
	delete(s.nonces, nonce)
	if boot.path != "" {
		_ = os.Remove(boot.path)
	}
}

func (s *sessions) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.tokens = nil
	for nonce, boot := range s.nonces {
		s.removeNonce(nonce, boot)
	}
}

// Redeem consumes a nonce. On success it returns a new session token.
func (s *sessions) Redeem(nonce string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	boot, ok := s.nonces[nonce]
	s.removeNonce(nonce, boot)
	now := s.now()
	if !ok || !now.Before(boot.until) {
		return "", false
	}
	token := randomToken()
	s.tokens = append(s.tokens, sessionToken{value: token, until: now.Add(sessionTTL)})
	if len(s.tokens) > maxSessions {
		s.tokens = s.tokens[len(s.tokens)-maxSessions:]
	}
	if boot.redeemed != nil {
		close(boot.redeemed)
	}
	return token, true
}

// Valid reports whether token is a live session, in constant time per entry.
func (s *sessions) Valid(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	found := 0
	now := s.now()
	for _, t := range s.tokens {
		if now.Before(t.until) {
			found |= subtle.ConstantTimeCompare([]byte(t.value), []byte(token))
		}
	}
	return found == 1
}

// ValidBearer authenticates an API request using its Authorization header.
func (s *sessions) ValidBearer(r *http.Request) bool {
	auth := r.Header.Values("Authorization")
	if len(auth) != 1 {
		return false
	}
	scheme, token, _ := strings.Cut(auth[0], " ")
	return strings.EqualFold(scheme, "Bearer") && s.Valid(token)
}
