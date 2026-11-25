// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

const (
	nonceTTL    = 10 * time.Second
	maxSessions = 16
	cookieName  = "pipe_session"
)

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// sessions holds single-use boot nonces and the session cookies they create.
type sessions struct {
	mu     sync.Mutex
	now    func() time.Time
	nonces map[string]time.Time
	tokens []string
}

func newSessions() *sessions {
	return &sessions{now: time.Now, nonces: map[string]time.Time{}}
}

// NewNonce returns a nonce that works once, within nonceTTL.
func (s *sessions) NewNonce() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for n, exp := range s.nonces {
		if now.After(exp) {
			delete(s.nonces, n)
		}
	}
	nonce := randomToken()
	s.nonces[nonce] = now.Add(nonceTTL)
	return nonce
}

// Redeem consumes a nonce. On success it returns a new session token.
func (s *sessions) Redeem(nonce string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.nonces[nonce]
	delete(s.nonces, nonce)
	if !ok || s.now().After(exp) {
		return "", false
	}
	token := randomToken()
	s.tokens = append(s.tokens, token)
	if len(s.tokens) > maxSessions {
		s.tokens = s.tokens[len(s.tokens)-maxSessions:]
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
	for _, t := range s.tokens {
		found |= subtle.ConstantTimeCompare([]byte(t), []byte(token))
	}
	return found == 1
}
