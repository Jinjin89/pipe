// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"pipe/internal/localfile"
	"pipe/internal/webview"
)

func TestDesktopSessionExpires(t *testing.T) {
	s := newSessions()
	now := time.Now()
	s.now = func() time.Time { return now }
	nonce := s.NewNonce()
	token, ok := s.Redeem(nonce)
	if !ok || !s.Valid(token) {
		t.Fatal("new session was not usable")
	}
	if _, ok := s.Redeem(nonce); ok {
		t.Fatal("nonce was redeemed twice")
	}
	now = now.Add(time.Hour)
	if s.Valid(token) || s.hasLive() {
		t.Fatal("expired session was accepted")
	}
}

func TestPrivateBootstrapRedeemsAndRemovesFile(t *testing.T) {
	s := newSessions()
	defer s.close()
	const origin = "http://127.0.0.1:9876"
	boot, err := s.newBootstrap(t.TempDir(), origin)
	if err != nil {
		t.Fatal(err)
	}
	body, err := localfile.ReadProtected(boot.path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(filepath.Base(boot.path), ".") || strings.Contains(bootstrapURL(boot.path), boot.nonce) {
		t.Fatal("the private redirect or public launcher path is invalid")
	}
	target := origin + "/#boot=" + boot.nonce
	for _, want := range []string{`content="0;url=` + target + `"`, `location.replace("` + target + `")`, `href="` + target + `"`} {
		if !strings.Contains(string(body), want) {
			t.Fatal("a bootstrap navigation method is missing")
		}
	}
	token, ok := s.Redeem(boot.nonce)
	if !ok || !boot.wasRedeemed() {
		t.Fatal("bootstrap redemption failed")
	}
	if _, err := os.Stat(boot.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("redeemed bootstrap file still exists: %v", err)
	}
	r := httptest.NewRequest("GET", origin+"/api/status", nil)
	r.Header.Set("Cookie", "pipe_session="+token)
	if s.ValidBearer(r) {
		t.Fatal("cookie authorized a request")
	}
	r.Header.Set("Authorization", "Bearer "+token)
	if !s.ValidBearer(r) {
		t.Fatal("redeemed bearer was rejected")
	}
}

func TestBrowserRetriesWithFreshPrivateBootstrap(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, test := range []struct {
		name                string
		quickExit, redeemed bool
	}{
		{"missed redemption", false, false},
		{"quick browser exit", true, false},
		{"crash after redemption", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a := newWindowTestApp()
				defer a.srv.sess.close()
				defer a.finishQuit()
				opened := make(chan string, 1)
				a.openDefault = func(path string) error {
					opened <- path
					return nil
				}
				initial := a.bootstrap()
				if initial == nil {
					t.Fatal("could not create a bootstrap")
				}
				if runtime.GOOS == "linux" && filepath.Dir(initial.path) != home {
					t.Fatalf("bootstrap path is outside the home directory: %s", initial.path)
				}
				a.winMu.Lock()
				attempt := a.trackBrowser(initial, true)
				a.winMu.Unlock()
				if test.redeemed {
					if _, ok := a.srv.sess.Redeem(initial.nonce); !ok {
						t.Fatal("initial nonce could not be redeemed")
					}
				}
				if test.quickExit {
					a.watch(func() error { return errors.New("browser exited") }, time.Now(), attempt, true)
				} else {
					time.Sleep(browserRedemptionTimeout)
					synctest.Wait()
				}
				select {
				case path := <-opened:
					next := a.browser
					if next == nil || path != next.path || next.path == initial.path || next.nonce == initial.nonce {
						t.Fatal("retry reused a browser bootstrap")
					}
					if _, err := os.Stat(initial.path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("previous bootstrap remains: %v", err)
					}
					if _, ok := a.srv.sess.Redeem(initial.nonce); ok {
						t.Fatal("previous nonce still works")
					}
					if _, ok := a.srv.sess.Redeem(next.nonce); !ok {
						t.Fatal("replacement nonce did not work")
					}
				default:
					t.Fatal("default browser never received a fresh bootstrap")
				}
			})
		})
	}
}

func TestFinalBrowserBootstrapUsesFullNonceTTL(t *testing.T) {
	dir := t.TempDir()
	synctest.Test(t, func(t *testing.T) {
		a := newWindowTestApp()
		defer a.srv.sess.close()
		defer a.finishQuit()
		boot, err := a.srv.sess.newBootstrap(dir, a.url)
		if err != nil {
			t.Fatal(err)
		}
		a.trackBrowser(boot, false)
		time.Sleep(nonceTTL - time.Second)
		synctest.Wait()
		if _, err := os.Stat(boot.path); err != nil {
			t.Fatalf("final bootstrap removed before nonce TTL: %v", err)
		}
		if _, ok := a.srv.sess.Redeem(boot.nonce); !ok {
			t.Fatal("slow browser could not redeem the final bootstrap")
		}
		boot, err = a.srv.sess.newBootstrap(dir, a.url)
		if err != nil {
			t.Fatal(err)
		}
		a.trackBrowser(boot, false)
		time.Sleep(nonceTTL)
		synctest.Wait()
		if _, err := os.Stat(boot.path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired final bootstrap file remained: %v", err)
		}
		if _, ok := a.srv.sess.Redeem(boot.nonce); ok {
			t.Fatal("final bootstrap survived its nonce TTL")
		}
	})
}

type testAppWindow struct {
	done    chan struct{}
	focused int
}

func (w *testAppWindow) Focus()                { w.focused++ }
func (w *testAppWindow) Close()                { close(w.done) }
func (w *testAppWindow) Done() <-chan struct{} { return w.done }

func newWindowTestApp() *App {
	a := &App{srv: &Server{sess: newSessions()}, url: "http://127.0.0.1:9876", quit: make(chan struct{})}
	a.keepRunning.Store(true)
	a.openWebview = func(string, webview.Options) (appWindow, error) {
		return &testAppWindow{done: make(chan struct{})}, nil
	}
	return a
}

func TestShowReopensNativeWindowAfterSessionExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := newWindowTestApp()
		defer a.closeWindow()
		a.Show()
		first, nonce := a.webWin.(*testAppWindow), a.webNonce
		if _, ok := a.srv.sess.Redeem(nonce); !ok {
			t.Fatal("initial nonce did not work")
		}
		a.Show()
		if a.webWin != first || first.focused != 1 {
			t.Fatal("a live native window was not focused")
		}
		time.Sleep(sessionTTL)
		a.Show()
		synctest.Wait()
		select {
		case <-first.Done():
		default:
			t.Fatal("expired native window stayed open")
		}
		if a.webWin == first || nonce == a.webNonce || first.focused != 1 {
			t.Fatal("expired window was focused or reopened without a fresh nonce")
		}
		if _, ok := a.srv.sess.Redeem(a.webNonce); !ok {
			t.Fatal("the reopened window's nonce did not work")
		}
	})
}

func TestNativeWindowCloseRevokesSessions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := newWindowTestApp()
		a.Show()
		token, ok := a.srv.sess.Redeem(a.webNonce)
		if !ok {
			t.Fatal("initial nonce did not work")
		}
		a.webWin.Close()
		synctest.Wait()
		if a.srv.sess.Valid(token) || a.srv.sess.hasLive() || a.webWin != nil {
			t.Fatal("closed native window retained an active session")
		}
	})
}
