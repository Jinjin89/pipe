// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"pipe/internal/localfile"
	"pipe/internal/sysproxy"
	"pipe/internal/webview"
)

// AppOptions is Config plus the run-mode switches.
type AppOptions struct {
	Config
	Background bool
	NoWindow   bool
	Stdout     io.Writer
	// KeepRunning: closing the window never quits (the macOS menu bar
	// icon is the way back). Without it, D9 applies.
	KeepRunning bool
	// Started is called once the server is up, before the first window.
	Started func(*App)
}

type instanceFile struct {
	Port   int    `json:"port"`
	Secret string `json:"secret"`
}

type appWindow interface {
	Focus()
	Close()
	Done() <-chan struct{}
}

type browserAttempt struct {
	*browserBootstrap
	retry bool
}

const (
	browserRedemptionTimeout = 8 * time.Second
	shutdownRetryInterval    = 2 * time.Second
)

// App ties the server, the window and the process lifetime together.
type App struct {
	opts AppOptions
	srv  *Server
	url  string // http://127.0.0.1:PORT

	quitOnce sync.Once
	quit     chan struct{}

	winMu      sync.Mutex
	winRunning bool
	opening    bool
	closing    bool
	webWin     appWindow
	webNonce   string
	browser    *browserAttempt

	openWebview func(string, webview.Options) (appWindow, error)
	openDefault func(string) error

	keepRunning atomic.Bool
}

// Run starts the app and blocks until it quits or ctx ends. If another
// instance owns the lock it asks that one to show its window and returns nil.
func Run(ctx context.Context, opts AppOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if err := os.MkdirAll(opts.Dir, 0700); err != nil {
		return err
	}
	release, held, err := acquireLock(filepath.Join(opts.Dir, "app.lock"))
	if err != nil {
		return fmt.Errorf("lock app: %w", err)
	}
	if held {
		if opts.Background {
			return nil // already running; nothing to show
		}
		return showExisting(opts.Dir)
	}
	defer release()
	// The kernel lock is ours, so any app.instance left over is stale.
	_ = os.Remove(filepath.Join(opts.Dir, "app.instance"))

	// Put back anything a crashed run left behind.
	if err := opts.Proxy.Repair(); err != nil {
		return fmt.Errorf("repair system proxy: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	a := &App{opts: opts, quit: make(chan struct{})}
	a.keepRunning.Store(opts.KeepRunning)
	opts.Config.OnQuit = a.finishQuit
	opts.Config.OnShow = a.show
	a.srv = NewServer(opts.Config)
	defer a.srv.sess.close()
	if err := a.srv.store.Err(); err != nil && opts.Logs != nil {
		opts.Logs.Add("error", "pipe", friendly(err))
	}
	port := listener.Addr().(*net.TCPAddr).Port
	a.srv.SetHost(fmt.Sprintf("127.0.0.1:%d", port))
	a.url = fmt.Sprintf("http://127.0.0.1:%d", port)

	instancePath := filepath.Join(opts.Dir, "app.instance")
	raw, _ := json.Marshal(instanceFile{Port: port, Secret: a.srv.ShowSecret()})
	if err := localfile.WritePrivateAtomic(instancePath, raw); err != nil {
		listener.Close()
		return err
	}
	defer os.Remove(instancePath)

	httpServer := &http.Server{Handler: a.srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go httpServer.Serve(listener)

	if err := a.srv.ConnectIfConfigured(); err != nil && opts.Logs != nil {
		opts.Logs.Add("error", "pipe", "Couldn't connect at start: "+friendly(err))
	}
	if opts.Started != nil {
		opts.Started(a)
	}
	if !opts.Background {
		a.show()
	}

	// Note: a Windows GUI process is not reliably told about logoff or
	// shutdown, so the system proxy may stay set then. Crash repair
	// (Proxy.Repair at the next launch) puts it back.
	select {
	case <-ctx.Done():
		a.retryShutdown()
	case <-a.quit:
	}
	a.closeWindow()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	return nil
}

// Quit reports whether the active connection was released and exit can proceed.
func (a *App) Quit() bool {
	if err := a.srv.Close(); err != nil {
		a.logQuitFailure(err)
		return false
	}
	a.finishQuit()
	return true
}

func (a *App) retryShutdown() {
	for {
		err := a.srv.Close()
		if err == nil {
			return
		}
		a.logQuitFailure(err)
		select {
		case <-time.After(shutdownRetryInterval):
		case <-a.quit:
			return
		}
	}
}

func (a *App) logQuitFailure(err error) {
	msg := "Couldn't quit Pipe: " + friendly(err)
	if a.opts.Logs != nil {
		a.opts.Logs.Add("error", "pipe", msg)
	} else {
		fmt.Fprintln(os.Stderr, msg)
	}
}

func (a *App) finishQuit() { a.quitOnce.Do(func() { close(a.quit) }) }

// Server is the running app's server, for in-process front ends (menu bar).
func (a *App) Server() *Server { return a.srv }

// Show opens the window, or brings it back.
func (a *App) Show() { a.show() }

// SetKeepRunning switches between "closing the window never quits" and D9.
func (a *App) SetKeepRunning(on bool) { a.keepRunning.Store(on) }

// show opens the window or prints the private bootstrap file's path.
func (a *App) show() {
	if a.opts.NoWindow {
		if boot := a.bootstrap(); boot != nil {
			fmt.Fprintln(a.opts.Stdout, boot.path)
		}
		return
	}
	a.winMu.Lock()
	if a.opening || a.closing {
		a.winMu.Unlock()
		return
	}
	old := a.webWin
	if old != nil {
		select {
		case <-old.Done():
		default:
			if a.srv.sess.hasLive() {
				a.winMu.Unlock()
				old.Focus()
				return
			}
		}
		a.clearWebview()
	}
	a.opening = true
	a.winMu.Unlock()

	if old != nil {
		old.Close()
	}
	nonce := a.srv.NewNonce()
	open := a.openWebview
	if open == nil {
		open = func(url string, options webview.Options) (appWindow, error) {
			return webview.Open(url, options)
		}
	}
	w, err := open(a.url+"/#boot="+nonce, webview.Options{Title: "Pipe", Width: 1000, Height: 700})
	a.winMu.Lock()
	a.opening = false
	if a.closing {
		a.srv.sess.discardNonce(nonce)
		a.winMu.Unlock()
		if err == nil {
			w.Close()
		}
		return
	}
	if err == nil {
		a.webWin, a.webNonce = w, nonce
		a.clearBrowserAttempt()
		a.winMu.Unlock()
		go a.watchWebview(w)
		return
	}
	a.srv.sess.discardNonce(nonce)
	if !errors.Is(err, webview.ErrUnsupported) && a.opts.Logs != nil {
		a.opts.Logs.Add("warn", "pipe", "Native window unavailable, falling back to browser: "+err.Error())
	}

	defer a.winMu.Unlock()
	boot := a.bootstrap()
	if boot == nil {
		return
	}
	cmd, err := startWindow(bootstrapURL(boot.path), filepath.Join(a.opts.Dir, "ui-profile"))
	if err != nil || cmd == nil {
		// An accepted portal request manages its own fallback and may need
		// the full nonce lifetime while the user chooses a browser.
		portal := a.openDefaultBrowser(boot.path)
		a.trackBrowser(boot, !portal)
		return
	}
	attempt := a.trackBrowser(boot, true)
	ownsWindow := !a.winRunning
	a.winRunning = true
	go a.watch(cmd.Wait, time.Now(), attempt, ownsWindow)
}

func (a *App) bootstrap() *browserBootstrap {
	dir, err := browserBootstrapDir()
	if err == nil {
		var boot *browserBootstrap
		boot, err = a.srv.sess.newBootstrap(dir, a.url)
		if err == nil {
			return boot
		}
	}
	if err != nil && a.opts.Logs != nil {
		a.opts.Logs.Add("error", "pipe", "Couldn't create the private browser bootstrap file: "+err.Error())
	}
	return nil
}

func (a *App) closeWindow() {
	a.winMu.Lock()
	a.closing = true
	w := a.webWin
	a.clearWebview()
	a.clearBrowserAttempt()
	a.winMu.Unlock()
	if w != nil {
		w.Close()
	}
}

// clearWebview retires the window's authentication while holding winMu.
func (a *App) clearWebview() {
	if a.webWin != nil {
		a.srv.sess.revokeWindow(a.webNonce)
		a.webWin, a.webNonce = nil, ""
	}
}

func (a *App) watchWebview(w appWindow) {
	<-w.Done()
	a.winMu.Lock()
	if a.webWin != w {
		a.winMu.Unlock()
		return
	}
	a.clearWebview()
	a.winMu.Unlock()
	a.quitIfOff(nil)
}

func (a *App) quitIfOff(attempt *browserAttempt) {
	if a.keepRunning.Load() || !a.srv.StateIsOff() {
		return
	}
	a.winMu.Lock()
	defer a.winMu.Unlock()
	if !a.closing && !a.opening && a.webWin == nil && !a.winRunning && a.browser == attempt {
		a.Quit()
	}
}

// trackBrowser starts waiting for this bootstrap while holding winMu.
func (a *App) trackBrowser(boot *browserBootstrap, retry bool) *browserAttempt {
	a.clearBrowserAttempt()
	attempt := &browserAttempt{browserBootstrap: boot, retry: retry}
	a.browser = attempt
	if !retry {
		return attempt // the session timer owns the final bootstrap's lifetime
	}
	go func() {
		timer := time.NewTimer(browserRedemptionTimeout)
		defer timer.Stop()
		select {
		case <-attempt.redeemed:
		case <-a.quit:
		case <-timer.C:
			a.retryBrowser(attempt, false)
		}
	}()
	return attempt
}

func (a *App) clearBrowserAttempt() {
	if a.browser != nil {
		a.srv.sess.discardNonce(a.browser.nonce)
		a.browser = nil
	}
}

func (a *App) openDefaultBrowser(path string) bool {
	var portal bool
	var err error
	if a.openDefault == nil {
		portal, err = openDefaultBrowser(path)
	} else {
		err = a.openDefault(path)
	}
	if err != nil && a.opts.Logs != nil {
		a.opts.Logs.Add("warn", "pipe", "Couldn't open the default browser: "+err.Error())
	}
	return portal
}

func (a *App) retryBrowser(attempt *browserAttempt, crashed bool) {
	a.winMu.Lock()
	defer a.winMu.Unlock()
	if a.closing || !attempt.retry || a.browser != attempt || !a.srv.sess.discardBootstrap(attempt.browserBootstrap, crashed) {
		return
	}
	a.browser = nil
	if boot := a.bootstrap(); boot != nil {
		a.trackBrowser(boot, false)
		a.openDefaultBrowser(boot.path)
	}
}

// watch waits for the window process. Closing the window while disconnected
// quits the app; while connected the app keeps running in the background.
func (a *App) watch(wait func() error, started time.Time, attempt *browserAttempt, ownsWindow bool) {
	err := wait()
	a.winMu.Lock()
	if ownsWindow {
		a.winRunning = false
	}
	a.winMu.Unlock()
	quickExit := time.Since(started) < 3*time.Second
	if quickExit && err != nil && ownsWindow {
		a.retryBrowser(attempt, true)
		return
	}
	if !attempt.wasRedeemed() {
		if quickExit && err == nil {
			// An existing browser can redeem a handoff after the launcher exits.
			timer := time.NewTimer(time.Second)
			defer timer.Stop()
			select {
			case <-attempt.redeemed:
				return
			case <-a.quit:
				return
			case <-timer.C:
			}
		}
		a.retryBrowser(attempt, false)
		return
	}
	if !quickExit && ownsWindow {
		a.quitIfOff(attempt)
	}
}

// showExisting asks the running instance to bring its window back.
func showExisting(dir string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	for i := 0; i < 12; i++ {
		if i > 0 {
			time.Sleep(250 * time.Millisecond)
		}
		raw, err := sysproxy.ReadPrivate(filepath.Join(dir, "app.instance"))
		if err != nil {
			lastErr = err
			continue
		}
		var inst instanceFile
		if err := json.Unmarshal(raw, &inst); err != nil {
			lastErr = err
			continue
		}
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/internal/show", inst.Port), nil)
		req.Header.Set("X-Pipe-Show", inst.Secret)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent {
			return nil
		}
		lastErr = fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return errors.New("Pipe is already running but did not answer: " + lastErr.Error())
}
