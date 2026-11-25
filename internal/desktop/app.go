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
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

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

// App ties the server, the window and the process lifetime together.
type App struct {
	opts AppOptions
	srv  *Server
	url  string // http://127.0.0.1:PORT

	quitOnce sync.Once
	quit     chan struct{}

	winMu      sync.Mutex
	winRunning bool
	webWin     *webview.Window

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
	_ = opts.Proxy.Repair()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	a := &App{opts: opts, quit: make(chan struct{})}
	a.keepRunning.Store(opts.KeepRunning)
	opts.Config.OnQuit = a.Quit
	opts.Config.OnShow = a.show
	a.srv = NewServer(opts.Config)
	port := listener.Addr().(*net.TCPAddr).Port
	a.srv.SetHost(fmt.Sprintf("127.0.0.1:%d", port))
	a.url = fmt.Sprintf("http://127.0.0.1:%d", port)

	instancePath := filepath.Join(opts.Dir, "app.instance")
	raw, _ := json.Marshal(instanceFile{Port: port, Secret: a.srv.ShowSecret()})
	if err := WriteFileAtomic(instancePath, raw, 0600); err != nil {
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
	case <-a.quit:
	}
	a.closeWindow()
	err = a.srv.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	return err
}

// Quit asks Run to return.
func (a *App) Quit() { a.quitOnce.Do(func() { close(a.quit) }) }

// Server is the running app's server, for in-process front ends (menu bar).
func (a *App) Server() *Server { return a.srv }

// Show opens the window, or brings it back.
func (a *App) Show() { a.show() }

// SetKeepRunning switches between "closing the window never quits" and D9.
func (a *App) SetKeepRunning(on bool) { a.keepRunning.Store(on) }

// show opens the window (or prints the URL with --no-window).
func (a *App) show() {
	if a.opts.NoWindow {
		fmt.Fprintln(a.opts.Stdout, a.url+"/#boot="+a.srv.NewNonce())
		return
	}
	a.winMu.Lock()
	if a.webWin != nil {
		select {
		case <-a.webWin.Done():
			a.webWin = nil
		default:
			w := a.webWin
			a.winMu.Unlock()
			w.Focus()
			return
		}
	}
	a.winMu.Unlock()

	url := a.url + "/#boot=" + a.srv.NewNonce()
	if w, err := webview.Open(url, webview.Options{Title: "Pipe", Width: 1000, Height: 700}); err == nil {
		a.winMu.Lock()
		if a.webWin != nil {
			select {
			case <-a.webWin.Done():
				a.webWin = nil
			default:
				existing := a.webWin
				a.winMu.Unlock()
				w.Close()
				existing.Focus()
				return
			}
		}
		a.webWin = w
		a.winMu.Unlock()
		go a.watchWebview(w)
		return
	} else if !errors.Is(err, webview.ErrUnsupported) && a.opts.Logs != nil {
		a.opts.Logs.Add("warn", "pipe", "Native window unavailable, falling back to browser: "+err.Error())
	}

	a.winMu.Lock()
	defer a.winMu.Unlock()
	cmd, err := startWindow(url, filepath.Join(a.opts.Dir, "ui-profile"))
	if err != nil || cmd == nil {
		// No Chromium browser (or it failed): the default browser can't be
		// watched, so Quit in the app is the way out.
		_ = openDefaultBrowser(a.url + "/#boot=" + a.srv.NewNonce())
		return
	}
	if a.winRunning {
		// A window process already owns this profile; the new command just
		// hands over to it and exits.
		go cmd.Wait()
		return
	}
	a.winRunning = true
	started := time.Now()
	go a.watch(cmd, started)
}

func (a *App) closeWindow() {
	a.winMu.Lock()
	w := a.webWin
	a.webWin = nil
	a.winMu.Unlock()
	if w != nil {
		w.Close()
	}
}

func (a *App) watchWebview(w *webview.Window) {
	<-w.Done()
	a.winMu.Lock()
	if a.webWin == w {
		a.webWin = nil
	}
	a.winMu.Unlock()
	if !a.keepRunning.Load() && a.srv.StateIsOff() {
		a.Quit()
	}
}

// watch waits for the window process. Closing the window while disconnected
// quits the app; while connected the app keeps running in the background.
func (a *App) watch(cmd *exec.Cmd, started time.Time) {
	err := cmd.Wait()
	a.winMu.Lock()
	a.winRunning = false
	a.winMu.Unlock()
	if time.Since(started) < 3*time.Second {
		if err != nil {
			// The browser refused to start; use the default one instead.
			_ = openDefaultBrowser(a.url + "/#boot=" + a.srv.NewNonce())
		}
		// A clean quick exit is a hand-off to a browser that already runs.
		return
	}
	if !a.keepRunning.Load() && a.srv.StateIsOff() {
		a.Quit()
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
