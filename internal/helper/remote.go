// SPDX-License-Identifier: GPL-3.0-or-later

package helper

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/localfile"
	"pipe/internal/logring"
)

// RemoteOptions configures the app side.
type RemoteOptions struct {
	Socket  string        // default: PathsFor(runtime.GOOS).Socket
	Logs    *logring.Ring // helper log lines are copied here by SyncLogs
	Version string        // the app's version; any other helper version is outdated
	Exe     string        // path to the running app executable for installation
}

const (
	msgNotAnswering = "Pipe Helper isn't answering."
	msgMissing      = "Pipe Helper isn't installed."
	msgOutdated     = "Pipe Helper needs an update."
	msgUnsupported  = "Pipe Helper isn't available on this system."

	infoTTL      = 3 * time.Second
	helloTimeout = time.Second
	statusLimit  = 2 * time.Second
	stopLimit    = 20 * time.Second
	startLimit   = 30 * time.Second
	quickLimit   = 10 * time.Second
	settleLimit  = 5 * time.Second
)

// holdRetry is the pause before the hold is dialled again (a variable for tests).
var holdRetry = time.Second

// Remote is the app side of Pipe Helper. It implements desktop.Helper.
type Remote struct {
	opts   RemoteOptions
	goos   string
	socket string
	// macOS has no /proc/self/exe. Hold the image open from app startup.
	darwinDigest func() (string, error)

	// Test hooks.
	run         func(name string, args ...string) ([]byte, error)
	lookPath    func(string) (string, error)
	trustedPath func(string) (string, error)
	openImage   func(string) (*os.File, error)
	dialContext func(context.Context, string, string) (net.Conn, error)

	mu        sync.Mutex
	info      Info
	infoAt    time.Time
	holdStop  context.CancelFunc
	holdDone  chan struct{}
	syncMu    sync.Mutex
	logCursor uint64 // the helper's log position; kept across sessions
	onChange  func()
}

// OnChange sets the function called when a running session ends without the
// app asking (the helper went away). It must not block.
func (r *Remote) OnChange(f func()) {
	r.mu.Lock()
	r.onChange = f
	r.mu.Unlock()
}

func NewRemote(opts RemoteOptions) *Remote {
	r := &Remote{opts: opts, goos: runtime.GOOS, lookPath: exec.LookPath,
		trustedPath: localfile.TrustedExecutable, openImage: openHelperImage}
	if r.goos == "darwin" && opts.Exe != "" {
		r.darwinDigest = pinHelperDigest(opts.Exe, r.openImage)
	}
	r.run = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}
	r.socket = opts.Socket
	if r.socket == "" {
		if p, ok := PathsFor(r.goos); ok {
			r.socket = p.Socket
		}
	}
	return r
}

// call sends one request and decodes the result into out (when not nil).
// The error text is friendly. absent reports confirmed socket absence.
// A done ctx closes the connection at once.
func (r *Remote) call(ctx context.Context, timeout time.Duration, method string, params any, out any) (absent bool, err error) {
	if r.socket == "" {
		return true, errors.New(msgUnsupported)
	}
	d := net.Dialer{Timeout: timeout}
	dial := d.DialContext
	if r.dialContext != nil {
		dial = r.dialContext
	}
	conn, err := dial(ctx, "unix", r.socket)
	if err != nil {
		return errors.Is(err, os.ErrNotExist), errors.New(msgNotAnswering)
	}
	defer conn.Close()
	defer context.AfterFunc(ctx, func() { conn.Close() })()
	conn.SetDeadline(time.Now().Add(timeout))
	resp, err := exchange(conn, method, params)
	if err != nil {
		return false, errors.New(msgNotAnswering)
	}
	if resp.Error != "" {
		return false, errors.New(resp.Error)
	}
	if out != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return false, errors.New(msgNotAnswering)
		}
	}
	return false, nil
}

func exchange(conn net.Conn, method string, params any) (Response, error) {
	req := Request{Method: method}
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			return Response{}, err
		}
		req.Params = data
	}
	line, _ := json.Marshal(req)
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return Response{}, err
	}
	var resp Response
	data, err := bufio.NewReaderSize(conn, 4096).ReadBytes('\n')
	if err != nil {
		return resp, err
	}
	return resp, json.Unmarshal(data, &resp)
}

func (r *Remote) sessionCall(method string, opts clientctl.Options) error {
	wire, err := EncodeOptions(opts)
	if err != nil {
		return err
	}
	// An older helper can silently ignore new option fields.
	r.dropInfo()
	info := r.Info()
	if info.State == StateMissing {
		return errors.New(msgNotAnswering)
	}
	if info.State == StateOutdated {
		return ErrOutdated
	}
	if info.State != StateOK {
		return errors.New(info.Note)
	}
	_, err = r.call(context.Background(), startLimit, method, wire, nil)
	return err
}

func (r *Remote) Start(opts clientctl.Options) error {
	if err := r.sessionCall("start", opts); err != nil {
		return err
	}
	r.startHold()
	return nil
}

func (r *Remote) Apply(opts clientctl.Options) error {
	if err := r.sessionCall("apply", opts); err != nil {
		return err
	}
	r.startHold()
	return nil
}

func (r *Remote) Stop() error {
	r.SyncLogs()
	absent, err := r.call(context.Background(), stopLimit, "stop", nil, nil)
	r.stopHold()
	r.dropInfo() // shutdown callers need a fresh probe if Status cannot confirm it
	if absent {
		return nil // confirmed absent, so there is no session to stop
	}
	return err
}

func (r *Remote) Status() clientctl.Status {
	var st clientctl.Status
	if _, err := r.call(context.Background(), statusLimit, "status", nil, &st); err != nil {
		return clientctl.Status{State: clientctl.StateError, LastError: msgNotAnswering, Routes: map[string]clientctl.RouteLatency{}}
	}
	if st.Routes == nil {
		st.Routes = map[string]clientctl.RouteLatency{}
	}
	return st
}

func (r *Remote) SetMode(mode string) error {
	_, err := r.call(context.Background(), quickLimit, "setMode", map[string]string{"mode": mode}, nil)
	return err
}

func (r *Remote) SetTier(tier string) error {
	_, err := r.call(context.Background(), quickLimit, "setTier", map[string]string{"tier": tier}, nil)
	return err
}

func (r *Remote) TestRoutes(ctx context.Context) map[string]clientctl.RouteLatency {
	var res struct {
		Routes map[string]clientctl.RouteLatency `json:"routes"`
	}
	if _, err := r.call(ctx, 26*time.Second, "testRoutes", nil, &res); err != nil || res.Routes == nil {
		return map[string]clientctl.RouteLatency{}
	}
	return res.Routes
}

// Info reports the helper state, cached for 3 s.
func (r *Remote) Info() Info {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.info.State != "" && time.Since(r.infoAt) < infoTTL {
		return r.info
	}
	r.info = r.probe()
	r.infoAt = time.Now()
	return r.info
}

func (r *Remote) dropInfo() {
	r.mu.Lock()
	r.info = Info{}
	r.infoAt = time.Time{}
	r.mu.Unlock()
}

func (r *Remote) probe() Info {
	if r.socket == "" {
		return Info{State: StateUnsupported, Note: msgUnsupported}
	}
	var hello struct {
		Version  string `json:"version"`
		Protocol int    `json:"protocol"`
	}
	absent, err := r.call(context.Background(), helloTimeout, "hello", nil, &hello)
	switch {
	case absent:
		return Info{State: StateMissing, Note: msgMissing}
	case err != nil:
		return Info{State: StateError, Note: err.Error()}
	case hello.Version != r.opts.Version || hello.Protocol != ProtocolVersion:
		return Info{State: StateOutdated, Version: hello.Version, Note: msgOutdated}
	}
	return Info{State: StateOK, Version: hello.Version}
}

// startHold opens the lease connection, once.
func (r *Remote) startHold() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.holdStop != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	r.holdStop, r.holdDone = cancel, done
	go func() {
		defer close(done)
		r.holdLoop(ctx)
		// The loop ended on its own (the session is gone): free the slot so
		// the next Start holds again.
		r.mu.Lock()
		if r.holdDone == done {
			r.holdStop, r.holdDone = nil, nil
		}
		r.mu.Unlock()
		cancel()
	}()
}

func (r *Remote) stopHold() {
	r.mu.Lock()
	cancel, done := r.holdStop, r.holdDone
	r.holdStop, r.holdDone = nil, nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// holdLoop keeps the lease. It retries until a hold is established, and
// ends when an established hold breaks: the helper's session is gone then.
func (r *Remote) holdLoop(ctx context.Context) {
	for ctx.Err() == nil {
		if r.holdOnce(ctx) {
			return
		}
		if !sleepCtx(ctx, holdRetry) {
			return
		}
	}
}

// holdOnce keeps one lease connection until it breaks and reports whether
// an established hold broke. A break the app didn't cause means the session
// is gone, so OnChange fires.
func (r *Remote) holdOnce(ctx context.Context) (broke bool) {
	conn, err := net.DialTimeout("unix", r.socket, time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	line, _ := json.Marshal(Request{Method: "hold"})
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return false
	}
	br := bufio.NewReader(conn)
	data, err := br.ReadBytes('\n')
	var resp Response
	if err != nil || json.Unmarshal(data, &resp) != nil || resp.Error != "" {
		return false
	}
	conn.SetDeadline(time.Time{})
	buf := make([]byte, 64)
	for {
		if _, err := br.Read(buf); err != nil {
			break
		}
	}
	r.mu.Lock()
	f := r.onChange
	r.mu.Unlock()
	if ctx.Err() != nil {
		return false
	}
	if f != nil {
		f()
	}
	return true
}

// SyncLogs copies the helper's new log lines into the app's ring. The app
// calls it when logs are read; the cursor survives sessions, so nothing is
// copied twice.
func (r *Remote) SyncLogs() {
	if r.opts.Logs == nil {
		return
	}
	r.syncMu.Lock() // one copier at a time, so the cursor never copies twice
	defer r.syncMu.Unlock()
	for {
		r.mu.Lock()
		after := r.logCursor
		r.mu.Unlock()
		var res struct {
			Entries []logring.Entry `json:"entries"`
			Next    uint64          `json:"next"`
		}
		const limit = 500
		if _, err := r.call(context.Background(), 2*time.Second, "logs", map[string]uint64{"after": after, "limit": limit}, &res); err != nil {
			return
		}
		for _, e := range res.Entries {
			r.opts.Logs.Add(e.Level, e.Source, e.Message)
		}
		r.mu.Lock()
		r.logCursor = res.Next
		if res.Next < after {
			r.logCursor = 0 // the helper restarted with a fresh ring: read it from the start
		}
		r.mu.Unlock()
		if len(res.Entries) < limit && res.Next >= after {
			return
		}
	}
}

// elevateCommand builds the OS prompt command that runs the helper command
// with administrator rights.
func elevateCommand(goos, exe string, uid int, remove bool) (string, []string) {
	switch goos {
	case "darwin":
		tail, prompt := `" helper install --uid " & item 2 of argv`, "Pipe wants to install Pipe Helper so TUN can start without asking again."
		if remove {
			tail, prompt = `" helper remove"`, "Pipe wants to remove Pipe Helper."
		}
		return "osascript", []string{
			"-e", "on run argv",
			"-e", "do shell script (quoted form of item 1 of argv) & " + tail + ` with prompt "` + prompt + `" with administrator privileges`,
			"-e", "end run",
			exe, strconv.Itoa(uid),
		}
	default:
		if remove {
			return "pkexec", []string{exe, "helper", "remove"}
		}
		return "pkexec", []string{exe, "helper", "install", "--uid", strconv.Itoa(uid)}
	}
}

func openHelperImage(path string) (*os.File, error) {
	if runtime.GOOS == "linux" {
		path = "/proc/self/exe"
	}
	return os.Open(path)
}

func pinHelperDigest(path string, open func(string) (*os.File, error)) func() (string, error) {
	file, err := open(path)
	return sync.OnceValues(func() (string, error) {
		if err != nil {
			return "", fmt.Errorf("open the running Pipe executable: %w", err)
		}
		defer file.Close()
		return digestHelperImage(file)
	})
}

func digestHelperImage(file *os.File) (string, error) {
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", errors.New("Pipe's running image must be a regular executable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("read the running Pipe executable: %w", err)
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func (r *Remote) installImage() (path, digest string, err error) {
	exe := r.opts.Exe
	if exe == "" {
		exe, err = os.Executable()
		if err != nil {
			return "", "", err
		}
	}
	if trusted, err := r.trustedPath(exe); err == nil {
		return trusted, "", nil
	}
	path, err = filepath.Abs(exe)
	if err != nil {
		return "", "", err
	}
	readDigest := r.darwinDigest
	if r.goos != "darwin" || readDigest == nil {
		readDigest = pinHelperDigest(path, r.openImage)
	}
	digest, err = readDigest()
	return path, digest, err
}

func elevateStagedHelper(goos, path, digest, dir string, uid int) (string, []string) {
	shell := []string{"-c", stageHelperScript, "pipe-helper", path, digest, dir, strconv.Itoa(uid), goos}
	if goos == "darwin" {
		args := []string{
			"-e", "on run argv",
			"-e", `set commandLine to "/bin/sh"`,
			"-e", "repeat with arg in argv",
			"-e", `set commandLine to commandLine & " " & quoted form of (contents of arg)`,
			"-e", "end repeat",
			"-e", `do shell script commandLine with prompt "Pipe wants to install Pipe Helper so TUN can start without asking again." with administrator privileges`,
			"-e", "end run", "--",
		}
		return "osascript", append(args, shell...)
	}
	return "pkexec", append([]string{"/bin/sh"}, shell...)
}

func (r *Remote) elevate(remove bool) error {
	paths, supported := PathsFor(r.goos)
	if r.socket == "" || !supported {
		return errors.New(msgUnsupported)
	}
	var exe, digest string
	var err error
	if remove {
		exe, err = r.trustedPath(paths.Binary)
	} else {
		exe, digest, err = r.installImage()
	}
	if err != nil {
		if remove {
			return fmt.Errorf("verify the installed Pipe Helper: %w", err)
		}
		return err
	}
	uid := os.Getuid()
	name, args := elevateCommand(r.goos, exe, uid, remove)
	if digest != "" {
		name, args = elevateStagedHelper(r.goos, exe, digest, filepath.Dir(paths.Binary), uid)
	}
	if name == "pkexec" {
		if _, err := r.lookPath("pkexec"); err != nil {
			if digest != "" {
				return errors.New("Installing Pipe Helper from a portable package requires pkexec.")
			}
			quoted := "'" + strings.ReplaceAll(exe, "'", `'\''`) + "'"
			cmd := fmt.Sprintf("sudo %s helper install --uid %d", quoted, uid)
			if remove {
				cmd = fmt.Sprintf("sudo %s helper remove", quoted)
			}
			return errors.New("Run this once in a terminal: " + cmd)
		}
	}
	out, err := r.run(name, args...)
	if err != nil {
		text := strings.TrimSpace(string(out))
		var ee *exec.ExitError
		switch {
		case r.goos == "darwin" && strings.Contains(text, "-128"):
			return ErrCanceled
		case r.goos != "darwin" && errors.As(err, &ee) && ee.ExitCode() == 126:
			return ErrCanceled
		}
		verb := "install"
		if remove {
			verb = "remove"
		}
		if text == "" {
			text = err.Error()
		}
		return fmt.Errorf("Couldn't %s Pipe Helper: %s", verb, text)
	}
	return nil
}

func (r *Remote) settle(want string) error {
	deadline := time.Now().Add(settleLimit)
	for {
		r.dropInfo()
		info := r.Info()
		if info.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			if want == StateOK {
				return errors.New("Pipe Helper was installed but isn't answering yet.")
			}
			return errors.New("Pipe Helper is still running.")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Install shows the OS password prompt and installs or upgrades the helper.
func (r *Remote) Install() error {
	err := r.elevate(false)
	r.dropInfo()
	if err != nil {
		return err
	}
	return r.settle(StateOK)
}

// Remove shows the OS password prompt and removes the helper.
func (r *Remote) Remove() error {
	err := r.elevate(true) // stopping the service ends the session; a dismissed prompt changes nothing
	r.dropInfo()
	if err != nil {
		return err
	}
	r.stopHold()
	return r.settle(StateMissing)
}
