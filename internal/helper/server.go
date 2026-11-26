// SPDX-License-Identifier: GPL-3.0-or-later

package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/config"
	"pipe/internal/logring"
	"pipe/internal/sysdns"
)

const (
	maxRequestLine = 512 * 1024
	requestTimeout = 5 * time.Second

	defaultFirstHold = 10 * time.Second
	defaultLastHold  = 5 * time.Second

	msgOtherUser = "Pipe Helper belongs to another user on this computer."
)

// Session is the controller driven by the helper.
type Session interface {
	StartWithReady(opts clientctl.Options, ready func() error) error
	Stop() error
	Status() clientctl.Status
	SetMode(mode string) error
	SetTier(tier string) error
	Apply(opts clientctl.Options) error
	TestRoutes(ctx context.Context) map[string]clientctl.RouteLatency
	DefaultInterface() string
}

// SystemDNS is the platform resolver state managed alongside a TUN session.
type SystemDNS interface {
	Set() error
	Restore() error
	Repair() error
	Servers() []netip.AddrPort
}

// ServeOptions configures Serve.
type ServeOptions struct {
	Socket   string
	OwnerUID int
	Version  string
	Logs     *logring.Ring
	Session  Session
	DNS      SystemDNS

	// Test hooks. Zero values give the production behaviour.
	FirstHold time.Duration                    // lease before the first hold (10 s)
	LastHold  time.Duration                    // lease after the last hold closes (5 s)
	PeerUID   func(*net.UnixConn) (int, error) // kernel peer uid lookup

	probeProfile func(context.Context, clientctl.ProbeOptions) clientctl.ProfileTestResult
}

// chownSocket is a variable so tests can run without root.
var chownSocket = os.Chown

// ReadOwner reads the owner record: one user id on one line.
func ReadOwner(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || uid <= 0 {
		return 0, errors.New("the owner record is not valid")
	}
	return uid, nil
}

type server struct {
	opts ServeOptions
	peer func(*net.UnixConn) (int, error)

	probeSlots   chan struct{}
	updateRoutes updateRouteState

	ctl sync.Mutex // serializes start, apply, stop, setMode, setTier

	lmu    sync.Mutex // lease state
	holds  int
	active bool // a session was started and not stopped
	dnsTUN bool // system DNS is pointed at Pipe while a TUN session runs
	gen    uint64
	timer  *time.Timer
}

// Serve listens on opts.Socket until ctx ends, then stops the session and
// removes the socket.
func Serve(ctx context.Context, opts ServeOptions) error {
	if opts.Session == nil || opts.Socket == "" {
		return errors.New("helper: socket and session are required")
	}
	prepareSystemDNS(&opts)
	if opts.probeProfile == nil {
		opts.probeProfile = clientctl.TestProfile
	}
	s := &server{opts: opts, peer: opts.PeerUID, probeSlots: make(chan struct{}, 2)}
	s.setSessionStopHook()
	if s.peer == nil {
		s.peer = peerUID
	}
	if s.opts.FirstHold <= 0 {
		s.opts.FirstHold = defaultFirstHold
	}
	if s.opts.LastHold <= 0 {
		s.opts.LastHold = defaultLastHold
	}
	ln, err := s.listen()
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	connCtx, cancel := context.WithCancel(ctx)
	go func() {
		<-connCtx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if connCtx.Err() != nil {
				break
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			cancel()
			wg.Wait()
			s.shutdown()
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(connCtx, conn.(*net.UnixConn))
		}()
	}
	cancel()
	wg.Wait()
	s.shutdown()
	return nil
}

// prepareSystemDNS repairs DNS settings a crash left pointing at Pipe. A failed
// repair leaves the armed file for another attempt and does not stop startup.
func prepareSystemDNS(opts *ServeOptions) {
	if opts.DNS == nil {
		opts.DNS = sysdns.NewDefault()
	}
	if err := opts.DNS.Repair(); err != nil {
		fmt.Fprintln(os.Stderr, "Pipe Helper: could not repair system DNS:", err)
	}
	if session, ok := opts.Session.(interface{ SetLANDNSServers(func() []netip.AddrPort) }); ok {
		session.SetLANDNSServers(opts.DNS.Servers)
	}
}

func (s *server) sessionStopped() {
	s.ctl.Lock()
	defer s.ctl.Unlock()
	// A start may have taken the lock first: only a session that is still down
	// gives up its lease and the system DNS.
	if status := s.opts.Session.Status(); status.Guarded || status.State == clientctl.StateOn || status.State == clientctl.StateConnecting {
		return
	}
	s.disarmLease()
	_ = s.restoreDNS()
}

func (s *server) setSessionStopHook() {
	if session, ok := s.opts.Session.(interface{ SetOnStopped(func()) }); ok {
		session.SetOnStopped(func() { go s.sessionStopped() })
	}
}

func (s *server) listen() (net.Listener, error) {
	path := s.opts.Socket
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	if err := chownSocket(path, s.opts.OwnerUID, -1); err != nil {
		ln.Close()
		os.Remove(path)
		return nil, err
	}
	return ln, nil
}

func (s *server) shutdown() {
	s.lmu.Lock()
	s.gen++
	if s.timer != nil {
		s.timer.Stop()
	}
	s.active = false
	s.lmu.Unlock()
	s.ctl.Lock()
	s.opts.Session.Stop()
	_ = s.restoreDNS()
	s.ctl.Unlock()
	os.Remove(s.opts.Socket)
}

func reply(conn net.Conn, res any, errText string) {
	var r Response
	if errText != "" {
		r.Error = errText
	} else {
		data, err := json.Marshal(res)
		if err != nil {
			r.Error = "Pipe Helper couldn't answer."
		} else {
			r.Result = data
		}
	}
	line, _ := json.Marshal(r)
	conn.SetWriteDeadline(time.Now().Add(requestTimeout))
	conn.Write(append(line, '\n'))
}

// readLine reads one request line of at most maxRequestLine bytes.
func readLine(conn net.Conn) ([]byte, error) {
	lr := &io.LimitedReader{R: conn, N: maxRequestLine + 1}
	line, err := bufio.NewReaderSize(lr, 4096).ReadBytes('\n')
	if len(line) > maxRequestLine {
		return nil, errors.New("That request is too large.")
	}
	if err != nil {
		return nil, errors.New("Pipe Helper couldn't read the request.")
	}
	return line, nil
}

func (s *server) handle(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	uid, err := s.peer(conn)
	if err != nil || (uid != s.opts.OwnerUID && uid != 0) {
		reply(conn, nil, msgOtherUser)
		// Let the client's request arrive so closing doesn't reset the answer.
		conn.SetReadDeadline(time.Now().Add(time.Second))
		io.Copy(io.Discard, io.LimitReader(conn, maxRequestLine))
		return
	}
	conn.SetReadDeadline(time.Now().Add(requestTimeout))
	line, err := readLine(conn)
	if err != nil {
		reply(conn, nil, err.Error())
		return
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		reply(conn, nil, "That request isn't valid.")
		return
	}
	if req.Method == "updateStream" {
		s.serveUpdateStream(ctx, conn, req.Params)
		return
	}
	conn.SetReadDeadline(time.Time{})
	if req.Method == "hold" {
		s.hold(ctx, conn)
		return
	}
	if req.Method == "testProfile" || req.Method == "testRoutes" {
		// Each connection carries one request. A read observes client cancellation
		// while the probe runs. The deferred Close also releases the read on success.
		pctx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			var buf [1]byte
			_, _ = conn.Read(buf[:])
			cancel()
		}()
		ctx = pctx
	}
	res, errText := s.dispatch(ctx, req)
	reply(conn, res, errText)
}

func (s *server) dispatch(ctx context.Context, req Request) (any, string) {
	ses := s.opts.Session
	switch req.Method {
	case "hello":
		return map[string]any{"version": s.opts.Version, "protocol": ProtocolVersion}, ""
	case "status":
		return ses.Status(), ""
	case "logs":
		var p struct {
			After uint64 `json:"after"`
			Limit int    `json:"limit"`
		}
		if len(req.Params) > 0 && json.Unmarshal(req.Params, &p) != nil {
			return nil, "That request isn't valid."
		}
		if p.Limit <= 0 || p.Limit > logring.DefaultCapacity {
			p.Limit = 200
		}
		entries, next := []logring.Entry{}, p.After
		if s.opts.Logs != nil {
			entries, next = s.opts.Logs.Since(p.After, p.Limit)
		}
		return map[string]any{"entries": entries, "next": next}, ""
	case "testRoutes":
		tctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		routes := ses.TestRoutes(tctx)
		if routes == nil {
			routes = map[string]clientctl.RouteLatency{}
		}
		return map[string]any{"routes": routes}, ""
	case "testProfile":
		return s.testProfile(ctx, req.Params)
	case "start", "apply":
		var p SessionOptions
		if json.Unmarshal(req.Params, &p) != nil {
			return nil, "That request isn't valid."
		}
		opts, err := DecodeOptions(p)
		if err != nil {
			return nil, err.Error()
		}
		s.ctl.Lock()
		defer s.ctl.Unlock()
		var dnsErr error
		ready := func() error {
			err := s.updateDNS(true)
			if dnsErr == nil {
				dnsErr = err
			}
			return err
		}
		if req.Method == "start" {
			err = ses.StartWithReady(opts, ready)
		} else if session, ok := ses.(interface {
			ApplyWithReady(clientctl.Options, func() error) error
		}); ok {
			err = session.ApplyWithReady(opts, ready)
		} else {
			err = ses.Apply(opts)
			if err == nil && ses.Status().State == clientctl.StateOn {
				_ = ready()
			}
		}
		status := ses.Status()
		// A failed DNS update on an unchanged session still leaves TUN active.
		if status.Guarded || status.State == clientctl.StateOn || status.State == clientctl.StateConnecting {
			s.armLease()
		} else {
			s.disarmLease()
			if dnsErr != nil {
				_ = ses.Stop()
			}
			_ = s.restoreDNS()
		}
		if dnsErr != nil {
			return nil, fmt.Sprintf("Could not set system DNS: %v", dnsErr)
		}
		if err != nil {
			return nil, err.Error()
		}
		if status.State != clientctl.StateOn {
			return nil, "The client session is not running."
		}
		return status, ""
	case "stop":
		s.ctl.Lock()
		defer s.ctl.Unlock()
		s.disarmLease()
		stopErr := ses.Stop()
		dnsErr := s.restoreDNS()
		if stopErr != nil {
			return nil, stopErr.Error()
		}
		if dnsErr != nil {
			return nil, fmt.Sprintf("Could not restore system DNS: %v", dnsErr)
		}
		return ses.Status(), ""
	case "setMode":
		var p struct {
			Mode string `json:"mode"`
		}
		if json.Unmarshal(req.Params, &p) != nil || !config.ValidMode(p.Mode) {
			return nil, "Routing mode must be Smart, Global or Direct."
		}
		s.ctl.Lock()
		defer s.ctl.Unlock()
		modeErr := ses.SetMode(p.Mode)
		status := ses.Status()
		if status.Guarded {
			s.armLease()
		} else if status.State != clientctl.StateOn {
			s.disarmLease()
			_ = s.restoreDNS()
		}
		if modeErr != nil {
			return nil, modeErr.Error()
		}
		return status, ""
	case "setTier":
		var p struct {
			Tier string `json:"tier"`
		}
		if json.Unmarshal(req.Params, &p) != nil || !validTier(p.Tier) {
			return nil, "That route isn't available."
		}
		s.ctl.Lock()
		defer s.ctl.Unlock()
		if err := ses.SetTier(p.Tier); err != nil {
			return nil, err.Error()
		}
		return ses.Status(), ""
	}
	return nil, "Pipe Helper doesn't know that request."
}

func (s *server) updateDNS(tun bool) error {
	if !tun {
		err := s.opts.DNS.Restore()
		if err == nil {
			s.dnsTUN = false
		}
		return err
	}
	if err := s.opts.DNS.Set(); err != nil {
		return err
	}
	s.dnsTUN = true
	return nil
}

func (s *server) restoreDNS() error { return s.updateDNS(false) }

// HoldSession renews the lease for a session observed through Status, including
// an active session whose Start reply went missing or whose GUI restarted.
func (r *Remote) HoldSession() { r.startHold() }

// hold keeps the lease alive for as long as the connection stays open.
func (s *server) hold(ctx context.Context, conn *net.UnixConn) {
	s.lmu.Lock()
	s.holds++
	s.gen++
	if s.timer != nil {
		s.timer.Stop()
	}
	s.lmu.Unlock()
	reply(conn, struct{}{}, "")

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	buf := make([]byte, 512)
	for {
		if _, err := conn.Read(buf); err != nil {
			break
		}
	}
	close(done)

	s.lmu.Lock()
	s.holds--
	if s.holds == 0 && s.active && ctx.Err() == nil {
		s.schedule(s.opts.LastHold)
	}
	s.lmu.Unlock()
}

// armLease starts the first-hold countdown unless a hold is already open.
func (s *server) armLease() {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	s.active = true
	if s.holds == 0 {
		s.schedule(s.opts.FirstHold)
	}
}

func (s *server) disarmLease() {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	s.active = false
	s.gen++
	if s.timer != nil {
		s.timer.Stop()
	}
}

// schedule must be called with lmu held. A newer schedule or a hold
// invalidates the older timer through gen.
func (s *server) schedule(d time.Duration) {
	s.gen++
	gen := s.gen
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(d, func() { s.expire(gen) })
}

func (s *server) expire(gen uint64) {
	s.ctl.Lock()
	defer s.ctl.Unlock()
	s.lmu.Lock()
	if gen != s.gen || s.holds > 0 || !s.active {
		s.lmu.Unlock()
		return
	}
	s.active = false
	s.lmu.Unlock()
	s.opts.Session.Stop()
	_ = s.restoreDNS()
}
