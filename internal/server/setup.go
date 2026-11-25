// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"pipe/internal/localfile"
)

const (
	setupBinary    = "/usr/local/bin/pipe"
	setupStateDir  = "/var/lib/pipe"
	setupUnitDir   = "/etc/systemd/system"
	setupSysctlDir = "/etc/sysctl.d"
	setupHopRange  = "20000-40000"
)

// SetupCommand is one external command. AsPipe runs it as the pipe user.
type SetupCommand struct {
	Argv   []string
	AsPipe bool
}

// SetupInterface is one network interface and its addresses.
type SetupInterface struct {
	Name  string
	Addrs []netip.Addr
}

// SetupOptions are the flags of pipe server setup.
type SetupOptions struct {
	Yes                                      bool
	Dir                                      string
	Mode                                     string
	Domain, FastSNI, CDNDomain, RescueListen string
	RealityDest, FastHop                     string
	ProxyDomain, ProxyCertMethod, ACMEListen string
	DNS, DNSKeyFile, DNSTokenFile, Cert, Key string
	Device                                   string
}

// SetupEnv holds every side effect so tests can replace it.
type SetupEnv struct {
	Root           string // prefix for all file paths
	GOOS           string
	EUID           int
	Executable     string
	Run            func(context.Context, SetupCommand) error
	LookupPipeUser func() (uid, gid uint32, found bool, err error)
	Chown          func(path string, uid, gid uint32) error
	Interfaces     func() ([]SetupInterface, error)
	PortBusy       func(port int) bool
	PortProbe      func(port int) (busy, unknown bool) // used by --template only
	Suffix         func() string
	In             io.Reader
	Out            io.Writer
}

// NewSetupEnv returns the real hooks.
func NewSetupEnv(in io.Reader, out io.Writer) (SetupEnv, error) {
	executable, err := os.Executable()
	if err != nil {
		return SetupEnv{}, err
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	return SetupEnv{
		GOOS: runtime.GOOS, EUID: os.Geteuid(), Executable: executable,
		Run: runSetupCommand, LookupPipeUser: lookupPipeUser, Chown: func(p string, uid, gid uint32) error {
			return os.Chown(p, int(uid), int(gid))
		},
		Interfaces: listSetupInterfaces, PortBusy: setupPortBusy, PortProbe: setupPortProbe,
		Suffix: func() string {
			b := make([]byte, 6)
			_, _ = rand.Read(b)
			return hex.EncodeToString(b)
		},
		In: in, Out: out,
	}, nil
}

func lookupPipeUser() (uint32, uint32, bool, error) {
	u, err := user.Lookup("pipe")
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return 0, 0, false, nil
		}
		return 0, 0, false, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, false, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	return uint32(uid), uint32(gid), err == nil, err
}

func runSetupCommand(ctx context.Context, c SetupCommand) error {
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if c.AsPipe {
		uid, gid, found, err := lookupPipeUser()
		if err != nil || !found {
			return errors.New("user pipe does not exist")
		}
		cmd.Env = append(os.Environ(), "HOME="+setupStateDir)
		if err := dropCredentials(cmd, uid, gid); err != nil {
			return err
		}
	}
	// Interrupt the child instead of killing it so it can restore the terminal.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 3 * time.Second
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(c.Argv[:min(len(c.Argv), 3)], " "), err)
	}
	return nil
}

func listSetupInterfaces() ([]SetupInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []SetupInterface
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		entry := SetupInterface{Name: iface.Name}
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				entry.Addrs = append(entry.Addrs, p.Addr().Unmap())
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

func setupPortBusy(port int) bool {
	for _, e := range []struct{ network, host string }{{"tcp4", "0.0.0.0"}, {"tcp6", "::"}} {
		l, err := net.Listen(e.network, net.JoinHostPort(e.host, strconv.Itoa(port)))
		if err == nil {
			_ = l.Close()
			continue
		}
		if portInUse(err) {
			return true
		}
	}
	return false
}

// SetupDetection is what setup learned about the host.
type SetupDetection struct {
	PublicIPs   []netip.Addr
	Bridges     []netip.Addr
	Port80Busy  bool
	Port443Busy bool
	// NetworkBridges are the br-* gateways (a subset of Bridges).
	NetworkBridges []netip.Addr
	// PortsUnknown means a port could not be probed (not root).
	PortsUnknown bool
}

func (d SetupDetection) suggestedMode() DeployMode {
	if d.Port80Busy || d.Port443Busy {
		return Shared
	}
	return Standalone
}

func publicAddress(a netip.Addr) bool {
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	return a.IsValid() && a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() &&
		!a.IsLinkLocalUnicast() && !cgnat.Contains(a)
}

func detectInterfaces(ifaces []SetupInterface) SetupDetection {
	var d SetupDetection
	for _, iface := range ifaces {
		bridge := iface.Name == "docker0" || strings.HasPrefix(iface.Name, "br-")
		for _, a := range iface.Addrs {
			switch {
			case bridge && a.Is4():
				d.Bridges = append(d.Bridges, a)
				if iface.Name != "docker0" {
					d.NetworkBridges = append(d.NetworkBridges, a)
				}
			case !bridge && publicAddress(a):
				d.PublicIPs = append(d.PublicIPs, a)
			}
		}
	}
	return d
}

func (e SetupEnv) detect() (SetupDetection, error) {
	ifaces, err := e.Interfaces()
	if err != nil {
		return SetupDetection{}, err
	}
	d := detectInterfaces(ifaces)
	d.Port80Busy, d.Port443Busy = e.PortBusy(80), e.PortBusy(443)
	return d, nil
}

func (e SetupEnv) path(p string) string { return filepath.Join(e.Root, p) }

type setupRun struct {
	SetupEnv
	opts    SetupOptions
	in      *bufio.Reader
	uid     uint32
	gid     uint32
	cleanup []string
	ctx     context.Context

	proxyDomainAsked bool // reality_dest self already asked for the proxy domain
}

func (r *setupRun) printf(format string, args ...any) {
	fmt.Fprintf(r.Out, format, args...)
}

// ask prompts for a line. Blank input or EOF returns def.
func (r *setupRun) ask(label, def string) string {
	if def != "" {
		r.printf("%s [%s]: ", label, def)
	} else {
		r.printf("%s: ", label)
	}
	done := make(chan string, 1)
	go func() {
		line, _ := r.in.ReadString('\n')
		done <- line
	}()
	var line string
	select {
	case line = <-done:
	case <-r.ctx.Done():
		return def
	}
	if r.ctx.Err() != nil {
		return def
	}
	if line = strings.TrimSpace(line); line != "" {
		return line
	}
	return def
}

func (r *setupRun) askYes(label string, def bool) bool {
	hint := "Y/n"
	if !def {
		hint = "y/N"
	}
	switch strings.ToLower(r.ask(label+" ("+hint+")", "")) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	}
	return def
}

func (r *setupRun) askRequired(label, def string) (string, error) {
	if v := r.ask(label, def); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("%s is required", strings.ToLower(label))
}

// Setup turns a fresh server into a running one, or safely upgrades an existing one.
func Setup(ctx context.Context, env SetupEnv, opts SetupOptions) (err error) {
	if env.GOOS != "linux" || env.EUID != 0 {
		return errors.New("run as root: sudo pipe server setup")
	}
	if opts.Dir == "" {
		opts.Dir = setupStateDir
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	r := &setupRun{ctx: ctx, SetupEnv: env, opts: opts, in: bufio.NewReader(env.In)}
	defer func() {
		for _, p := range r.cleanup {
			_ = os.Remove(env.path(p))
		}
	}()
	if err := r.installBinary(); err != nil {
		return err
	}
	if err := r.prepareUser(ctx); err != nil {
		return err
	}
	det, err := r.detect()
	if err != nil {
		return err
	}
	r.printDetection(det)
	existing := fileExists(r.path(filepath.Join(opts.Dir, settingsFile)))
	if existing {
		if err := r.chownState(); err != nil {
			return err
		}
	}
	var plan setupPlan
	if existing {
		plan, err = r.planExisting(det)
	} else {
		plan, err = r.planFresh(det)
	}
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	if err != nil {
		return err
	}
	if err := r.execute(ctx, plan); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.finish(plan, det)
	return nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (r *setupRun) installBinary() error {
	dest := r.path(setupBinary)
	info, err := os.Lstat(dest)
	regular := err == nil && info.Mode().IsRegular()
	if regular {
		same := r.Executable == dest
		if !same {
			data, err := os.ReadFile(r.Executable)
			if err != nil {
				return err
			}
			old, err := os.ReadFile(dest)
			same = err == nil && bytes.Equal(old, data)
		}
		if same {
			return r.fixBinary(dest)
		}
	}
	data, err := os.ReadFile(r.Executable)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	// Rename replaces a symlink at dest instead of following it.
	if err := writeAtomic(filepath.Dir(dest), filepath.Base(dest), data, 0755); err != nil {
		return err
	}
	if err := r.fixBinary(dest); err != nil {
		return err
	}
	r.printf("Installed %s\n", setupBinary)
	return nil
}

func (r *setupRun) fixBinary(dest string) error {
	if err := os.Chmod(dest, 0755); err != nil {
		return err
	}
	return r.Chown(dest, 0, 0)
}

// chownState gives pipe every non-symlink entry of the state dir. It never follows symlinks.
func (r *setupRun) chownState() error {
	return filepath.WalkDir(r.path(r.opts.Dir), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		return r.Chown(p, r.uid, r.gid)
	})
}

func (r *setupRun) prepareUser(ctx context.Context) error {
	uid, gid, found, err := r.LookupPipeUser()
	if err != nil {
		return err
	}
	if !found {
		nologin := "/usr/sbin/nologin"
		if !fileExists(r.path(nologin)) && fileExists(r.path("/sbin/nologin")) {
			nologin = "/sbin/nologin"
		}
		err := r.Run(ctx, SetupCommand{Argv: []string{"useradd", "--system", "--home-dir", setupStateDir, "--shell", nologin, "pipe"}})
		if err != nil {
			return err
		}
		if uid, gid, found, err = r.LookupPipeUser(); err != nil || !found {
			return errors.New("user pipe was not created")
		}
	}
	r.uid, r.gid = uid, gid
	dir := r.path(r.opts.Dir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	return r.Chown(dir, uid, gid)
}

func (r *setupRun) printDetection(d SetupDetection) {
	ips := make([]string, 0, len(d.PublicIPs))
	for _, ip := range d.PublicIPs {
		ips = append(ips, ip.String())
	}
	r.printf("Public IPs: %s\n", orNone(strings.Join(ips, ", ")))
	r.printf("TCP 80 busy: %t, TCP 443 busy: %t. Suggested mode: %s.\n", d.Port80Busy, d.Port443Busy, d.suggestedMode())
	if len(d.Bridges) > 0 {
		bridges := make([]string, 0, len(d.Bridges))
		for _, b := range d.Bridges {
			bridges = append(bridges, b.String())
		}
		r.printf("Docker bridge gateways: %s\n", strings.Join(bridges, ", "))
	}
}

func orNone(s string) string {
	if s == "" {
		return "none found"
	}
	return s
}

// setupPlan is the list of decisions made before anything is changed.
// stageSpec names an argv entry that holds a source file to stage for pipe.
type stageSpec struct {
	index  int
	src    string
	secret bool
}

type setupPlan struct {
	existing     bool
	mode         DeployMode
	domain, cdn  string
	rescueListen string
	fastHop      string
	initArgs     []string
	proxyArgs    []string
	proxyDomain  string
	device       string
	proxyStage   []stageSpec
	realityArgs  []string // existing server: move an older REALITY target to self
	noStealth    bool     // shared mode without the HTTPS proxy
}

type savedSettings struct {
	Mode         string `json:"mode"`
	Domain       string `json:"domain"`
	CDNDomain    string `json:"cdn_domain"`
	FastHop      string `json:"fast_hop"`
	RescueListen string `json:"rescue_listen"`
	HTTPSProxy   *bool  `json:"https_proxy"`
	RealityDest  string `json:"reality_dest"`
	Listener     *struct {
		Domain string `json:"domain"`
		Port   uint16 `json:"port"`
	} `json:"https_proxy_listener"`
}

func (r *setupRun) planExisting(det SetupDetection) (setupPlan, error) {
	data, err := os.ReadFile(r.path(filepath.Join(r.opts.Dir, settingsFile)))
	if err != nil {
		return setupPlan{}, err
	}
	var s savedSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return setupPlan{}, fmt.Errorf("read %s: %w", settingsFile, err)
	}
	if s.Mode == "" {
		s.Mode = string(Standalone)
	}
	plan := setupPlan{existing: true, mode: DeployMode(s.Mode), domain: s.Domain, cdn: s.CDNDomain, rescueListen: s.RescueListen, fastHop: s.FastHop}
	proxyOn := s.Listener != nil || (DeployMode(s.Mode) == Standalone && (s.HTTPSProxy == nil || *s.HTTPSProxy))
	r.printf("Existing install in %s: mode %s, domain %s", r.opts.Dir, s.Mode, s.Domain)
	if s.CDNDomain != "" {
		r.printf(", Rescue %s", s.CDNDomain)
	}
	if s.FastHop != "" {
		r.printf(", Fast hop %s", s.FastHop)
	}
	switch {
	case s.Listener != nil:
		r.printf(", HTTPS proxy %s:%d", s.Listener.Domain, s.Listener.Port)
	case proxyOn:
		r.printf(", HTTPS proxy on")
	default:
		r.printf(", HTTPS proxy off")
	}
	r.printf(".\nState is kept; init is skipped.\n")
	if plan.mode == Shared && !proxyOn {
		if (r.opts.Yes && r.opts.ProxyDomain != "") || (!r.opts.Yes && r.askYes("Enable the HTTPS proxy?", false)) {
			if err := r.planProxy(&plan, det); err != nil {
				return plan, err
			}
		}
	} else if r.opts.Yes && r.opts.ProxyDomain != "" && (s.Listener == nil || !equalDNS(s.Listener.Domain, r.opts.ProxyDomain)) {
		return plan, errors.New("the HTTPS proxy is already enabled or needs shared mode")
	}
	if err := r.planRetarget(&plan, s, proxyOn); err != nil {
		return plan, err
	}
	plan.device = r.opts.Device
	if !r.opts.Yes && plan.device == "" {
		plan.device = r.ask("Add a device (name, blank to skip)", "")
	}
	return plan, nil
}

// planRetarget handles one narrow change of an existing shared server: an
// older third-party REALITY target moves to self (the HTTPS proxy site). It
// changes links, so it only runs when reality_dest self is asked for.
func (r *setupRun) planRetarget(plan *setupPlan, s savedSettings, proxyOn bool) error {
	if err := CheckRealityDest(r.opts.RealityDest); err != nil {
		return err
	}
	if plan.mode != Shared {
		return nil
	}
	haveProxy := proxyOn || plan.proxyArgs != nil
	asked := r.opts.RealityDest != ""
	if asked && !haveProxy {
		return errSelfNeedsProxy
	}
	plan.noStealth = !haveProxy
	if s.RealityDest != "" && s.RealityDest != realitySelf {
		if !asked {
			r.printf("Stealth is off: this server still has the REALITY target %s, which is no longer supported. Re-run setup with reality_dest self to move it to your HTTPS proxy site.\n", s.RealityDest)
		} else {
			plan.realityArgs = []string{setupBinary, "server", "reality", "--dir", r.opts.Dir}
		}
	}
	return nil
}

func (r *setupRun) planFresh(det SetupDetection) (setupPlan, error) {
	o := r.opts
	plan := setupPlan{}
	yes := o.Yes
	need := func(v, flag string) error {
		if yes && v == "" {
			return fmt.Errorf("--yes requires %s", flag)
		}
		return nil
	}
	suggested := det.suggestedMode()
	switch DeployMode(o.Mode) {
	case Standalone, Shared:
		plan.mode = DeployMode(o.Mode)
	case "", Auto:
		plan.mode = suggested
		if !yes {
			r.printf("Shared mode runs pipe next to an existing website. Standalone owns TCP 80 and 443.\n")
			switch strings.ToLower(r.ask("Mode (standalone or shared)", string(suggested))) {
			case "standalone":
				plan.mode = Standalone
			case "shared":
				plan.mode = Shared
			default:
				return plan, errors.New("mode must be standalone or shared")
			}
		}
	default:
		return plan, errors.New("--mode must be standalone or shared")
	}
	if err := CheckRealityDest(o.RealityDest); err != nil {
		return plan, err
	}
	if plan.mode == Standalone && (o.RealityDest != "" || o.RescueListen != "" || o.ProxyDomain != "") {
		return plan, errors.New("reality_dest, Rescue listen and a separate HTTPS proxy need shared mode")
	}
	args := []string{setupBinary, "server", "init", "--dir", r.opts.Dir, "--mode", string(plan.mode)}
	var err error
	if plan.mode == Standalone {
		plan.domain = o.Domain
		if err = need(plan.domain, "--domain"); err != nil {
			return plan, err
		}
		if !yes {
			r.printf("Create a DNS A record for this name pointing at this server.\n")
			if plan.domain, err = r.askRequired("Domain", plan.domain); err != nil {
				return plan, err
			}
		}
		plan.cdn = o.CDNDomain
		if !yes && plan.cdn == "" {
			plan.cdn = r.ask("CDN domain for Rescue (blank for none)", "")
		}
		plan.fastHop = o.FastHop
		if !yes && plan.fastHop == "" && r.askYes("Fast port hopping "+setupHopRange, true) {
			plan.fastHop = setupHopRange
		}
		args = append(args, "--domain", plan.domain)
		if plan.cdn != "" {
			args = append(args, "--cdn-domain", plan.cdn)
		}
	} else {
		def := o.Domain
		if def == "" && len(det.PublicIPs) > 0 {
			def = det.PublicIPs[0].String()
		}
		plan.domain = def
		if err = need(plan.domain, "--domain"); err != nil {
			return plan, err
		}
		if !yes {
			if plan.domain, err = r.askRequired("Server address (DNS name or IP)", def); err != nil {
				return plan, err
			}
		}
		fastSNI := o.FastSNI
		if _, ipErr := netip.ParseAddr(plan.domain); ipErr == nil {
			if err = need(fastSNI, "--fast-sni (the server address is an IP)"); err != nil {
				return plan, err
			}
			if !yes {
				if fastSNI, err = r.askRequired("Fast SNI name (a DNS name, required for an IP address)", fastSNI); err != nil {
					return plan, err
				}
			}
		}
		plan.cdn = o.CDNDomain
		if !yes && plan.cdn == "" {
			plan.cdn = r.ask("Rescue CDN subdomain (blank for none)", "")
		}
		plan.rescueListen = o.RescueListen
		if plan.cdn != "" && plan.rescueListen == "" {
			if len(det.Bridges) > 0 {
				plan.rescueListen = net.JoinHostPort(det.Bridges[0].String(), "18080")
			}
			if yes {
				if plan.rescueListen == "" {
					return plan, errors.New("--yes requires --rescue-listen with --cdn-domain")
				}
			} else {
				r.printf("Rescue listen is the Docker bridge gateway of the web server. Find it with:\n  docker inspect <nginx-container> --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}'\n")
				if plan.rescueListen, err = r.askRequired("Rescue listen IP:port", plan.rescueListen); err != nil {
					return plan, err
				}
			}
		}
		args = append(args, "--domain", plan.domain)
		if fastSNI != "" {
			args = append(args, "--fast-sni", fastSNI)
		}
		if plan.cdn != "" {
			args = append(args, "--cdn-domain", plan.cdn, "--rescue-listen", plan.rescueListen)
		}
		plan.fastHop = o.FastHop
		if !yes && plan.fastHop == "" && r.askYes("Fast port hopping "+setupHopRange, true) {
			plan.fastHop = setupHopRange
		}
	}
	if plan.fastHop != "" && plan.fastHop != "none" {
		args = append(args, "--fast-hop", plan.fastHop)
	}
	plan.initArgs = args
	if plan.mode == Shared {
		if yes && o.ProxyDomain == "" {
			// No proxy requested.
		} else if err := r.planProxy(&plan, det); err != nil {
			return plan, err
		}
		if plan.proxyArgs == nil {
			if o.RealityDest != "" {
				return plan, errSelfNeedsProxy
			}
			plan.noStealth = true
		}
	}
	plan.device = o.Device
	if plan.device == "" {
		plan.device = "phone"
		if !yes {
			plan.device = r.ask("First device name", "phone")
		}
	}
	return plan, nil
}

// stage copies a root-readable file into the state dir for the pipe user, removed at the end.
func (r *setupRun) stage(src string, secret bool) (string, error) {
	var data []byte
	var err error
	if secret {
		data, err = localfile.Read(r.path(src), 4096, true)
	} else {
		data, err = os.ReadFile(r.path(src))
	}
	if err != nil {
		return "", err
	}
	defer clear(data)
	name := ".setup-" + r.Suffix()
	rel := filepath.Join(r.opts.Dir, name)
	file := r.path(rel)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	r.cleanup = append(r.cleanup, rel)
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if err := r.Chown(file, r.uid, r.gid); err != nil {
		return "", err
	}
	return rel, nil
}

func (r *setupRun) planProxy(plan *setupPlan, det SetupDetection) error {
	o := r.opts
	yes := o.Yes
	domain := o.ProxyDomain
	if !yes && !r.proxyDomainAsked {
		r.printf("The HTTPS proxy needs its own DNS-only name pointing at this server.\n")
		domain = r.ask("HTTPS proxy domain (blank to skip)", domain)
		if domain == "" {
			return nil
		}
	} else if domain == "" {
		return errors.New("--yes requires --proxy-domain to enable the HTTPS proxy")
	}
	method := o.ProxyCertMethod
	if method == "" {
		method = "auto"
	}
	if !yes {
		method = strings.ToLower(r.ask("Certificate method (auto, http, nginx, dns, files)", method))
	}
	switch method {
	case "auto", "http", "nginx", "dns", "files":
	default:
		return errors.New("certificate method must be auto, http, nginx, dns or files")
	}
	dns, key, token, cert, keyFile, acme := o.DNS, o.DNSKeyFile, o.DNSTokenFile, o.Cert, o.Key, o.ACMEListen
	if method == "auto" {
		// Resolve here as root: the child cannot probe TCP 80 without privileges.
		var why string
		switch {
		case cert != "" || keyFile != "":
			method, why = "files", "certificate files were given"
		case dns != "":
			method, why = "dns", "a DNS provider was given"
		case det.Port80Busy:
			method, why = "nginx", "TCP 80 is taken by a web server"
		default:
			method, why = "http", "TCP 80 is free"
		}
		r.printf("Certificate method auto chose %s: %s.\n", method, why)
	}
	args := []string{setupBinary, "server", "proxy", "enable", "--dir", r.opts.Dir, "--domain", domain, "--cert-method", method}
	if !yes {
		switch method {
		case "dns":
			dns = r.ask("DNS provider (cloudflare or alidns)", dns)
			if dns == "alidns" {
				key = r.ask("AccessKey file (blank to be prompted)", key)
			} else {
				token = r.ask("API token file (blank to be prompted)", token)
			}
		case "files":
			cert = r.ask("Certificate chain file", cert)
			keyFile = r.ask("Private key file", keyFile)
			r.printf("Warning: these files must stay readable by user pipe.\n")
		}
	}
	if method == "nginx" && plan.rescueListen == "" && acme == "" {
		if yes {
			return errors.New("--yes requires --acme-listen for the nginx method without a Rescue listener")
		}
		var err error
		if acme, err = r.askRequired("ACME listen private IP:port for nginx", ""); err != nil {
			return err
		}
	}
	if method == "dns" && dns == "" {
		return errors.New("--dns is required for the dns method")
	}
	if method == "files" && (cert == "" || keyFile == "") {
		return errors.New("--cert and --key are required for the files method")
	}
	if dns != "" {
		args = append(args, "--dns", dns)
	}
	for _, f := range []struct {
		flag string
		path *string
	}{{"--dns-key-file", &key}, {"--dns-token-file", &token}} {
		if *f.path == "" {
			continue
		}
		args = append(args, f.flag, *f.path)
		plan.proxyStage = append(plan.proxyStage, stageSpec{len(args) - 1, *f.path, true})
	}
	if cert != "" {
		args = append(args, "--cert", cert)
		r.printf("Note: %s must stay readable by user pipe.\n", cert)
	}
	if keyFile != "" {
		args = append(args, "--key", keyFile)
		r.printf("Note: %s must stay readable by user pipe.\n", keyFile)
	}
	if acme != "" {
		args = append(args, "--acme-listen", acme)
	}
	plan.proxyArgs, plan.proxyDomain = args, domain
	return nil
}

func (r *setupRun) execute(ctx context.Context, plan setupPlan) error {
	asPipe := func(argv ...string) error {
		return r.Run(ctx, SetupCommand{Argv: argv, AsPipe: true})
	}
	// Staged copies exist only while the child that reads them runs.
	asPipeStaged := func(argv []string, specs []stageSpec) error {
		argv = append([]string(nil), argv...)
		for _, spec := range specs {
			staged, err := r.stage(spec.src, spec.secret)
			if err != nil {
				return err
			}
			argv[spec.index] = staged
			defer os.Remove(r.path(staged))
		}
		return asPipe(argv...)
	}
	asRoot := func(argv ...string) error {
		return r.Run(ctx, SetupCommand{Argv: argv})
	}
	if !plan.existing {
		if err := asPipe(plan.initArgs...); err != nil {
			return err
		}
	}
	if plan.proxyArgs != nil {
		if err := asPipeStaged(plan.proxyArgs, plan.proxyStage); err != nil {
			return err
		}
	}
	if plan.realityArgs != nil {
		if err := asPipe(plan.realityArgs...); err != nil {
			return err
		}
	}
	if err := asPipe(setupBinary, "server", "install", "--dir", r.opts.Dir); err != nil {
		return err
	}
	if plan.device != "" {
		if err := asPipe(setupBinary, "server", "add", plan.device, "--dir", r.opts.Dir); err != nil {
			return err
		}
	}
	install := r.path(filepath.Join(r.opts.Dir, "install"))
	hop := fileExists(filepath.Join(install, "pipe-hop.service"))
	files := []struct{ name, dir string }{{"pipe.service", setupUnitDir}, {"90-pipe.conf", setupSysctlDir}}
	if hop {
		files = append(files, struct{ name, dir string }{"pipe-hop.service", setupUnitDir})
	}
	for _, f := range files {
		changed, err := r.copyIfChanged(filepath.Join(install, f.name), filepath.Join(r.path(f.dir), f.name))
		if err != nil {
			return err
		}
		if changed {
			r.printf("Wrote %s/%s\n", f.dir, f.name)
		}
	}
	unit, err := os.ReadFile(r.path(filepath.Join(setupUnitDir, "pipe.service")))
	if err != nil {
		return err
	}
	if !strings.Contains(string(unit), "ExecStart="+unitArgument(setupBinary)+" ") {
		return errors.New("pipe.service does not run " + setupBinary)
	}
	for _, argv := range [][]string{
		{"sysctl", "-p", filepath.Join(setupSysctlDir, "90-pipe.conf")},
		{"systemctl", "daemon-reload"},
	} {
		if err := asRoot(argv...); err != nil {
			return err
		}
	}
	if hop {
		if err := asRoot("systemctl", "enable", "--now", "pipe-hop"); err != nil {
			return err
		}
	}
	if err := asRoot("systemctl", "enable", "pipe"); err != nil {
		return err
	}
	return asRoot("systemctl", "restart", "pipe")
}

func (r *setupRun) copyIfChanged(src, dst string) (bool, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return false, err
	}
	if old, err := os.ReadFile(dst); err == nil && bytes.Equal(old, data) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return false, err
	}
	if err := writeAtomic(filepath.Dir(dst), filepath.Base(dst), data, 0644); err != nil {
		return false, err
	}
	return true, r.Chown(dst, 0, 0)
}

func (r *setupRun) finish(plan setupPlan, det SetupDetection) {
	ip := "<this server's public IP>"
	if len(det.PublicIPs) > 0 {
		ip = det.PublicIPs[0].String()
	}
	if plan.realityArgs != nil {
		r.printf("\nStealth moved to your HTTPS proxy site. Device links need the new Stealth name: in each saved link, set rsni=<proxy domain> (or add the device again).\n")
	}
	if plan.noStealth {
		r.printf("\nStealth is not set up: in shared mode it borrows your own HTTPS proxy site. Add proxy_domain (pipe server proxy enable) to get it. Fast and Rescue work without it.\n")
	}
	r.printf("\nNext steps\n")
	n := 1
	step := func(format string, args ...any) {
		r.printf("%d. "+format+"\n", append([]any{n}, args...)...)
		n++
	}
	if _, err := netip.ParseAddr(plan.domain); err != nil && plan.domain != "" {
		step("DNS: create an A record %s -> %s (DNS only).", plan.domain, ip)
	}
	if plan.proxyDomain != "" {
		step("DNS: create an A record %s -> %s (DNS only).", plan.proxyDomain, ip)
	}
	if plan.cdn != "" {
		step("Cloudflare: proxy %s (orange cloud), turn WebSockets on and set SSL to Full (strict).", plan.cdn)
	}
	nginxFile := filepath.Join(r.opts.Dir, "install", "pipe-nginx.conf")
	if fileExists(r.path(nginxFile)) {
		step("nginx: install -m 0600 %s <nginx conf dir>/pipe.conf && nginx -t && nginx -s reload", nginxFile)
		r.printf("   nginx in Docker: copy it into the mounted conf dir, then\n   docker exec <container> nginx -t && docker exec <container> nginx -s reload\n")
	}
	step("Firewall: open the ports listed by install above (also in %s/install/pipe.nft).", r.opts.Dir)
	step("Check: systemctl status pipe; journalctl -u pipe -n 50")
}
