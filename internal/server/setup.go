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
	"io/fs"
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

	"pipe/internal/link"
	"pipe/internal/localfile"
)

const (
	setupBinary    = "/usr/local/bin/pipe"
	setupStateDir  = "/var/lib/pipe"
	setupUnitDir   = "/etc/systemd/system"
	setupSysctlDir = "/etc/sysctl.d"
)

// SetupCommand is one external command. AsPipe runs it as the pipe user.
type SetupCommand struct {
	Argv   []string
	AsPipe bool

	installFromSetup bool
}

// SetupInterface is one network interface and its addresses.
type SetupInterface struct {
	Name  string
	Addrs []netip.Addr
}

// SetupOptions combines the setup choices with the CLI-only controls.
type SetupOptions struct {
	SetupConfig
	Dir         string
	Yes         bool
	FromConfig  bool // Omitted optional services are off when applying a JSON file.
	NoProxy     bool
	ClearRescue bool
}

// SetupEnv holds every side effect so tests can replace it.
type SetupEnv struct {
	Root           string // prefix for all file paths
	GOOS           string
	EUID           int
	Executable     string
	Run            func(context.Context, SetupCommand) error
	LookupPipeUser func() (uid, gid uint32, found bool, err error)
	Chown          func(path string, uid, gid uint32) error // optional test hook
	Interfaces     func() ([]SetupInterface, error)
	PortProbe      func(port int) (busy, unknown bool) // used by --template only
	Suffix         func() string
	In             io.Reader
	Out            io.Writer

	chownStagedFile func(*os.File, uint32, uint32) error // optional test hook
	probeBinding    func(setupBinding) error
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
		Run: runSetupCommand, LookupPipeUser: lookupPipeUser,
		Interfaces: listSetupInterfaces, PortProbe: setupPortProbe,
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
		if c.installFromSetup {
			cmd.Env = append(cmd.Env, setupInstallEnv+"=1")
		}
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

// SetupDetection is what setup learned about the host.
type SetupDetection struct {
	PublicIPs   []netip.Addr
	Port80Busy  bool
	Port443Busy bool
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
		for _, a := range iface.Addrs {
			if publicAddress(a) {
				d.PublicIPs = append(d.PublicIPs, a)
			}
		}
	}
	return d
}

func (r *setupRun) detect(fresh bool) (SetupDetection, error) {
	ifaces, err := r.Interfaces()
	if err != nil {
		return SetupDetection{}, err
	}
	d := detectInterfaces(ifaces)
	if fresh {
		d.Port80Busy = portInUse(r.probePort(setupBinding{"HTTP", "tcp", 80, false}))
		d.Port443Busy = portInUse(r.probePort(setupBinding{"HTTPS", "tcp", 443, false}))
	}
	return d, nil
}

func (e SetupEnv) path(p string) string { return filepath.Join(e.Root, p) }

type setupRun struct {
	SetupEnv
	opts       SetupOptions
	in         *bufio.Reader
	uid        uint32
	gid        uint32
	state      *os.Root
	cleanup    []string
	portChecks map[setupBinding]error
	ctx        context.Context
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

// Setup turns a fresh server into a running one, or safely upgrades an existing one.
func Setup(ctx context.Context, env SetupEnv, opts SetupOptions) error {
	if env.GOOS != "linux" || env.EUID != 0 {
		return errors.New("run as root: sudo pipe server setup")
	}
	if opts.Dir == "" {
		opts.Dir = setupStateDir
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	r := &setupRun{ctx: ctx, SetupEnv: env, opts: opts, in: bufio.NewReader(env.In)}
	uid, gid, found, err := r.LookupPipeUser()
	if err != nil {
		return err
	}
	if !found {
		uid = ^uint32(0)
	}
	r.uid, r.gid = uid, gid
	r.state, err = openSetupState(r.path(opts.Dir), uid, false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	defer func() {
		if r.state != nil {
			_ = r.state.Close()
		}
	}()
	existing := false
	if r.state != nil {
		_, err := r.state.Lstat(settingsFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		existing = err == nil
	}
	det, err := r.detect(!existing)
	if err != nil {
		return err
	}
	var plan setupPlan
	if existing {
		plan, err = r.planExisting()
	} else {
		plan, err = r.planFresh(det)
	}
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	if err != nil {
		return err
	}
	var saved Settings
	if plan.saved != nil {
		saved = *plan.saved
	}
	proposed, err := plan.update.proposed(saved, func(port uint16) error {
		binding := setupBinding{"Rescue VMess", "tcp", port, true}
		if plan.saved != nil && savedSetupPort(saved, binding) {
			return nil
		}
		return r.probePort(binding)
	})
	if err != nil {
		return err
	}
	plan.update.VMess = proposed.Ports.VMess
	if err := r.checkPorts(proposed, plan.saved); err != nil {
		return err
	}
	if err := r.prepareState(ctx, found); err != nil {
		return err
	}
	if plan.saved != nil {
		if err := r.chownState(); err != nil {
			return err
		}
	}
	if warning := RescuePortWarning(proposed.sharedRescuePort()); warning != "" {
		r.printf("Warning: %s.\n", warning)
	}
	settings, err := r.execute(ctx, plan)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.finish(plan, det, settings)
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
	return r.chown(dest, 0, 0)
}

func (r *setupRun) chown(path string, uid, gid uint32) error {
	if r.Chown != nil {
		return r.Chown(path, uid, gid)
	}
	return os.Lchown(path, int(uid), int(gid))
}

// chownState gives pipe the non-symlink entries under the state directory.
func (r *setupRun) chownState() error {
	return fs.WalkDir(r.state.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if r.Chown != nil {
			return r.Chown(r.path(filepath.Join(r.opts.Dir, filepath.FromSlash(name))), r.uid, r.gid)
		}
		return r.state.Lchown(name, int(r.uid), int(r.gid))
	})
}

func (r *setupRun) prepareState(ctx context.Context, found bool) error {
	if !found {
		nologin := "/usr/sbin/nologin"
		if !fileExists(r.path(nologin)) && fileExists(r.path("/sbin/nologin")) {
			nologin = "/sbin/nologin"
		}
		if err := r.Run(ctx, SetupCommand{Argv: []string{"useradd", "--system", "--home-dir", setupStateDir, "--shell", nologin, "pipe"}}); err != nil {
			return err
		}
		uid, gid, found, err := r.LookupPipeUser()
		if err != nil || !found {
			return errors.New("user pipe was not created")
		}
		r.uid, r.gid = uid, gid
		// Check the parents again with the UID just assigned to Pipe.
		if r.state != nil {
			_ = r.state.Close()
			r.state = nil
		}
	}
	dir := r.path(r.opts.Dir)
	if r.state == nil {
		var err error
		r.state, err = openSetupState(dir, r.uid, true)
		if err != nil {
			return err
		}
	}
	if err := r.state.Chmod(".", 0700); err != nil {
		return err
	}
	if r.Chown != nil {
		return r.Chown(dir, r.uid, r.gid)
	}
	return r.state.Lchown(".", int(r.uid), int(r.gid))
}

func (r *setupRun) printLayout(d SetupDetection) {
	switch {
	case d.Port80Busy && d.Port443Busy:
		r.printf("TCP 80 and 443 are in use, so Pipe uses the shared layout with its own ports.\n")
	case d.Port80Busy:
		r.printf("TCP 80 is in use, so Pipe uses the shared layout with its own ports.\n")
	case d.Port443Busy:
		r.printf("TCP 443 is in use, so Pipe uses the shared layout with its own ports.\n")
	default:
		r.printf("TCP 80 and 443 are free, so Pipe uses the standalone layout and owns those ports.\n")
	}
}

// setupPlan holds the state changes that will be passed to the service user.
type setupPlan struct {
	saved       *Settings
	update      setupUpdate
	fast        SetupFast // authorized inputs for privileged system files
	device      string
	migratedWeb bool
}

func (o SetupOptions) disablesProxy() bool {
	return o.NoProxy || (o.FromConfig && o.Proxy == nil)
}

func (o SetupOptions) checkIdentity() error {
	if (o.FromConfig || o.SNI != "") && !link.ValidDNSName(o.SNI) {
		return errors.New("sni must be the server's DNS-only name")
	}
	if o.IP != "" {
		ip, err := netip.ParseAddr(o.IP)
		if err != nil || ip.Zone() != "" {
			return errors.New("ip must be an IPv4 or IPv6 address")
		}
	}
	if o.Fast.Hop != "" {
		if _, _, err := link.ParseHop(o.Fast.Hop); err != nil {
			return err
		}
	}
	if o.Device != "" && !link.ValidName(o.Device) {
		return errors.New("invalid device name")
	}
	return nil
}

func checkSetupRescueName(sni, name string) error {
	if !link.ValidDNSName(name) {
		return errors.New("rescue.sni must be a DNS name")
	}
	if equalDNS(sni, name) {
		return errors.New("rescue.sni must differ from sni")
	}
	return nil
}

func (r *setupRun) planFresh(det SetupDetection) (setupPlan, error) {
	r.printLayout(det)
	mode := det.suggestedMode()
	o := r.opts
	if !o.Yes {
		var err error
		o, err = r.promptFresh(o, det)
		if err != nil {
			return setupPlan{}, err
		}
	}
	if o.SNI == "" {
		return setupPlan{}, errors.New("setup requires sni (or --sni)")
	}
	if err := o.checkIdentity(); err != nil {
		return setupPlan{}, err
	}
	sni := strings.ToLower(o.SNI)
	if o.Rescue != nil {
		if err := checkSetupRescueName(sni, o.Rescue.SNI); err != nil {
			return setupPlan{}, err
		}
	}
	initial := &setupInitialSettings{Mode: mode, Domain: sni, Hop: o.Fast.Hop, FastPort: o.Fast.Port, StealthPort: o.Stealth.Port}
	if o.IP != "" {
		initial.Domain, initial.FastSNI = netip.MustParseAddr(o.IP).Unmap().String(), sni
	}
	plan := setupPlan{update: setupUpdate{Initial: initial, Rescue: o.Rescue}, device: o.Device, fast: o.Fast}
	if plan.fast.Port == 0 {
		plan.fast.Port = link.DefaultPort
	}
	if plan.device == "" {
		plan.device = "phone"
	}
	if mode == Standalone {
		r.noteStandaloneOverrides(o, link.DefaultPort)
		initial.StealthPort = 0
		plan.update.Proxy = &setupProxyUpdate{Enabled: !o.disablesProxy()}
		return plan, nil
	}
	if !o.disablesProxy() {
		if err := r.planProxy(&plan, o, sni, nil); err != nil {
			return plan, err
		}
	}
	return plan, nil
}

func (r *setupRun) promptFresh(o SetupOptions, det SetupDetection) (SetupOptions, error) {
	if o.SNI == "" {
		o.SNI = r.ask("Server DNS-only name (SNI)", "")
	}
	if o.IP == "" {
		o.IP = r.ask("IP for device links (blank uses the DNS name)", "")
	}
	if o.Fast.Port == 0 {
		port, err := r.askPort("Fast UDP port", 443)
		if err != nil {
			return o, err
		}
		o.Fast.Port = port
	}
	if o.Fast.Hop == "" {
		o.Fast.Hop = r.ask("Fast UDP hopping range (blank for none)", "")
	}
	if o.Proxy == nil && !o.NoProxy {
		o.NoProxy = !r.askYes("Enable the HTTPS proxy?", true)
	}
	if det.suggestedMode() == Shared && !o.NoProxy {
		if o.Stealth.Port == 0 {
			port, err := r.askPort("Stealth TCP port", 8443)
			if err != nil {
				return o, err
			}
			o.Stealth.Port = port
		}
		if o.Proxy == nil {
			port, err := r.askPort("HTTPS proxy TCP port", DefaultProxyPort)
			if err != nil {
				return o, err
			}
			o.Proxy = &SetupPort{Port: port}
		}
		if o.Cert == nil {
			cert, err := r.promptCertificate(det)
			if err != nil {
				return o, err
			}
			o.Cert = cert
		}
	}
	if o.Rescue == nil && !o.ClearRescue {
		if name := r.ask("Rescue Cloudflare name (blank for none)", ""); name != "" {
			o.Rescue = &SetupRescue{SNI: name}
		}
	}
	if o.Rescue != nil && det.suggestedMode() == Shared {
		rescue := *o.Rescue
		if rescue.Port == 0 {
			port, err := r.askPort("Rescue TCP port", DefaultRescuePort)
			if err != nil {
				return o, err
			}
			rescue.Port = port
		}
		if rescue.Cert == "" {
			rescue.Cert = r.ask("Rescue certificate chain file (Cloudflare Origin CA)", "")
		}
		if rescue.Key == "" {
			rescue.Key = r.ask("Rescue private key file", "")
		}
		o.Rescue = &rescue
	}
	if o.Device == "" {
		o.Device = r.ask("First device name", "phone")
	}
	return o, nil
}

func (r *setupRun) askPort(label string, fallback uint16) (uint16, error) {
	raw := r.ask(label, strconv.Itoa(int(fallback)))
	n, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%s must be between 1 and 65535", label)
	}
	return uint16(n), nil
}

func (r *setupRun) promptCertificate(det SetupDetection) (*SetupCertificate, error) {
	fallback := "automatic"
	if det.Port80Busy {
		fallback = proxyDNSCloudflare
	}
	method := strings.ToLower(r.ask("Certificate (automatic, cloudflare, alidns or files)", fallback))
	switch method {
	case "automatic":
		return nil, nil
	case proxyDNSCloudflare:
		return &SetupCertificate{DNS: method, TokenFile: r.ask("Cloudflare API token file", "")}, nil
	case proxyDNSAliDNS:
		return &SetupCertificate{DNS: method, KeyFile: r.ask("AliDNS AccessKey file", "")}, nil
	case "files":
		return &SetupCertificate{File: r.ask("Certificate chain file", ""), Key: r.ask("Private key file", "")}, nil
	default:
		return nil, errors.New("choose automatic, cloudflare, alidns or files for the certificate")
	}
}

func (r *setupRun) noteStandaloneOverrides(o SetupOptions, port uint16) {
	var ignored []string
	if o.Cert != nil {
		ignored = append(ignored, "cert")
	}
	if o.Stealth.Port != 0 && o.Stealth.Port != port {
		ignored = append(ignored, "stealth.port")
	}
	if o.Proxy != nil && o.Proxy.Port != 0 && o.Proxy.Port != port {
		ignored = append(ignored, "proxy.port")
	}
	if o.Rescue != nil {
		if o.Rescue.Port != 0 && o.Rescue.Port != port {
			ignored = append(ignored, "rescue.port")
		}
		if o.Rescue.Cert != "" || o.Rescue.Key != "" {
			ignored = append(ignored, "rescue certificate files")
		}
	}
	if len(ignored) != 0 {
		r.printf("Ignoring %s because the standalone layout uses automatic certificates and shares TCP %d.\n", strings.Join(ignored, ", "), port)
	}
}

func (r *setupRun) planExisting() (setupPlan, error) {
	saved, err := r.readSetupSettings()
	if err != nil {
		return setupPlan{}, err
	}
	o := r.opts
	plan := setupPlan{saved: &saved, update: setupUpdate{Expected: settingsDigest(saved)}, device: o.Device}
	sni := savedSetupSNI(saved)
	r.printf("Keeping the saved %s layout in %s, with its keys and devices.\n", saved.Mode, o.Dir)
	if err := o.checkIdentity(); err != nil {
		return plan, err
	}
	if o.IP != "" {
		current, err := netip.ParseAddr(saved.Domain)
		if err != nil || current.Unmap() != netip.MustParseAddr(o.IP).Unmap() {
			return plan, errors.New("setup cannot change the saved address for device links")
		}
	}
	if o.SNI != "" && !equalDNS(o.SNI, sni) && !equalDNS(o.SNI, saved.fastName()) {
		return plan, errors.New("sni must match the saved Fast or HTTPS proxy name")
	}
	if !equalDNS(sni, saved.fastName()) {
		r.printf("Keeping the saved Fast TLS name %s and HTTPS proxy name %s.\n", saved.fastName(), sni)
	}
	plan.fast, err = r.authorizedSetupFast(o.Fast)
	if err != nil {
		return plan, err
	}
	if err := plan.fast.checkSaved(saved); err != nil {
		return plan, err
	}
	if saved.Mode == Shared && !o.disablesProxy() && o.Stealth.Port != 0 && o.Stealth.Port != saved.stealthPort() {
		return plan, errors.New("setup cannot change the saved Stealth port")
	}
	if !o.Yes && plan.device == "" {
		plan.device = r.ask("Add a device (name, blank to skip)", "")
		if plan.device != "" && !link.ValidName(plan.device) {
			return plan, errors.New("invalid device name")
		}
	}
	switch {
	case o.Rescue != nil:
		cfg := *o.Rescue
		if cfg.SNI == "" && !o.FromConfig {
			cfg.SNI = saved.CDNDomain
		}
		if err := checkSetupRescueName(sni, cfg.SNI); err != nil {
			return plan, err
		}
		if saved.Mode == Shared && cfg.Port == 0 && !o.FromConfig && saved.Rescue != nil {
			cfg.Port = saved.Rescue.Port
		}
		if saved.Mode == Shared || !equalDNS(saved.CDNDomain, cfg.SNI) {
			plan.update.Rescue = &cfg
		}
	case (o.FromConfig || o.ClearRescue) && saved.CDNDomain != "":
		plan.update.Rescue = &SetupRescue{}
	}
	if saved.Mode == Standalone {
		r.noteStandaloneOverrides(o, saved.stealthPort())
		if (o.FromConfig || o.Proxy != nil || o.NoProxy) && saved.proxyEnabled() == o.disablesProxy() {
			plan.update.Proxy = &setupProxyUpdate{Enabled: !o.disablesProxy()}
		}
		return plan, nil
	}
	listener := saved.HTTPSProxyListener
	switch {
	case o.disablesProxy() && listener != nil:
		plan.update.Proxy = &setupProxyUpdate{}
	case !o.disablesProxy() && (o.Proxy != nil || o.Cert != nil):
		if err := r.planProxy(&plan, o, sni, listener); err != nil {
			return plan, err
		}
	}
	retiredRescue := saved.CDNDomain != "" && (saved.RescueListen != "" || saved.Rescue == nil)
	retiredHTTPSProxy := listener != nil && listener.retired()
	plan.migratedWeb = retiredRescue && plan.update.Rescue != nil || retiredHTTPSProxy && plan.update.Proxy != nil
	if (retiredRescue && plan.update.Rescue == nil) || (retiredHTTPSProxy && plan.update.Proxy == nil) {
		if err := r.printRetiredSetup(saved, retiredRescue && plan.update.Rescue == nil, retiredHTTPSProxy && plan.update.Proxy == nil); err != nil {
			return plan, err
		}
	}
	return plan, nil
}

func (r *setupRun) authorizedSetupFast(fast SetupFast) (SetupFast, error) {
	if fast.Hop != "" && fast.Port != 0 {
		return fast, nil
	}
	path := r.path(filepath.Join(setupUnitDir, hopServiceUnit))
	installed, err := readInstalledSetupHop(path, r.uid)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fast, fmt.Errorf("cannot use installed Fast hopping settings: %w. Supply --fast-hop and --fast-port", err)
	}
	if fast.Hop == "" {
		fast.Hop = installed.Hop
	}
	if fast.Port == 0 {
		fast.Port = installed.Port
	}
	if fast.Hop != "" && fast.Port == 0 {
		return fast, errors.New("supply --fast-port with --fast-hop when there is no installed pipe-hop.service")
	}
	return fast, nil
}

func readInstalledSetupHop(path string, pipeUID uint32) (SetupFast, error) {
	f, err := openSetupOperatorFile(path, pipeUID)
	if err != nil {
		return SetupFast{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return SetupFast{}, err
	}
	if uid, ok := setupFileOwner(info); !ok || uid != 0 {
		return SetupFast{}, fmt.Errorf("%s must be owned by root", path)
	}
	data, err := readBoundedSetupFile(f, maxSetupConfigBytes, false)
	if err != nil {
		return SetupFast{}, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		cmd, ok := strings.CutPrefix(strings.TrimSpace(line), "ExecStart=")
		if !ok {
			continue
		}
		executable, args, ok := strings.Cut(cmd, " server hop-apply --fast-hop ")
		binary := strings.Trim(executable, `"`)
		if !ok || filepath.Base(binary) != "pipe" ||
			(executable != unitArgument(binary) && strings.ContainsAny(executable, " \t\"")) {
			break
		}
		fields := strings.Fields(args)
		if len(fields) != 3 || fields[1] != "--fast-port" {
			break
		}
		port, err := strconv.ParseUint(fields[2], 10, 16)
		if err != nil || port == 0 {
			break
		}
		if _, _, err := link.ParseHop(fields[0]); err != nil {
			break
		}
		return SetupFast{Hop: fields[0], Port: uint16(port)}, nil
	}
	return SetupFast{}, fmt.Errorf("%s must specify a Fast hopping range and UDP port", path)
}

func (fast SetupFast) checkSaved(saved Settings) error {
	if fast.Hop != saved.FastHop || fast.Port != 0 && fast.Port != saved.fastPort() {
		return errors.New("saved Fast hopping range or UDP port differs from the authorized setup values. Restore the authorized settings or supply the intended --fast-hop and --fast-port")
	}
	return nil
}

// stage copies a root-readable file into the state dir for the pipe user, removed at the end.
func (r *setupRun) stage(src string, limit int64, ownerOnly bool) (string, error) {
	data, err := readSetupOperatorFile(r.path(src), r.uid, limit, ownerOnly)
	if err != nil {
		return "", err
	}
	defer clear(data)
	name := ".setup-" + r.Suffix()
	rel := filepath.Join(r.opts.Dir, name)
	f, err := r.state.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	r.cleanup = append(r.cleanup, name)
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Chmod(0600); err != nil {
		return "", err
	}
	if r.chownStagedFile != nil {
		err = r.chownStagedFile(f, r.uid, r.gid)
	} else {
		err = f.Chown(int(r.uid), int(r.gid))
	}
	if err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return rel, nil
}

func readSetupFile(path string, limit int64, ownerOnly bool) ([]byte, error) {
	f, err := openSetupFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readBoundedSetupFile(f, limit, ownerOnly)
}

func readSetupOperatorFile(path string, pipeUID uint32, limit int64, ownerOnly bool) ([]byte, error) {
	f, err := openSetupOperatorFile(path, pipeUID)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readBoundedSetupFile(f, limit, ownerOnly)
}

func readBoundedSetupFile(f *os.File, limit int64, ownerOnly bool) ([]byte, error) {
	path := f.Name()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", path)
	}
	if ownerOnly && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s permissions must restrict access to the owner", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		clear(data)
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, nil
}

func (r *setupRun) readSetupJSON(name string, out any) error {
	data, err := readSetupFile(r.path(filepath.Join(r.opts.Dir, name)), localfile.MaxConfigBytes, true)
	if err != nil {
		return err
	}
	defer clear(data)
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("invalid JSON in %s", name)
	}
	return nil
}

func (r *setupRun) readSetupSettings() (Settings, error) {
	var settings Settings
	if err := r.readSetupJSON(settingsFile, &settings); err != nil {
		return settings, err
	}
	if settings.Mode == "" {
		settings.Mode = Standalone
	}
	if err := settings.normalizeDeployment(); err != nil {
		return settings, err
	}
	if !link.ValidWSPath(settings.WSPath) {
		return settings, errors.New("invalid server WebSocket path")
	}
	return settings, nil
}

func (r *setupRun) planProxy(plan *setupPlan, o SetupOptions, name string, saved *httpsProxyListenerConfig) error {
	port := uint16(DefaultProxyPort)
	if saved != nil {
		port = saved.Port
	}
	if o.Proxy != nil && o.Proxy.Port != 0 {
		port = o.Proxy.Port
	}
	if saved != nil && !saved.retired() && o.Cert == nil {
		if port != saved.Port {
			cfg := *saved
			cfg.Port = port
			plan.update.Proxy = &setupProxyUpdate{Enabled: true, Listener: &cfg}
		}
		return nil
	}
	opts, err := setupCertificateOptions(o.Cert)
	if err != nil {
		return err
	}
	opts.Domain, opts.Port = name, port
	if saved != nil {
		opts.WWW = saved.WWW
	}
	if opts.CertMethod == "" {
		http := setupBinding{"HTTPS proxy HTTP-01", "tcp", 80, false}
		if (plan.saved == nil || !savedSetupPort(*plan.saved, http)) && portInUse(r.probePort(http)) {
			return errors.New("TCP 80 is in use. Set cert to DNS credentials or certificate files for the HTTPS proxy")
		}
		opts.CertMethod = "http"
		r.printf("Using HTTP-01 for the HTTPS proxy certificate.\n")
	}
	cfg, dnsFile, err := proxyConfigForEnable(opts)
	if err != nil {
		return err
	}
	if cfg.method() == "files" {
		r.printf("The HTTPS proxy certificate and key files must stay readable by user pipe.\n")
	}
	plan.update.Proxy = &setupProxyUpdate{Enabled: true, Listener: &cfg, DNSFile: dnsFile}
	return nil
}

func setupCertificateOptions(cert *SetupCertificate) (ProxyEnableOptions, error) {
	if cert == nil {
		return ProxyEnableOptions{}, nil
	}
	hasFiles := cert.File != "" || cert.Key != ""
	hasDNS := cert.DNS != "" || cert.TokenFile != "" || cert.KeyFile != ""
	switch {
	case !hasDNS && cert.File != "" && cert.Key != "":
		return ProxyEnableOptions{CertMethod: "files", CertFile: cert.File, KeyFile: cert.Key}, nil
	case !hasFiles && cert.DNS == proxyDNSCloudflare && cert.TokenFile != "" && cert.KeyFile == "":
		return ProxyEnableOptions{CertMethod: "dns", DNS: cert.DNS, DNSTokenFile: cert.TokenFile}, nil
	case !hasFiles && cert.DNS == proxyDNSAliDNS && cert.KeyFile != "" && cert.TokenFile == "":
		return ProxyEnableOptions{CertMethod: "dns", DNS: cert.DNS, DNSKeyFile: cert.KeyFile}, nil
	default:
		return ProxyEnableOptions{}, errors.New("cert requires cloudflare with token_file, alidns with key_file, or file and key")
	}
}

func (r *setupRun) applyUpdate(plan setupPlan) error {
	update := plan.update
	if plan.saved != nil && update.Proxy == nil && update.Rescue == nil && update.VMess == plan.saved.Ports.VMess {
		return nil
	}
	// Stage all privileged inputs before the child can touch the active state.
	defer func() {
		for _, name := range r.cleanup {
			_ = r.state.Remove(name)
		}
	}()
	if rescue := update.Rescue; rescue != nil && rescue.SNI != "" && rescue.Cert != "" &&
		(update.Initial != nil && update.Initial.Mode == Shared || plan.saved != nil && plan.saved.Mode == Shared) {
		staged := *rescue
		var err error
		if staged.Cert, err = r.stage(rescue.Cert, localfile.MaxConfigBytes, false); err != nil {
			return err
		}
		if staged.Key, err = r.stage(rescue.Key, localfile.MaxConfigBytes, true); err != nil {
			return err
		}
		update.Rescue = &staged
	}
	if proxy := update.Proxy; proxy != nil && proxy.DNSFile != "" {
		staged := *proxy
		var err error
		if staged.DNSFile, err = r.stage(proxy.DNSFile, 4096, true); err != nil {
			return err
		}
		update.Proxy = &staged
	}
	data, err := json.Marshal(update)
	if err != nil {
		return err
	}
	return r.Run(r.ctx, SetupCommand{
		Argv:   []string{setupBinary, "server", "setup", ApplySetupUpdateCommand, r.opts.Dir, string(data)},
		AsPipe: true,
	})
}

func (r *setupRun) execute(ctx context.Context, plan setupPlan) (Settings, error) {
	asPipe := func(argv ...string) error {
		return r.Run(ctx, SetupCommand{Argv: argv, AsPipe: true})
	}
	asRoot := func(argv ...string) error {
		return r.Run(ctx, SetupCommand{Argv: argv})
	}
	// The new binary can read either settings format, including if setup
	// is interrupted immediately after the child commits.
	if err := r.installBinary(); err != nil {
		return Settings{}, err
	}
	if err := r.applyUpdate(plan); err != nil {
		return Settings{}, err
	}
	settings, err := r.readSetupSettings()
	if err != nil {
		return Settings{}, err
	}
	if err := plan.fast.checkSaved(settings); err != nil {
		return Settings{}, err
	}
	if change := plan.update.Proxy; change != nil && change.Listener != nil {
		r.printf("HTTPS proxy enabled for %s. Open TCP %d in the firewall.\n", change.Listener.Domain, change.Listener.Port)
	}
	if err := r.Run(ctx, SetupCommand{
		Argv: []string{setupBinary, "server", "install", "--dir", r.opts.Dir}, AsPipe: true, installFromSetup: true,
	}); err != nil {
		return Settings{}, err
	}
	if plan.device != "" {
		var devices []Device
		if err := r.readSetupJSON(devicesFile, &devices); err != nil {
			return Settings{}, err
		}
		if deviceIndex(devices, plan.device) >= 0 {
			if plan.saved != nil && existingEndpointsChanged(*plan.saved, settings) {
				r.printf("Device %q is already enrolled. Its credentials are kept. Update the endpoints in its link as shown below.\n", plan.device)
			} else {
				r.printf("Device %q is already enrolled. Its existing link stays valid.\n", plan.device)
			}
		} else if err := asPipe(setupBinary, "server", "add", plan.device, "--dir", r.opts.Dir); err != nil {
			return Settings{}, err
		}
	}
	state, err := filepath.Abs(r.opts.Dir)
	if err != nil {
		return Settings{}, err
	}
	for _, f := range systemInstallFiles(state, setupBinary, plan.fast) {
		dir := setupUnitDir
		if f.name == "90-pipe.conf" {
			dir = setupSysctlDir
		}
		changed, err := r.installIfChanged(filepath.Join(r.path(dir), f.name), f)
		if err != nil {
			return Settings{}, err
		}
		if changed {
			r.printf("Wrote %s/%s\n", dir, f.name)
		}
	}
	for _, argv := range [][]string{
		{"sysctl", "-p", filepath.Join(setupSysctlDir, "90-pipe.conf")},
		{"systemctl", "daemon-reload"},
	} {
		if err := asRoot(argv...); err != nil {
			return Settings{}, err
		}
	}
	if plan.fast.Hop != "" {
		if err := asRoot("systemctl", "enable", "pipe-hop"); err != nil {
			return Settings{}, err
		}
		if err := asRoot("systemctl", "restart", "pipe-hop"); err != nil {
			return Settings{}, err
		}
	}
	if err := asRoot("systemctl", "enable", "pipe"); err != nil {
		return Settings{}, err
	}
	return settings, asRoot("systemctl", "restart", "pipe")
}

func (r *setupRun) installIfChanged(dst string, file installFile) (bool, error) {
	data := []byte(file.contents)
	if installedSetupFileMatches(dst, data) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return false, err
	}
	if err := writeAtomic(filepath.Dir(dst), filepath.Base(dst), data, file.mode); err != nil {
		return false, err
	}
	return true, r.chown(dst, 0, 0)
}

func installedSetupFileMatches(path string, data []byte) bool {
	f, err := openSetupFile(path)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return false
	}
	if uid, ok := setupFileOwner(info); !ok || uid != 0 {
		return false
	}
	old, err := readBoundedSetupFile(f, int64(len(data)), false)
	return err == nil && bytes.Equal(old, data)
}

func existingEndpointsChanged(old, next Settings) bool {
	oldAuthority := old.proxyAuthority()
	if old.HTTPSProxyListener != nil && old.HTTPSProxyListener.retired() && next.proxyAuthority() != "" {
		oldAuthority = addrPort(old.HTTPSProxyListener.Domain, old.HTTPSProxyListener.Port)
	}
	return old.CDNDomain != "" && (old.rescuePort() != next.rescuePort() || !equalDNS(old.CDNDomain, next.CDNDomain)) ||
		oldAuthority != "" && oldAuthority != next.proxyAuthority() || !equalDNS(old.stealthName(), next.stealthName())
}

func (r *setupRun) finish(plan setupPlan, det SetupDetection, settings Settings) {
	ip := "<this server's public IP>"
	if len(det.PublicIPs) > 0 {
		ip = det.PublicIPs[0].String()
	}
	if address, err := netip.ParseAddr(settings.Domain); err == nil {
		ip = address.String()
	}
	if problem := settings.realityTargetProblem(); problem != nil {
		if settings.HTTPSProxyListener == nil {
			r.printf("\nStealth is off in the shared layout. Add a proxy section so Stealth can use the HTTPS proxy site.\n")
		} else {
			r.printf("\nStealth is off. %s\n", problem)
		}
	}
	r.printf("\nNext steps\n")
	n := 1
	step := func(format string, args ...any) {
		r.printf("%d. "+format+"\n", append([]any{n}, args...)...)
		n++
	}
	if name := settings.fastName(); name != "" {
		step("Point the DNS-only name %s to %s.", name, ip)
	}
	if name, _ := settings.proxyEndpoint(); name != "" && !equalDNS(name, settings.fastName()) {
		step("Point the DNS-only name %s to %s.", name, ip)
	}
	rescuePort := settings.rescuePort()
	if rescuePort != 0 {
		step("Cloudflare: proxy %s (orange cloud), turn WebSockets on and set SSL to Full (strict).", settings.CDNDomain)
	}
	if settings.Mode == Shared && rescuePort != 0 {
		step("Open Rescue TCP %d in the firewall. Only Cloudflare needs it.", rescuePort)
	}
	if plan.migratedWeb {
		step("Remove Pipe's old configuration file from the website's nginx and reload the website.")
	}
	setLink := func(field, value string) {
		step("In each device link, set %s=%s (replace it if present, otherwise add it).", field, value)
	}
	if plan.saved != nil && plan.update.Rescue != nil {
		previous := *plan.saved
		switch {
		case rescuePort == 0 && previous.CDNDomain != "":
			step("Remove cdn and wsp from saved Rescue links.")
		case rescuePort != 0 && (previous.rescuePort() != rescuePort ||
			!equalDNS(previous.CDNDomain, settings.CDNDomain) || previous.WSPath != settings.WSPath):
			setLink("cdn", (link.Profile{CDN: settings.CDNDomain, CDNPort: rescuePort}).CDNEndpoint())
			setLink("wsp", settings.WSPath)
		}
	}
	if plan.saved != nil && plan.update.Proxy != nil {
		if name := settings.stealthName(); !equalDNS(plan.saved.stealthName(), name) {
			setLink("rsni", name)
		}
		_, oldPort := plan.saved.proxyEndpoint()
		if old := plan.saved.HTTPSProxyListener; old != nil && old.retired() {
			oldPort = old.Port // Pre-upgrade links and shell exports used this port.
		}
		authority := settings.proxyAuthority()
		switch {
		case authority != "" && authority != plan.saved.proxyAuthority():
			setLink("hp", authority)
			if _, port := settings.proxyEndpoint(); oldPort != 0 && oldPort != port {
				step("Use %s in existing export https_proxy and http_proxy lines.", authority)
			}
			step("Run pipe server proxy export <name> with the same --dir for a fresh export.")
		case authority == "" && oldPort != 0:
			step("Remove hp from saved links and clear the HTTPS proxy export lines.")
		}
	}
	step("Firewall: open the ports listed by install above.")
	step("Check: systemctl status pipe; journalctl -u pipe -n 50")
}
