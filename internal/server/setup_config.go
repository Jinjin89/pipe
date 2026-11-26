// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"pipe/internal/localfile"
	"pipe/templates"
)

const maxSetupConfigBytes = 64 << 10

// SetupConfig is the operator's setup JSON. Certificate values are file paths.
type SetupConfig struct {
	IP      string            `json:"ip,omitempty"`
	SNI     string            `json:"sni"`
	Cert    *SetupCertificate `json:"cert,omitempty"`
	Fast    SetupFast         `json:"fast,omitzero"`
	Stealth SetupPort         `json:"stealth,omitzero"`
	Proxy   *SetupPort        `json:"proxy,omitempty"`
	Rescue  *SetupRescue      `json:"rescue,omitempty"`
	Device  string            `json:"device,omitempty"`
}

type SetupCertificate struct {
	DNS       string `json:"dns,omitempty"`
	TokenFile string `json:"token_file,omitempty"`
	KeyFile   string `json:"key_file,omitempty"`
	File      string `json:"file,omitempty"`
	Key       string `json:"key,omitempty"`
}

type SetupFast struct {
	Port uint16 `json:"port,omitempty"`
	Hop  string `json:"hop,omitempty"`
}

type SetupPort struct {
	Port uint16 `json:"port,omitempty"`
}

type SetupRescue struct {
	SNI  string `json:"sni"`
	Port uint16 `json:"port,omitempty"`
	Cert string `json:"cert,omitempty"`
	Key  string `json:"key,omitempty"`
}

// LoadSetupConfig reads the JSON before flag overrides. Paths in the file are
// relative to the file's directory. A config file implies noninteractive setup.
func LoadSetupConfig(path string) (SetupOptions, error) {
	data, err := readSetupConfigInput(path)
	if err != nil {
		return SetupOptions{}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return SetupOptions{}, fmt.Errorf("setup config %s: %w", path, err)
	}
	if raw == nil {
		return SetupOptions{}, fmt.Errorf("setup config %s must contain a JSON object", path)
	}
	for key, value := range raw {
		switch strings.ToLower(key) {
		case "mode", "domain", "fast_sni", "cdn_domain", "proxy_domain", "proxy_cert_method",
			"rescue_listen", "acme_listen", "reality_dest", "dir", "fast_port", "fast_hop",
			"stealth_port", "proxy_port", "rescue_port", "rescue_cert", "rescue_key", "dns",
			"dns_key_file", "dns_token_file", "key":
			return SetupOptions{}, oldSetupFormat(path)
		case "cert":
			if bytes.HasPrefix(bytes.TrimSpace(value), []byte(`"`)) {
				return SetupOptions{}, oldSetupFormat(path)
			}
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg SetupConfig
	if err := dec.Decode(&cfg); err != nil {
		return SetupOptions{}, fmt.Errorf("setup config %s: %w", path, err)
	}
	resolve := func(name string) string {
		if name == "" || filepath.IsAbs(name) {
			return name
		}
		return filepath.Join(filepath.Dir(path), name)
	}
	if c := cfg.Cert; c != nil {
		c.File, c.Key = resolve(c.File), resolve(c.Key)
		c.TokenFile, c.KeyFile = resolve(c.TokenFile), resolve(c.KeyFile)
	}
	if r := cfg.Rescue; r != nil {
		r.Cert, r.Key = resolve(r.Cert), resolve(r.Key)
	}
	return SetupOptions{SetupConfig: cfg, FromConfig: true, Yes: true}, nil
}

func readSetupConfigInput(path string) ([]byte, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return localfile.Read(path, maxSetupConfigBytes, false)
	}
	uid, _, found, err := lookupPipeUser()
	if err != nil {
		return nil, err
	}
	if !found {
		uid = ^uint32(0)
	}
	return readSetupOperatorFile(path, uid, maxSetupConfigBytes, false)
}

func oldSetupFormat(path string) error {
	return fmt.Errorf("%s: this is the old setup format; run `pipe server setup --template > setup.json`", path)
}

// SetupTemplateFor renders the single embedded template using the host's IP
// and ports. When probing is inconclusive, show the dedicated-port example.
// Migration notes go to env.Out when it is set.
func SetupTemplateFor(env SetupEnv, dir string) ([]byte, error) {
	if dir == "" {
		dir = setupStateDir
	}
	var cfg SetupConfig
	if err := json.Unmarshal(templates.Setup, &cfg); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(env.path(filepath.Join(dir, settingsFile))); err == nil {
		r := setupRun{SetupEnv: env, opts: SetupOptions{Dir: dir}}
		saved, err := r.readSetupSettings()
		if err != nil {
			return nil, err
		}
		return renderSetupConfig(env.savedSetupConfig(saved, cfg))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var d SetupDetection
	if env.Interfaces != nil {
		ifaces, err := env.Interfaces()
		if err != nil {
			return nil, err
		}
		d = detectInterfaces(ifaces)
	}
	if env.PortProbe == nil {
		d.PortsUnknown = true
	} else {
		var unknown80, unknown443 bool
		d.Port80Busy, unknown80 = env.PortProbe(80)
		d.Port443Busy, unknown443 = env.PortProbe(443)
		d.PortsUnknown = unknown80 || unknown443
	}
	cfg.IP = ""
	if len(d.PublicIPs) != 0 {
		cfg.IP = d.PublicIPs[0].String()
	}
	if d.suggestedMode() == Standalone && !d.PortsUnknown {
		cfg.Stealth.Port, cfg.Proxy.Port, cfg.Rescue.Port = 443, 443, 443
		cfg.Cert = nil
		cfg.Rescue.Cert, cfg.Rescue.Key = "", ""
	} else if !d.Port80Busy && !d.PortsUnknown {
		cfg.Cert = nil // HTTP-01 is available even when TCP 443 is occupied.
	}
	return renderSetupConfig(cfg)
}

func renderSetupConfig(cfg SetupConfig) ([]byte, error) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func savedSetupSNI(s Settings) string {
	if cfg := s.HTTPSProxyListener; cfg != nil {
		return cfg.Domain
	}
	if s.LastProxyDomain != "" {
		return s.LastProxyDomain
	}
	if s.RealityDest == realitySelf && s.RealitySNI != "" {
		return s.RealitySNI
	}
	return s.fastName()
}

func (env SetupEnv) savedSetupConfig(s Settings, example SetupConfig) SetupConfig {
	cfg := SetupConfig{SNI: savedSetupSNI(s), Fast: env.savedSetupFast(s),
		Stealth: SetupPort{Port: s.stealthPort()}}
	if ip, err := netip.ParseAddr(s.Domain); err == nil {
		cfg.IP = ip.String()
	}
	if proxy := s.HTTPSProxyListener; proxy != nil {
		cfg.Proxy = &SetupPort{Port: proxy.Port}
		if proxy.retired() {
			cfg.Cert = example.Cert
		}
	} else if s.proxyEnabled() {
		cfg.Proxy = &SetupPort{Port: s.stealthPort()}
	}
	if s.CDNDomain != "" {
		cfg.Rescue = &SetupRescue{SNI: s.CDNDomain, Port: s.rescuePort()}
		if s.Mode == Shared && cfg.Rescue.Port == 0 {
			cfg.Rescue.Port, cfg.Rescue.Cert, cfg.Rescue.Key = DefaultRescuePort, example.Rescue.Cert, example.Rescue.Key
		}
	}
	return cfg
}

func (env SetupEnv) savedSetupFast(saved Settings) SetupFast {
	// A Fast port by itself can become a hopping target when setup reads the
	// range from an installed unit. Only emit an authorized pair.
	if saved.FastHop == "" {
		return SetupFast{}
	}
	lookup := env.LookupPipeUser
	if lookup == nil {
		lookup = lookupPipeUser
	}
	uid, _, found, err := lookup()
	if err == nil {
		if !found {
			uid = ^uint32(0)
		}
		path := env.path(filepath.Join(setupUnitDir, hopServiceUnit))
		if fast, err := readInstalledSetupHop(path, uid); err == nil && fast.checkSaved(saved) == nil {
			return fast
		}
	}
	if env.Out != nil {
		fmt.Fprintln(env.Out, "Fast hopping needs operator confirmation. Add the intended fast.hop and fast.port to the JSON or pass --fast-hop and --fast-port.")
	}
	return SetupFast{}
}

func (r *setupRun) printRetiredSetup(saved Settings, rescue, proxy bool) error {
	if rescue {
		r.printf("Rescue will be off after restart. Replace its retired listener with a rescue section containing the certificate and key.\n")
	}
	if proxy {
		r.printf("The HTTPS proxy will be off after restart. Stealth will also be off until the proxy uses a supported certificate method. Replace the retired method with cert and proxy sections.\n")
	}
	var example SetupConfig
	if err := json.Unmarshal(templates.Setup, &example); err != nil {
		return err
	}
	data, err := renderSetupConfig(r.savedSetupConfig(saved, example))
	if err != nil {
		return err
	}
	r.printf("Fill in the credential paths in this setup file, then run pipe server setup --config setup.json with the same --dir.\n%s", data)
	return nil
}

// setupPortProbe reports whether a TCP port is in use, including a loopback
// probe when a non-root template command lacks permission to bind it.
func setupPortProbe(port int) (busy, unknown bool) {
	for _, e := range []struct{ network, host string }{{"tcp4", "0.0.0.0"}, {"tcp6", "::"}} {
		l, err := net.Listen(e.network, net.JoinHostPort(e.host, strconv.Itoa(port)))
		switch {
		case err == nil:
			_ = l.Close()
		case portInUse(err):
			return true, false
		case errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM):
			unknown = true
		}
	}
	if unknown {
		for _, host := range []string{"127.0.0.1", "::1"} {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 200*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return true, false
			}
		}
	}
	return false, unknown
}
