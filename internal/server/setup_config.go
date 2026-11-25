// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"pipe/internal/localfile"
)

const maxSetupConfigBytes = 64 << 10

// setupConfigFile is the JSON form of SetupOptions. It holds file paths only,
// never secrets, and unknown keys are rejected.
type setupConfigFile struct {
	Mode            string `json:"mode"`
	Domain          string `json:"domain"`
	FastSNI         string `json:"fast_sni"`
	CDNDomain       string `json:"cdn_domain"`
	RescueListen    string `json:"rescue_listen"`
	RealityDest     string `json:"reality_dest"`
	FastHop         string `json:"fast_hop"`
	ProxyDomain     string `json:"proxy_domain"`
	ProxyCertMethod string `json:"proxy_cert_method"`
	ACMEListen      string `json:"acme_listen"`
	DNS             string `json:"dns"`
	DNSKeyFile      string `json:"dns_key_file"`
	DNSTokenFile    string `json:"dns_token_file"`
	Cert            string `json:"cert"`
	Key             string `json:"key"`
	Device          string `json:"device"`
	Dir             string `json:"dir"`
}

// LoadSetupConfig reads a JSON setup file. Relative file paths are resolved
// against the directory of the JSON file. Empty values mean not set.
func LoadSetupConfig(path string) (SetupOptions, error) {
	data, err := localfile.Read(path, maxSetupConfigBytes, false)
	if err != nil {
		return SetupOptions{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return SetupOptions{}, fmt.Errorf("setup config %s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return SetupOptions{}, fmt.Errorf("setup config %s: unexpected data after the JSON object", path)
	}
	// Keys that start with "_" are notes and are ignored, whatever their value.
	for k := range raw {
		if strings.HasPrefix(k, "_") {
			delete(raw, k)
		}
	}
	filtered, err := json.Marshal(raw)
	if err != nil {
		return SetupOptions{}, err
	}
	strict := json.NewDecoder(bytes.NewReader(filtered))
	strict.DisallowUnknownFields()
	var c setupConfigFile
	if err := strict.Decode(&c); err != nil {
		return SetupOptions{}, fmt.Errorf("setup config %s: %w", path, err)
	}
	opts := SetupOptions{
		Dir:             c.Dir,
		Mode:            c.Mode,
		Domain:          c.Domain,
		FastSNI:         c.FastSNI,
		CDNDomain:       c.CDNDomain,
		RescueListen:    c.RescueListen,
		RealityDest:     c.RealityDest,
		FastHop:         c.FastHop,
		ProxyDomain:     c.ProxyDomain,
		ProxyCertMethod: c.ProxyCertMethod,
		ACMEListen:      c.ACMEListen,
		DNS:             c.DNS,
		DNSKeyFile:      c.DNSKeyFile,
		DNSTokenFile:    c.DNSTokenFile,
		Cert:            c.Cert,
		Key:             c.Key,
		Device:          c.Device,
	}
	clearUnusedSetupFields(&opts)
	base := filepath.Dir(path)
	rel := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	opts.DNSKeyFile = rel(opts.DNSKeyFile)
	opts.DNSTokenFile = rel(opts.DNSTokenFile)
	opts.Cert = rel(opts.Cert)
	opts.Key = rel(opts.Key)
	return opts, nil
}

// clearUnusedSetupFields drops values that do not apply, so suggested
// placeholders in a template are harmless.
func clearUnusedSetupFields(o *SetupOptions) {
	if o.Mode == string(Standalone) {
		o.FastSNI, o.RescueListen, o.RealityDest = "", "", ""
		o.ProxyDomain = ""
	}
	if o.ProxyDomain == "" {
		o.ProxyCertMethod, o.ACMEListen, o.DNS, o.DNSKeyFile, o.DNSTokenFile, o.Cert, o.Key = "", "", "", "", "", "", ""
		return
	}
	method := o.ProxyCertMethod
	if method != "files" {
		o.Cert, o.Key = "", ""
	}
	if method != "dns" {
		o.DNS = ""
	}
	if method != "dns" || o.DNS != "alidns" {
		o.DNSKeyFile = ""
	}
	if method != "dns" || o.DNS != "cloudflare" {
		o.DNSTokenFile = ""
	}
	if method != "auto" && method != "nginx" {
		o.ACMEListen = ""
	}
}

// SetupTemplate renders a plain JSON setup file for the layout with suggested
// values. Placeholders that do not apply are ignored by LoadSetupConfig.
func SetupTemplate(layout DeployMode, det SetupDetection) []byte {
	type kv struct{ k, v string }
	fields := []kv{{"mode", string(layout)}}
	if layout == Shared {
		domain, rescue := "203.0.113.7", "172.17.0.1:18080"
		if len(det.PublicIPs) > 0 {
			domain = det.PublicIPs[0].String()
		}
		// User-defined br-* networks come before docker0.
		if len(det.NetworkBridges) > 0 {
			rescue = det.NetworkBridges[0].String() + ":18080"
		} else if len(det.Bridges) > 0 {
			rescue = det.Bridges[0].String() + ":18080"
		}
		fields = append(fields, []kv{
			{"domain", domain},
			{"fast_sni", "proxy.example.org"},
			{"cdn_domain", "static.example.com"},
			{"rescue_listen", rescue},
			{"reality_dest", "self"},
			{"fast_hop", "20000-40000"},
			{"proxy_domain", "proxy.example.org"},
			{"proxy_cert_method", "auto"},
			{"dns", "alidns"},
			{"dns_key_file", "/path/to/alidns.key"},
			{"dns_token_file", "/path/to/cloudflare.token"},
			{"cert", "/path/to/fullchain.pem"},
			{"key", "/path/to/privkey.pem"},
			{"device", "phone"},
		}...)
	} else {
		fields = append(fields, []kv{
			{"domain", "vpn.example.com"},
			{"cdn_domain", "static.example.com"},
			{"fast_hop", "20000-40000"},
			{"device", "phone"},
		}...)
	}
	str := func(v string) []byte {
		var vb bytes.Buffer
		enc := json.NewEncoder(&vb)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(v)
		return bytes.TrimSpace(vb.Bytes())
	}
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, f := range fields {
		sep := ","
		if i == len(fields)-1 {
			sep = ""
		}
		fmt.Fprintf(&b, "  %s: %s%s\n", str(f.k), str(f.v), sep)
	}
	b.WriteString("}\n")
	return b.Bytes()
}

// SetupTemplateFor detects the host and renders a template. It changes
// nothing and needs no root. An empty or auto layout uses the suggestion.
func SetupTemplateFor(env SetupEnv, layout DeployMode) ([]byte, error) {
	var d SetupDetection
	if env.Interfaces != nil {
		ifaces, err := env.Interfaces()
		if err != nil {
			return nil, err
		}
		d = detectInterfaces(ifaces)
	}
	if env.PortProbe != nil {
		for _, port := range []int{80, 443} {
			busy, unknown := env.PortProbe(port)
			d.PortsUnknown = d.PortsUnknown || unknown
			if port == 80 {
				d.Port80Busy = busy
			} else {
				d.Port443Busy = busy
			}
		}
	} else {
		d.PortsUnknown = true
	}
	switch layout {
	case "", Auto:
		layout = d.suggestedMode()
	case Standalone, Shared:
	default:
		return nil, errors.New("--mode must be standalone or shared")
	}
	return SetupTemplate(layout, d), nil
}

// setupPortProbe reports whether a TCP port is in use. Missing permission
// to bind makes the answer unknown.
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
	return false, unknown
}
