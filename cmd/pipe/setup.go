// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"pipe/internal/server"
)

func runServerSetup(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == server.ApplySetupUpdateCommand {
		if len(args) != 3 {
			return errors.New("invalid setup update")
		}
		return server.ApplySetupUpdate(ctx, args[1], args[2])
	}
	o, template, err := parseSetupOptions(args)
	if err != nil {
		return err
	}
	env, err := server.NewSetupEnv(os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	if template {
		env.Out = os.Stderr
		return printSetupTemplate(env, os.Stdout, o.Dir)
	}
	return server.Setup(ctx, env, o)
}

func parseSetupOptions(args []string) (server.SetupOptions, bool, error) {
	fs := flag.NewFlagSet("pipe server setup", flag.ContinueOnError)
	var flags server.SetupOptions
	var cert server.SetupCertificate
	var proxy server.SetupPort
	var rescue server.SetupRescue
	fs.BoolVar(&flags.Yes, "yes", false, "do not ask questions; use flags and defaults")
	fs.StringVar(&flags.Dir, "dir", "/var/lib/pipe", "server state directory")
	fs.StringVar(&flags.IP, "ip", "", "IP address for device links (default: the SNI name)")
	fs.StringVar(&flags.SNI, "sni", "", "server DNS-only name for Fast, Stealth and the HTTPS proxy")
	fs.StringVar(&cert.DNS, "dns", "", "certificate DNS provider (cloudflare or alidns)")
	fs.StringVar(&cert.TokenFile, "dns-token-file", "", "owner-only Cloudflare API token file")
	fs.StringVar(&cert.KeyFile, "dns-key-file", "", "owner-only AliDNS AccessKey file")
	fs.StringVar(&cert.File, "cert", "", "TLS certificate chain file (readable by user pipe)")
	fs.StringVar(&cert.Key, "key", "", "TLS private key file (readable only by user pipe)")
	registerPortFlag(fs, &flags.Fast.Port, "fast-port", "Fast UDP port (default 443)")
	fs.StringVar(&flags.Fast.Hop, "fast-hop", "", "optional Fast UDP hopping range, for example 20000-40000")
	registerPortFlag(fs, &flags.Stealth.Port, "stealth-port", "Stealth TCP port (default 443 standalone, 8443 shared)")
	registerPortFlag(fs, &proxy.Port, "proxy-port", "HTTPS proxy TCP port (default 443 standalone, 9443 shared)")
	fs.BoolVar(&flags.NoProxy, "no-proxy", false, "disable the HTTPS proxy and shared Stealth")
	fs.StringVar(&rescue.SNI, "rescue-sni", "", "optional Rescue CDN DNS name (empty disables Rescue)")
	registerPortFlag(fs, &rescue.Port, "rescue-port", "Rescue TLS port (default 443 standalone, 2053 shared)")
	fs.StringVar(&rescue.Cert, "rescue-cert", "", "shared Rescue certificate chain file")
	fs.StringVar(&rescue.Key, "rescue-key", "", "shared Rescue owner-only private key file")
	fs.StringVar(&flags.Device, "device", "", "device name to add (default phone on a fresh install)")
	var configPath string
	var template bool
	fs.BoolVar(&template, "template", false, "print the JSON setup template for this host")
	fs.StringVar(&configPath, "config", "", "JSON setup file (implies --yes)")
	if err := parseFlags(fs, args); err != nil {
		return server.SetupOptions{}, false, err
	}
	if fs.NArg() != 0 {
		return server.SetupOptions{}, false, errors.New("server setup takes only flags")
	}
	if template && configPath != "" {
		return server.SetupOptions{}, false, errors.New("--template and --config cannot be used together")
	}
	var o server.SetupOptions
	if configPath != "" {
		var err error
		o, err = server.LoadSetupConfig(configPath)
		if err != nil {
			return o, false, err
		}
	}
	o.Dir, o.Yes, o.NoProxy = flags.Dir, o.Yes || flags.Yes, flags.NoProxy
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for _, f := range []struct {
		name string
		dst  *string
		src  string
	}{
		{"ip", &o.IP, flags.IP}, {"sni", &o.SNI, flags.SNI},
		{"device", &o.Device, flags.Device}, {"fast-hop", &o.Fast.Hop, flags.Fast.Hop},
	} {
		if set[f.name] {
			*f.dst = f.src
		}
	}
	if set["fast-port"] {
		o.Fast.Port = flags.Fast.Port
	}
	if set["stealth-port"] {
		o.Stealth = flags.Stealth
	}
	if o.NoProxy {
		if set["proxy-port"] {
			return o, false, errors.New("--no-proxy cannot be combined with --proxy-port")
		}
		o.Proxy = nil
	} else if set["proxy-port"] || (set["no-proxy"] && o.Proxy == nil) {
		o.Proxy = &proxy
	}
	if set["rescue-sni"] && rescue.SNI == "" {
		o.Rescue, o.ClearRescue = nil, true
	} else if set["rescue-sni"] || set["rescue-port"] || set["rescue-cert"] || set["rescue-key"] {
		if o.Rescue == nil {
			o.Rescue = new(server.SetupRescue)
		}
		if set["rescue-sni"] {
			o.Rescue.SNI = rescue.SNI
		}
		if set["rescue-port"] {
			o.Rescue.Port = rescue.Port
		}
		if set["rescue-cert"] {
			o.Rescue.Cert = rescue.Cert
		}
		if set["rescue-key"] {
			o.Rescue.Key = rescue.Key
		}
	}
	o.Cert = mergeSetupCertificate(o.Cert, cert, set)
	return o, template, nil
}

func mergeSetupCertificate(base *server.SetupCertificate, flags server.SetupCertificate, set map[string]bool) *server.SetupCertificate {
	dns := set["dns"] || set["dns-token-file"] || set["dns-key-file"]
	files := set["cert"] || set["key"]
	if !dns && !files {
		return base
	}
	var cert server.SetupCertificate
	if base != nil {
		cert = *base
	}
	if !dns {
		cert.DNS, cert.TokenFile, cert.KeyFile = "", "", ""
	}
	if !files {
		cert.File, cert.Key = "", ""
	}
	if set["dns"] && cert.DNS != flags.DNS {
		cert.DNS, cert.TokenFile, cert.KeyFile = flags.DNS, "", ""
	}
	for _, f := range []struct {
		name string
		dst  *string
		src  string
	}{
		{"dns-token-file", &cert.TokenFile, flags.TokenFile}, {"dns-key-file", &cert.KeyFile, flags.KeyFile},
		{"cert", &cert.File, flags.File}, {"key", &cert.Key, flags.Key},
	} {
		if set[f.name] {
			*f.dst = f.src
		}
	}
	return &cert
}

// printSetupTemplate writes the template. It does not need root.
func printSetupTemplate(env server.SetupEnv, w io.Writer, dir string) error {
	data, err := server.SetupTemplateFor(env, dir)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
