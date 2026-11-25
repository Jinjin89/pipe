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
	fs := flag.NewFlagSet("pipe server setup", flag.ContinueOnError)
	var o server.SetupOptions
	fs.BoolVar(&o.Yes, "yes", false, "do not ask questions; use flags and defaults")
	fs.StringVar(&o.Dir, "dir", "/var/lib/pipe", "server state directory")
	fs.StringVar(&o.Mode, "mode", "", "standalone or shared (default: detected)")
	fs.StringVar(&o.Domain, "domain", "", "server DNS name (shared mode: or public IP)")
	fs.StringVar(&o.FastSNI, "fast-sni", "", "Fast TLS DNS name (required for an IP address)")
	fs.StringVar(&o.CDNDomain, "cdn-domain", "", "optional CDN DNS name for Rescue")
	fs.StringVar(&o.RescueListen, "rescue-listen", "", "shared Rescue listener, private IP:port")
	fs.StringVar(&o.RealityDest, "reality-dest", "", "only \"self\" (the default): Stealth borrows your HTTPS proxy site, so it needs proxy-domain")
	fs.StringVar(&o.FastHop, "fast-hop", "", "Fast UDP hopping range, for example 20000-40000")
	fs.StringVar(&o.ProxyDomain, "proxy-domain", "", "shared mode: DNS-only HTTPS proxy hostname")
	fs.StringVar(&o.ProxyCertMethod, "proxy-cert-method", "", "auto, http, nginx, dns or files")
	fs.StringVar(&o.ACMEListen, "acme-listen", "", "private IP:port for the nginx ACME method")
	fs.StringVar(&o.DNS, "dns", "", "ACME DNS-01 provider (cloudflare or alidns)")
	fs.StringVar(&o.DNSKeyFile, "dns-key-file", "", "AliDNS AccessKey file")
	fs.StringVar(&o.DNSTokenFile, "dns-token-file", "", "Cloudflare API token file")
	fs.StringVar(&o.Cert, "cert", "", "TLS certificate chain file (must stay readable by user pipe)")
	fs.StringVar(&o.Key, "key", "", "TLS private key file (must stay readable by user pipe)")
	fs.StringVar(&o.Device, "device", "", "device name to add (default phone on a fresh install)")
	var configPath string
	var template bool
	fs.BoolVar(&template, "template", false, "print a commented JSON setup file to stdout and exit (--mode picks the layout)")
	fs.StringVar(&configPath, "config", "", "JSON file with setup options (implies --yes)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("server setup takes only flags")
	}
	if template {
		if configPath != "" {
			return errors.New("--template and --config cannot be used together")
		}
		env, err := server.NewSetupEnv(os.Stdin, os.Stdout)
		if err != nil {
			return err
		}
		return printSetupTemplate(env, os.Stdout, server.DeployMode(o.Mode))
	}
	if configPath != "" {
		cfg, err := server.LoadSetupConfig(configPath)
		if err != nil {
			return err
		}
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		o = mergeSetupConfig(cfg, o, set)
	}
	env, err := server.NewSetupEnv(os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	return server.Setup(ctx, env, o)
}

// mergeSetupConfig applies the JSON values, then lets flags that were set
// explicitly override them. A config implies --yes.
func mergeSetupConfig(cfg, flags server.SetupOptions, set map[string]bool) server.SetupOptions {
	out := cfg
	out.Yes = true
	if out.Dir == "" {
		out.Dir = flags.Dir
	}
	fields := []struct {
		name string
		dst  *string
		src  string
	}{
		{"dir", &out.Dir, flags.Dir},
		{"mode", &out.Mode, flags.Mode},
		{"domain", &out.Domain, flags.Domain},
		{"fast-sni", &out.FastSNI, flags.FastSNI},
		{"cdn-domain", &out.CDNDomain, flags.CDNDomain},
		{"rescue-listen", &out.RescueListen, flags.RescueListen},
		{"reality-dest", &out.RealityDest, flags.RealityDest},
		{"fast-hop", &out.FastHop, flags.FastHop},
		{"proxy-domain", &out.ProxyDomain, flags.ProxyDomain},
		{"proxy-cert-method", &out.ProxyCertMethod, flags.ProxyCertMethod},
		{"acme-listen", &out.ACMEListen, flags.ACMEListen},
		{"dns", &out.DNS, flags.DNS},
		{"dns-key-file", &out.DNSKeyFile, flags.DNSKeyFile},
		{"dns-token-file", &out.DNSTokenFile, flags.DNSTokenFile},
		{"cert", &out.Cert, flags.Cert},
		{"key", &out.Key, flags.Key},
		{"device", &out.Device, flags.Device},
	}
	for _, f := range fields {
		if set[f.name] {
			*f.dst = f.src
		}
	}
	return out
}

// printSetupTemplate writes the template. It does not need root.
func printSetupTemplate(env server.SetupEnv, w io.Writer, layout server.DeployMode) error {
	data, err := server.SetupTemplateFor(env, layout)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
