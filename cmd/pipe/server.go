// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pipe/internal/link"
	"pipe/internal/server"

	"golang.org/x/term"
	"rsc.io/qr"
)

func runServer(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(os.Stderr, "Usage: pipe server <setup | init | add | revoke | list | run | install | uninstall | proxy | rescue | reality | hop-apply | relay-command> [options]")
		return nil
	}
	command := args[0]
	switch command {
	case "setup":
		return runServerSetup(ctx, args[1:])
	case "proxy":
		return runServerProxy(ctx, args[1:])
	case "hop-apply":
		return runServerHopApply(ctx, args[1:])
	}
	fs := flag.NewFlagSet("pipe server "+command, flag.ContinueOnError)
	var options server.RunOptions
	var initOptions server.InitOptions
	var domain, cdn, deployMode string
	var uninstallOptions server.UninstallOptions
	fs.StringVar(&options.Dir, "dir", "", "server state directory (or PIPE_SERVER_DIR)")
	switch command {
	case "init":
		fs.StringVar(&domain, "domain", "", "DNS-only direct hostname")
		fs.StringVar(&cdn, "cdn-domain", "", "optional CDN DNS name")
		fs.StringVar(&deployMode, "mode", "auto", "auto, standalone or shared")
		fs.StringVar(&initOptions.FastSNI, "fast-sni", "", "Fast TLS DNS name (defaults to the proxy domain in shared mode when set)")
		fs.StringVar(&initOptions.ProxyDomain, "proxy-domain", "", "shared HTTPS proxy hostname to use as the default Fast TLS name")
		fs.StringVar(&initOptions.FastHop, "fast-hop", "", "Fast UDP hopping range")
		fs.StringVar(&initOptions.RealityDest, "reality-dest", "", "retired setting that accepts only self")
		registerRescueFlags(fs, &initOptions.Rescue)
		fs.BoolVar(&initOptions.NoHTTPSProxy, "no-https-proxy", false, "disable standalone HTTPS forward proxy")
		registerPortFlag(fs, &initOptions.Ports.HTTP, "http-port", "standalone HTTP/ACME port (default 80)")
		registerPortFlag(fs, &initOptions.Ports.HTTPS, "https-port", "base port for Fast and standalone Stealth (default 443)")
		registerPortFlag(fs, &initOptions.Ports.Fast, "fast-port", "Fast UDP port (default 443)")
		registerPortFlag(fs, &initOptions.Ports.Stealth, "stealth-port", "Stealth TCP port (default 443 standalone, 8443 shared)")
		registerPortFlag(fs, &initOptions.Ports.Decoy, "decoy-port", "standalone loopback TLS website port")
		registerPortFlag(fs, &initOptions.Ports.VMess, "vmess-port", "loopback VMess port for Rescue")
		registerPortFlag(fs, &initOptions.Ports.RealityOrigin, "reality-origin-port", "standalone loopback REALITY origin port when using a CDN")
		registerPortFlag(fs, &initOptions.Ports.RealityCDN, "reality-cdn-port", "standalone loopback REALITY CDN port")
	case "rescue":
		fs.StringVar(&cdn, "cdn-domain", "", "shared Rescue CDN hostname (empty disables Rescue)")
		registerRescueFlags(fs, &initOptions.Rescue)
	case "reality":
		fs.StringVar(&initOptions.RealityDest, "reality-dest", "", "only \"self\" (the default)")
	case "add":
		fs.BoolVar(&options.TestPorts, "test-ports", false, "use the test HTTPS port in the device link")
	case "run":
		fs.StringVar(&options.TestCA, "test-ca", "", "local test CA directory")
		fs.BoolVar(&options.TestPorts, "test-ports", false, "use the high test ports")
		fs.StringVar(&options.TestListen, "test-listen", "", "test bind IP (default 127.0.0.1)")
		registerTestHostsFlag(fs, &options.TestHosts)
		fs.StringVar(&options.WWW, "www", "", "directory of static site files")
		fs.StringVar(&options.WebUpstream, "web-upstream", "", "HTTP(S) site to reverse proxy")
		fs.StringVar(&options.CFOriginCA, "cf-origin-ca", "", "PEM CA for Cloudflare Authenticated Origin Pulls")
	case "install":
		fs.StringVar(&deployMode, "mode", "auto", "use or confirm the mode saved by init")
	case "uninstall":
		fs.BoolVar(&uninstallOptions.Purge, "purge", false, "also delete the state directory and all device keys")
		fs.BoolVar(&uninstallOptions.Yes, "yes", false, "skip the purge confirmation")
	case "revoke", "list", "relay-command":
	default:
		return fmt.Errorf("unknown server command %q", command)
	}
	if err := parseFlags(fs, args[1:]); err != nil {
		return err
	}
	if command == "add" || command == "revoke" {
		if fs.NArg() != 1 {
			return fmt.Errorf("server %s requires one device name", command)
		}
	} else if fs.NArg() != 0 {
		return fmt.Errorf("server %s takes only flags", command)
	}
	dir, err := serverStateDir(options.Dir)
	if err != nil {
		return err
	}
	options.Dir = dir
	switch command {
	case "init":
		if domain == "" {
			return errors.New("server init requires --domain")
		}
		initOptions.Mode = server.DeployMode(deployMode)
		initOptions.Warn = warnServer
		if err := server.InitWithOptions(options.Dir, domain, cdn, initOptions); err != nil {
			return err
		}
		_, err := fmt.Fprintln(os.Stdout, "Initialized server state in", options.Dir)
		return err
	case "rescue":
		var cdnDomain *string
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "cdn-domain" {
				cdnDomain = &cdn
			}
		})
		if cdnDomain == nil && initOptions.Rescue == (server.RescueConfig{}) {
			return errors.New("server rescue requires --cdn-domain or dedicated Rescue options")
		}
		port, err := server.SetRescue(options.Dir, cdnDomain, initOptions.Rescue)
		if err != nil {
			return err
		}
		if port == 0 {
			fmt.Fprintln(os.Stdout, "Shared Rescue disabled.")
		} else {
			fmt.Fprintf(os.Stdout, "Shared Rescue configured. Open TCP %d in the firewall.\n", port)
		}
		_, err = fmt.Fprintln(os.Stdout, "Keys and devices are kept. Restart the server. Update saved links or add devices under new names to get links with the current Rescue settings.")
		return err
	case "reality":
		if err := server.CheckRealityDest(initOptions.RealityDest); err != nil {
			return err
		}
		changed, err := server.SetRealityTarget(options.Dir)
		if err != nil {
			return err
		}
		if !changed {
			_, err = fmt.Fprintln(os.Stdout, "REALITY already borrows your HTTPS proxy site.")
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, "Stealth now borrows your HTTPS proxy site. Keys and devices are kept. Device links need the new Stealth name: in each saved link, set rsni=<proxy domain> (or add the device again). Restart the server.")
		return err
	case "add":
		encoded, code, proxy, err := server.AddWithProxy(options.Dir, fs.Arg(0), options.TestPorts)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(os.Stdout, encoded); err != nil {
			return err
		}
		if _, err := fmt.Fprint(os.Stdout, terminalQR(code)); err != nil {
			return err
		}
		if proxy != "" {
			_, err = fmt.Fprintln(os.Stdout, link.ProxyExport(proxy))
		}
		return err
	case "revoke":
		if err := server.Revoke(options.Dir, fs.Arg(0)); err != nil {
			return err
		}
		_, err := fmt.Fprintln(os.Stdout, "Revoked", fs.Arg(0))
		return err
	case "list":
		devices, err := server.ReadDevices(options.Dir)
		if err != nil {
			return err
		}
		for _, device := range devices {
			if _, err := fmt.Fprintf(os.Stdout, "%s\t%s\n", device.Name, device.CreatedAt.Format(time.RFC3339)); err != nil {
				return err
			}
		}
		return nil
	case "run":
		options.Log = os.Stderr
		return server.Run(ctx, options)
	case "relay-command":
		line, hint, err := server.RelayCommand(ctx, options.Dir)
		if err != nil {
			return err
		}
		if hint != "" {
			fmt.Fprintln(os.Stderr, hint)
		}
		if line != "" {
			_, err = fmt.Fprintln(os.Stdout, line)
		}
		return err
	case "install":
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		paths, hints, err := server.Install(ctx, options.Dir, executable, server.DeployMode(deployMode), warnServer)
		for _, path := range paths {
			fmt.Fprintln(os.Stdout, path)
		}
		for _, hint := range hints {
			fmt.Fprintln(os.Stdout, hint)
		}
		return err
	case "uninstall":
		uninstallOptions.Dir = options.Dir
		uninstallOptions.Inform = func(line string) { fmt.Fprintln(os.Stdout, line) }
		if term.IsTerminal(int(os.Stdin.Fd())) {
			uninstallOptions.Confirm = confirmOnTerminal
		}
		return server.Uninstall(ctx, uninstallOptions)
	}
	return nil
}

func runServerHopApply(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pipe server hop-apply", flag.ContinueOnError)
	var ports string
	var fast uint16
	fs.StringVar(&ports, "fast-hop", "", "Fast UDP hopping range")
	registerPortFlag(fs, &fast, "fast-port", "Fast UDP listening port")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("server hop-apply takes only flags")
	}
	return server.ApplyFastHop(ctx, ports, fast)
}

func serverStateDir(dir string) (string, error) {
	if dir == "" {
		dir = os.Getenv("PIPE_SERVER_DIR")
	}
	if dir != "" {
		return dir, nil
	}
	userConfig, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(userConfig, "pipe", "server"), nil
}

func runServerProxy(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "Usage: pipe server proxy <enable | disable | status | export <name>> [options]")
		return nil
	}
	action := args[0]
	fs := flag.NewFlagSet("pipe server proxy "+action, flag.ContinueOnError)
	var dir string
	fs.StringVar(&dir, "dir", "", "server state directory (or PIPE_SERVER_DIR)")
	opts := server.ProxyEnableOptions{
		Port: server.DefaultProxyPort, Warn: warnServer,
		Inform:     func(line string) { fmt.Fprintln(os.Stdout, line) },
		ReadSecret: terminalSecretReader(),
	}
	switch action {
	case "enable":
		fs.StringVar(&opts.Domain, "domain", "", "DNS-only hostname for the HTTPS proxy")
		registerPortFlag(fs, &opts.Port, "port", "HTTPS proxy TCP port (default 9443)")
		fs.StringVar(&opts.CertMethod, "cert-method", "", "certificate method: auto, http, dns or files (default: infer from options or auto)")
		fs.StringVar(&opts.DNS, "dns", "", "ACME DNS-01 provider (cloudflare or alidns)")
		fs.StringVar(&opts.DNSTokenFile, "dns-token-file", "", "owner-only Cloudflare API token file")
		fs.StringVar(&opts.DNSKeyFile, "dns-key-file", "", "owner-only AliDNS AccessKey file")
		fs.StringVar(&opts.CertFile, "cert", "", "TLS certificate chain file")
		fs.StringVar(&opts.KeyFile, "key", "", "owner-only TLS private key file")
		fs.StringVar(&opts.WWW, "www", "", "static website directory for unauthenticated visitors")
	case "disable", "status", "export":
	default:
		return fmt.Errorf("unknown server proxy command %q", action)
	}
	if err := parseFlags(fs, args[1:]); err != nil {
		return err
	}
	if action == "export" {
		if fs.NArg() != 1 {
			return errors.New("server proxy export requires one device name")
		}
	} else if fs.NArg() != 0 {
		return fmt.Errorf("server proxy %s takes only flags", action)
	}
	dir, err := serverStateDir(dir)
	if err != nil {
		return err
	}
	switch action {
	case "enable":
		if err := server.EnableProxy(ctx, dir, opts); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "HTTPS proxy enabled for %s. Open TCP %d in the firewall.\n", strings.ToLower(opts.Domain), opts.Port)
		if method := enabledMethod(dir); method == "http" {
			fmt.Fprintln(os.Stdout, "The certificate is requested when pipe server run starts. TCP 80 must be open to all IPs.")
		}
		fmt.Fprintln(os.Stdout, "Use pipe server proxy export <name> --dir <state> to retrieve an existing device's export line.")
	case "disable":
		if err := server.DisableProxy(dir); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "HTTPS proxy disabled.")
	case "status":
		status, err := server.ProxyStatus(dir)
		if err != nil {
			return err
		}
		if status.Domain == "" {
			fmt.Fprintln(os.Stdout, "HTTPS proxy disabled.")
		} else {
			fmt.Fprintf(os.Stdout, "HTTPS proxy enabled at %s:%d (%s).\n", status.Domain, status.Port, status.Source)
			fmt.Fprintf(os.Stdout, "Certificate method: %s\n", status.Method)
			expiry := "not issued yet"
			if !status.Expiry.IsZero() {
				expiry = status.Expiry.UTC().Format("2006-01-02")
			}
			fmt.Fprintf(os.Stdout, "Certificate expires: %s\n", expiry)
		}
		return nil
	case "export":
		proxy, err := server.ProxyExport(dir, fs.Arg(0))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, link.ProxyExport(proxy))
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, "Restart pipe server run to apply the change (for example, systemctl restart pipe).")
	return err
}

func registerRescueFlags(fs *flag.FlagSet, cfg *server.RescueConfig) {
	registerPortFlag(fs, &cfg.Port, "rescue-port", "shared Rescue TLS port (default 2053)")
	fs.StringVar(&cfg.Cert, "rescue-cert", "", "shared Rescue certificate chain file")
	fs.StringVar(&cfg.Key, "rescue-key", "", "shared Rescue owner-only private key file")
}

func registerPortFlag(fs *flag.FlagSet, port *uint16, name, help string) {
	fs.Func(name, help, func(raw string) error {
		n, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || n == 0 {
			return errors.New("port must be between 1 and 65535")
		}
		*port = uint16(n)
		return nil
	})
}

func warnServer(message string) {
	fmt.Fprintln(os.Stderr, "Warning:", message)
}

func terminalQR(code *qr.Code) string {
	var out strings.Builder
	const quiet = 4
	for y := -quiet; y < code.Size+quiet; y += 2 {
		out.WriteString("\x1b[30;107m")
		for x := -quiet; x < code.Size+quiet; x++ {
			top, bottom := code.Black(x, y), code.Black(x, y+1)
			switch {
			case top && bottom:
				out.WriteRune('█')
			case top:
				out.WriteRune('▀')
			case bottom:
				out.WriteRune('▄')
			default:
				out.WriteByte(' ')
			}
		}
		out.WriteString("\x1b[0m\n")
	}
	return out.String()
}

func enabledMethod(dir string) string {
	status, err := server.ProxyStatus(dir)
	if err != nil {
		return ""
	}
	return status.Method
}

func confirmOnTerminal(prompt string) (bool, error) {
	fmt.Fprint(os.Stderr, prompt+" ")
	var answer string
	fmt.Fscanln(os.Stdin, &answer)
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}
