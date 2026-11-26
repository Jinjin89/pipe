// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"pipe/internal/clientctl"
	"pipe/internal/config"
	"pipe/internal/failover"
	"pipe/internal/link"
	"pipe/internal/localfile"
	"pipe/internal/server"
	"pipe/internal/sysdns"
)

func runClient(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "--migrate-private" {
		if len(args) != 2 {
			return errors.New("--migrate-private requires a file path")
		}
		return localfile.MigratePrivate(args[1])
	}
	options, err := parseClientOptions(args)
	if err != nil {
		return err
	}
	failoverErrors := make(chan error, 1)
	ctl := clientctl.NewWithSettings(clientctl.Settings{
		EngineLogOutput: os.Stderr,
		OnTier:          func(tier failover.Tier) { fmt.Fprintln(os.Stderr, "Tier", tier) },
		OnRelayStatus:   printRelayChanges(os.Stderr),
		OnFailoverError: func(err error) {
			select {
			case failoverErrors <- err:
			default:
			}
		},
		RawErrors:        true,
		SkipConnectProbe: true,
	})
	var dns clientDNS
	if options.TUN && runtime.GOOS == "darwin" {
		dns = sysdns.NewDefault()
	}
	return runClientSession(ctx, ctl, options, dns, failoverErrors, os.Stderr)
}

func printRelayChanges(stderr io.Writer) func(string, string) {
	var lastHost, lastState string
	return func(host, state string) {
		if host == lastHost && state == lastState {
			return
		}
		lastHost, lastState = host, state
		if host == "" {
			return
		}
		switch state {
		case "via":
			fmt.Fprintf(stderr, "Relay %s: in use\n", host)
		case "direct":
			fmt.Fprintf(stderr, "Relay %s: not reachable, going direct\n", host)
		}
	}
}

func parseClientOptions(args []string) (clientctl.Options, error) {
	fs := flag.NewFlagSet("pipe run", flag.ContinueOnError)
	options := clientctl.Options{TUNOnly: true, RulesInDirect: true}
	var mode, tier, profiles, linkFile, testCA, testAddress string
	var tun bool
	fs.BoolVar(&tun, "tun", false, "use TUN for whole-device routing")
	fs.StringVar(&mode, "mode", "smart", "routing mode: smart, global or direct")
	fs.StringVar(&options.Listen, "listen", config.DefaultListen, "loopback HTTP/SOCKS listen address")
	fs.BoolVar(&options.SystemProxy, "system-proxy", false, "set the operating system's proxy while running")
	fs.StringVar(&tier, "tier", "auto", "proxy tier: auto, fast, stealth or rescue")
	fs.StringVar(&options.Relay, "relay", "", "relay `code`, IP address or DNS name")
	fs.StringVar(&options.LogLevel, "log", "warn", "engine log detail: warn, info or debug")
	fs.StringVar(&profiles, "profile-dir", "", "directory of private NAME.link files (or PIPE_PROFILE_DIR)")
	fs.StringVar(&linkFile, "link-file", "", "read a link from an owner-only file (use - for stdin)")
	fs.StringVar(&testCA, "test-ca", "", "trust the local test CA from this directory")
	fs.StringVar(&testAddress, "test-address", "", "private test IP for both origin and CDN")
	registerTestHostsFlag(fs, &options.TestHosts)
	if err := parseFlags(fs, args); err != nil {
		return options, err
	}
	if (linkFile == "" && fs.NArg() != 1) || (linkFile != "" && fs.NArg() != 0) {
		return options, errors.New("run requires one pipe link, protected link file, or YAML file")
	}
	switch options.LogLevel {
	case "warn", "info", "debug":
	default:
		return options, errors.New("--log must be warn, info or debug")
	}
	prefs := config.Defaults()
	source := fs.Arg(0)
	if linkFile != "" || source == "-" {
		var data []byte
		var err error
		const maxLinkBytes = 4096
		if linkFile == "-" || source == "-" {
			data, err = io.ReadAll(io.LimitReader(os.Stdin, maxLinkBytes+1))
		} else {
			data, err = localfile.ReadProtected(linkFile, maxLinkBytes)
		}
		if err != nil {
			return options, err
		}
		if len(data) > maxLinkBytes {
			return options, errors.New("device link input is too large")
		}
		options.Profile, err = link.Parse(strings.TrimSpace(string(data)))
		if err != nil {
			return options, errors.New("invalid device link input")
		}
	} else if strings.HasPrefix(source, "pipe:") {
		profile, err := link.Parse(source)
		if err != nil {
			return options, err
		}
		options.Profile = profile
	} else {
		file, err := config.ReadYAML(source)
		if err != nil {
			return options, err
		}
		prefs = file.Preferences
	}
	fs.Visit(func(option *flag.Flag) {
		switch option.Name {
		case "mode":
			prefs.Mode = mode
		case "tun":
			prefs.TUN = tun
		}
	})
	if !config.ValidMode(prefs.Mode) {
		return options, errors.New("mode must be smart, global or direct")
	}
	options.Mode, options.TUN, options.IPv6, options.Rules = prefs.Mode, prefs.TUN, prefs.IPv6, prefs.Rules
	if options.Profile.Host == "" && (options.UsesProxy() || prefs.Server != "") {
		profile, err := readProfile(profiles, prefs.Server)
		if err != nil {
			return options, err
		}
		options.Profile = profile
	}
	options.Tier = failover.Tier(tier)
	if testCA != "" {
		options.TestCAFile = filepath.Join(testCA, server.TestRootFile)
	}
	if testAddress != "" {
		ip, err := netip.ParseAddr(testAddress)
		if err != nil {
			return options, errors.New("--test-address must be an IP address")
		}
		options.TestAddress = ip
	}
	return options, nil
}

type clientSession interface {
	StartWithReady(clientctl.Options, func() error) error
	Stop() error
	Status() clientctl.Status
	SetLANDNSServers(func() []netip.AddrPort)
	SetOnStopped(func())
}

type clientDNS interface {
	Repair() error
	Set() error
	Restore() error
	Servers() []netip.AddrPort
}

func runClientSession(ctx context.Context, ctl clientSession, options clientctl.Options, dns clientDNS, failoverErrors <-chan error, stderr io.Writer) (runErr error) {
	if dns != nil {
		if err := dns.Repair(); err != nil {
			return fmt.Errorf("repair system DNS: %w", err)
		}
		ctl.SetLANDNSServers(dns.Servers)
	}
	// The ready callback and the stop hook run under the controller's lock.
	// Both shutdown paths restore only after the engine closes.
	var dnsSetAttempted bool
	restoreDNS := sync.OnceValue(func() error {
		if dnsSetAttempted {
			if err := dns.Restore(); err != nil {
				return fmt.Errorf("restore system DNS: %w", err)
			}
		}
		return nil
	})
	stopped := make(chan struct{})
	ctl.SetOnStopped(func() {
		_ = restoreDNS()
		close(stopped)
	})
	defer func() {
		stopErr := ctl.Stop()
		runErr = errors.Join(runErr, stopErr, restoreDNS())
	}()
	if err := ctl.StartWithReady(options, func() error {
		if dns != nil {
			dnsSetAttempted = true
			if err := dns.Set(); err != nil {
				return fmt.Errorf("set system DNS: %w", err)
			}
		}
		if options.TUN {
			fmt.Fprintln(stderr, "Client started in TUN mode")
		} else {
			fmt.Fprintln(stderr, "Client listening on", ctl.Status().Listen)
		}
		return nil
	}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	case <-stopped:
		return errors.New(ctl.Status().LastError)
	case err := <-failoverErrors:
		return err
	}
}

func readProfile(dir, alias string) (link.Profile, error) {
	if alias == "" {
		alias = "default"
	}
	if !config.ValidAlias(alias) {
		return link.Profile{}, errors.New("invalid server profile alias")
	}
	if dir == "" {
		dir = os.Getenv("PIPE_PROFILE_DIR")
	}
	if dir == "" {
		userConfig, err := os.UserConfigDir()
		if err != nil {
			return link.Profile{}, err
		}
		dir = filepath.Join(userConfig, "pipe", "profiles")
	}
	data, err := localfile.Read(filepath.Join(dir, alias+".link"), 4096, true)
	if err != nil {
		return link.Profile{}, err
	}
	return link.Parse(strings.TrimSpace(string(data)))
}
