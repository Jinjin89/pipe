// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"pipe/internal/link"
	"pipe/internal/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "pipe:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 && defaultCommand != "" {
		args = []string{defaultCommand}
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(os.Stderr, "Usage: pipe app [--background | --no-window | --install-desktop-entry]\n       pipe helper <install | remove | status | run>\n       pipe run <link | pipe.yaml> [--relay <code>] [options]\n       pipe server <setup | init | add | revoke | list | run | install | uninstall | proxy | rescue | reality | relay-command> [options]\n       pipe relay <add | remove | status | apply> [options]\n       pipe version")
		return nil
	}
	switch args[0] {
	case "run":
		return runClient(ctx, args[1:])
	case "app":
		return runApp(ctx, args[1:])
	case "helper":
		return runHelper(ctx, args[1:])
	case "server":
		return runServer(ctx, args[1:])
	case "relay":
		return runRelay(ctx, args[1:])
	case "version", "--version":
		fmt.Println("pipe", version.Version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// Walk the known flags so subcommands accept options on either side of an
// operand. FlagSet still parses values and handles errors and --help.
func parseFlags(fs *flag.FlagSet, args []string) error {
	var flags, operands []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			operands = append(operands, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
			continue
		}
		flags = append(flags, arg)
		name, _, inline := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if value := fs.Lookup(name); value != nil && !inline {
			boolean, ok := value.Value.(interface{ IsBoolFlag() bool })
			if !ok || !boolean.IsBoolFlag() {
				if i+1 >= len(args) || args[i+1] == "--" {
					return fmt.Errorf("--%s requires a value", name)
				}
				i++
				flags = append(flags, args[i])
			}
		}
	}
	return fs.Parse(append(append(flags, "--"), operands...))
}

func registerTestHostsFlag(fs *flag.FlagSet, hosts *map[string]netip.Addr) {
	fs.Func("test-hosts", "test DNS mapping HOST=IP (repeatable, requires --test-ca)", func(value string) error {
		host, address, ok := strings.Cut(value, "=")
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		_, hostIPErr := netip.ParseAddr(host)
		ip, err := netip.ParseAddr(address)
		if !ok || !link.ValidHost(host) || hostIPErr == nil || err != nil || ip.Zone() != "" {
			return errors.New("expected a DNS hostname and an IP address in HOST=IP form")
		}
		if *hosts == nil {
			*hosts = make(map[string]netip.Addr)
		}
		(*hosts)[host] = ip.Unmap()
		return nil
	})
}
