// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"pipe/internal/link"
)

const sysctlConfig = "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\nnet.core.rmem_max = 16777216\nnet.core.wmem_max = 16777216\n"
const setupInstallEnv = "PIPE_SETUP_INSTALL"

var installEUID = os.Geteuid

func Install(_ context.Context, dir, executable string, mode DeployMode, _ func(string)) ([]string, []string, error) {
	root := installEUID() == 0
	var settings Settings
	var err error
	if root {
		run := setupRun{opts: SetupOptions{Dir: dir}}
		settings, err = run.readSetupSettings()
	} else {
		settings, err = ReadSettings(dir)
	}
	if err != nil {
		return nil, nil, err
	}
	if mode != "" && mode != Auto && mode != settings.Mode {
		return nil, nil, fmt.Errorf("server was initialized in %s mode", settings.Mode)
	}
	var paths []string
	if !root {
		paths, err = GenerateInstall(dir, executable)
		if err != nil {
			return paths, nil, err
		}
	}
	hints := []string{
		fmt.Sprintf("Saved deployment mode %s.", settings.Mode),
		fmt.Sprintf("Allow clients from any IP on Fast UDP %d.", settings.fastPort()),
	}
	if settings.realityTargetProblem() == nil {
		hints = append(hints, fmt.Sprintf("Allow clients from any IP on Stealth TCP %d.", settings.stealthPort()))
	}
	fromSetup := os.Getenv(setupInstallEnv) == "1"
	if !fromSetup {
		hints = append(hints, "Use sudo pipe server setup --yes with the same --dir to render and install the systemd units and sysctl file as root.")
	}
	if settings.FastHop == "" {
		hints = append(hints, "For connections from CN, consider initializing with --fast-hop 20000-40000.")
	} else {
		hints = append(hints, "Allow the Fast UDP hopping range "+settings.FastHop+".")
		if !fromSetup {
			hints = append(hints, "Fast port hopping is applied by pipe-hop.service. To configure it with setup, supply --fast-hop and --fast-port.")
		}
	}
	switch settings.Mode {
	case Standalone:
		hints = append(hints, fmt.Sprintf("Allow TCP %d for ACME HTTP-01.", settings.Ports.HTTP))
	case Shared:
		hints = append(hints, "Keep the existing website's TCP 443 restriction.")
		if cfg := settings.HTTPSProxyListener; cfg != nil && !cfg.retired() {
			hints = append(hints, fmt.Sprintf("Allow TCP %d for the HTTPS proxy on its DNS-only domain.", cfg.Port))
			if cfg.method() == "http" {
				hints = append(hints, "Allow public TCP 80 for HTTPS proxy HTTP-01.")
			}
		}
		if port := settings.sharedRescuePort(); port != 0 {
			hints = append(hints, fmt.Sprintf("Allow TCP %d for Rescue. Only Cloudflare needs it.", port),
				"Cloudflare Rescue subdomain: enable WebSockets, use SSL Full (strict), and bypass caching. Cloudflare can close idle WebSockets after 100 s.")
		}
	}
	return paths, hints, nil
}

func GenerateInstall(dir, executable string) ([]string, error) {
	settings, err := ReadSettings(dir)
	if err != nil {
		return nil, err
	}
	state, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	output := filepath.Join(state, "install")
	if err := os.MkdirAll(output, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(output, 0700); err != nil {
		return nil, err
	}
	files := installArtifacts(settings, state, executable)
	paths := make([]string, 0, len(files))
	for _, file := range files {
		if err := writeAtomic(output, file.name, []byte(file.contents), file.mode); err != nil {
			return paths, err
		}
		paths = append(paths, filepath.Join(output, file.name))
	}
	for _, name := range []string{"pipe-rescue.nginx", "pipe-nginx.conf"} {
		path := filepath.Join(output, name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return paths, err
		}
	}
	return paths, nil
}

type installFile struct {
	name, contents string
	mode           os.FileMode
}

func installArtifacts(settings Settings, state, executable string) []installFile {
	firewall := fmt.Sprintf("# Add to your existing input chain.\nudp dport %d accept\n", settings.fastPort())
	if settings.realityTargetProblem() == nil {
		firewall += fmt.Sprintf("tcp dport %d accept\n", settings.stealthPort())
	}
	if settings.Mode == Standalone {
		firewall += fmt.Sprintf("tcp dport %d accept # ACME HTTP-01\n", settings.Ports.HTTP)
	} else if cfg := settings.HTTPSProxyListener; cfg != nil && !cfg.retired() {
		firewall += fmt.Sprintf("tcp dport %d accept # HTTPS forward proxy\n", cfg.Port)
		if cfg.method() == "http" {
			firewall += "tcp dport 80 accept # ACME HTTP-01\n"
		}
	}
	if settings.FastHop != "" {
		firewall += fmt.Sprintf("# In prerouting, allow udp dport %s before translation to %d.\n", settings.FastHop, settings.fastPort())
	}
	files := systemInstallFiles(state, executable, SetupFast{Port: settings.fastPort(), Hop: settings.FastHop})
	return append(files, installFile{"pipe.nft", firewall, 0644})
}

const hopServiceUnit = "pipe-hop.service"

func systemInstallFiles(state, executable string, fast SetupFast) []installFile {
	unit := fmt.Sprintf(`[Unit]
Description=Pipe server
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
User=pipe
Group=pipe
ExecStart=%s server run --dir %s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
`, unitArgument(executable), unitArgument(state))
	files := []installFile{
		{"pipe.service", unit, 0644},
		{"90-pipe.conf", sysctlConfig, 0644},
	}
	if fast.Hop != "" {
		hopUnit := fmt.Sprintf(`[Unit]
Description=Pipe Fast UDP port hopping
After=nftables.service
Before=pipe.service

[Service]
Type=oneshot
User=root
RemainAfterExit=yes
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
ExecStart=%s server hop-apply --fast-hop %s --fast-port %d

[Install]
WantedBy=multi-user.target
`, unitArgument(executable), fast.Hop, fast.Port)
		files = append(files, installFile{hopServiceUnit, hopUnit, 0644})
	}
	return files
}

const hopTableComment = "pipe Fast port hopping"

func ApplyFastHop(ctx context.Context, ports string, fast uint16) error {
	if ports == "" || fast == 0 {
		return errors.New("--fast-hop and --fast-port are required")
	}
	return setHopTable(ctx, ports, fast)
}

func setHopTable(ctx context.Context, ports string, fast uint16) error {
	if runtime.GOOS != "linux" {
		return errors.New("Fast port hopping requires nftables on Linux")
	}
	if ports != "" {
		if _, _, err := link.ParseHop(ports); err != nil {
			return err
		}
	}
	run := func(input string, args ...string) (string, error) {
		command := exec.CommandContext(ctx, "nft", args...)
		command.Stdin = strings.NewReader(input)
		output, err := command.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("nft %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
		return string(output), nil
	}
	return reconcileHopTable(ports, fast, run)
}

func reconcileHopTable(ports string, fast uint16, nft func(string, ...string) (string, error)) error {
	tables, err := nft("", "list", "tables")
	if err != nil {
		return err
	}
	var transaction string
	for line := range strings.SplitSeq(tables, "\n") {
		if strings.TrimSpace(line) == "table inet pipe" {
			table, err := nft("", "list", "table", "inet", "pipe")
			if err != nil {
				return err
			}
			owned := false
			for line := range strings.SplitSeq(table, "\n") {
				if strings.TrimSuffix(strings.TrimSpace(line), ";") == fmt.Sprintf("comment %q", hopTableComment) {
					owned = true
					break
				}
			}
			if !owned {
				return errors.New("inet pipe already exists without the Fast hopping ownership comment")
			}
			transaction = "delete table inet pipe\n"
			break
		}
	}
	if ports != "" {
		transaction += fmt.Sprintf(`create table inet pipe { comment %q; }
add chain inet pipe fast_hop { type nat hook prerouting priority dstnat; policy accept; }
add rule inet pipe fast_hop fib daddr type local udp dport %s redirect to :%d
`, hopTableComment, ports, fast)
	}
	if transaction == "" {
		return nil
	}
	_, err = nft(transaction, "-f", "-")
	return err
}

func unitArgument(value string) string {
	escape := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$", "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return `"` + escape.Replace(value) + `"`
}
