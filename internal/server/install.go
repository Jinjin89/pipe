// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"pipe/internal/link"
)

const sysctlConfig = "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\nnet.core.rmem_max = 16777216\nnet.core.wmem_max = 16777216\n"

// installEUID and installApplyHop are variables so tests can avoid root and nft.
var (
	installEUID     = os.Geteuid
	installApplyHop = ApplyFastHop
)

func Install(ctx context.Context, dir, executable string, mode DeployMode, warn func(string)) ([]string, []string, error) {
	settings, err := ReadSettings(dir)
	if err != nil {
		return nil, nil, err
	}
	if mode != "" && mode != Auto && mode != settings.Mode {
		return nil, nil, fmt.Errorf("server was initialized in %s mode", settings.Mode)
	}
	if settings.Mode == Shared {
		if err := settings.realityTargetProblem(); err != nil && warn != nil {
			warn("Stealth will be off: " + err.Error())
		}
	}
	paths, err := GenerateInstall(dir, executable)
	if err != nil {
		return paths, nil, err
	}
	hints := []string{
		fmt.Sprintf("Saved deployment mode %s.", settings.Mode),
		fmt.Sprintf("Allow clients from any IP on UDP %d and TCP %d.", settings.fastPort(), settings.stealthPort()),
	}
	if settings.FastHop != "" {
		if installEUID() == 0 {
			if err := installApplyHop(ctx, settings.FastHop, settings.fastPort()); err != nil {
				return paths, nil, err
			}
		} else {
			hints = append(hints, "Fast port hopping is applied by pipe-hop.service (or run pipe server hop-apply as root).")
		}
	}
	if settings.FastHop == "" {
		hints = append(hints, "For connections from CN, consider initializing with --fast-hop 20000-40000.")
	} else {
		hints = append(hints, "Allow the Fast UDP hopping range "+settings.FastHop+".",
			"Copy the generated pipe-hop.service into /etc/systemd/system, then run:",
			"systemctl daemon-reload",
			"systemctl enable --now pipe-hop.service")
	}
	switch settings.Mode {
	case Standalone:
		hints = append(hints, fmt.Sprintf("Allow TCP %d for ACME HTTP-01.", settings.Ports.HTTP))
	case Shared:
		hints = append(hints, "Keep the existing website's TCP 443 restriction.")
		if cfg := settings.HTTPSProxyListener; cfg != nil {
			hints = append(hints, fmt.Sprintf("Allow TCP %d for the HTTPS proxy on its DNS-only domain.", cfg.Port))
			if cfg.method() == "http" || cfg.method() == "nginx" {
				hints = append(hints, "Allow public TCP 80 for HTTPS proxy HTTP-01.")
			}
		}
		if settings.RescueListen != "" {
			hints = append(hints, "Allow the reverse proxy's bridge to reach "+settings.RescueListen+" if required.",
				"Cloudflare Rescue subdomain: WebSockets on, SSL Full (strict), exempt it from Bot Fight Mode, and bypass caching. Cloudflare can close idle WebSockets after 100 s.",
				nginxLocation(settings))
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
	if nginxConfig(settings) == "" {
		path := filepath.Join(output, "pipe-nginx.conf")
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
	firewall := fmt.Sprintf("# Add to your existing input chain before its drop rule.\ntcp dport %d accept\nudp dport %d accept\n", settings.stealthPort(), settings.fastPort())
	if settings.Mode == Standalone {
		firewall += fmt.Sprintf("tcp dport %d accept # ACME HTTP-01\n", settings.Ports.HTTP)
	} else if cfg := settings.HTTPSProxyListener; cfg != nil {
		firewall += fmt.Sprintf("tcp dport %d accept # HTTPS forward proxy\n", cfg.Port)
		if cfg.method() == "http" || cfg.method() == "nginx" {
			firewall += "tcp dport 80 accept # ACME HTTP-01\n"
		}
	}
	if settings.FastHop != "" {
		firewall += fmt.Sprintf("# In prerouting, allow udp dport %s before translation to %d.\n", settings.FastHop, settings.fastPort())
	}
	files := []installFile{
		{"pipe.service", unit, 0644},
		{"90-pipe.conf", sysctlConfig, 0644},
		{"pipe.nft", firewall, 0644},
	}
	if settings.Mode == Shared && settings.RescueListen != "" {
		files = append(files, installFile{"pipe-rescue.nginx", nginxLocation(settings), 0600})
	}
	if nginx := nginxConfig(settings); nginx != "" {
		files = append(files, installFile{"pipe-nginx.conf", nginx, 0600})
	}
	if settings.FastHop != "" {
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
`, unitArgument(executable), settings.FastHop, settings.fastPort())
		files = append(files, installFile{"pipe-hop.service", hopUnit, 0644})
	}
	return files
}

func nginxLocation(settings Settings) string {
	listen, _ := privateRescueAddress(settings.RescueListen)
	return fmt.Sprintf(`location = %s {
    proxy_pass http://%s;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 1h;
    proxy_buffering off;
    access_log off;
}
`, settings.WSPath, listen)
}

// hostListensIPv6 reports whether this host can open IPv6 sockets: nginx
// refuses a whole config whose [::] listen it cannot open (D20 for nginx).
var hostListensIPv6 = func() bool {
	listener, err := net.Listen("tcp6", "[::]:0")
	if err != nil {
		return !ipv6Unavailable(err)
	}
	_ = listener.Close()
	return true
}

// nginxListen is one listen line, plus its IPv6 twin when the host has IPv6.
func nginxListen(port string) string {
	line := "    listen " + port + ";\n"
	if hostListensIPv6() {
		line += "    listen [::]:" + port + ";\n"
	}
	return line
}

func nginxConfig(settings Settings) string {
	if settings.Mode != Shared {
		return ""
	}
	var out strings.Builder
	if settings.RescueListen != "" {
		location := strings.TrimSuffix(nginxLocation(settings), "\n")
		fmt.Fprintf(&out, `server {
%s    server_name %s;
    # Uses the http-level certificate. Otherwise, add your certificate and key directives here.

    %s
    location / { return 404; }
}
`, nginxListen("443 ssl"), settings.CDNDomain, strings.ReplaceAll(location, "\n", "\n    "))
	}
	if cfg := settings.HTTPSProxyListener; cfg != nil && cfg.method() == "nginx" {
		if out.Len() != 0 {
			out.WriteByte('\n')
		}
		out.WriteString(nginxACMEBlock(*cfg))
	}
	return out.String()
}

func nginxACMEBlock(cfg httpsProxyListenerConfig) string {
	return fmt.Sprintf(`server {
    # Open TCP 80 to all IPs in the provider firewall for HTTP-01.
%s    server_name %s;

    location ^~ /.well-known/acme-challenge/ {
        # Override any inherited Cloudflare-only allowlist for ACME validators.
        allow all;
        limit_except GET { deny all; }
        proxy_pass http://%s;
        proxy_set_header Host $http_host;
        access_log off;
    }
    location / { return 404; }
}
`, nginxListen("80"), cfg.Domain, cfg.ACMEListen)
}

func ProxyACMENginx(dir string) (string, error) {
	settings, err := ReadSettings(dir)
	if err != nil {
		return "", err
	}
	if cfg := settings.HTTPSProxyListener; cfg != nil && cfg.method() == "nginx" {
		return nginxACMEBlock(*cfg), nil
	}
	return "", nil
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
