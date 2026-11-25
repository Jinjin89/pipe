#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -Eeuo pipefail

check='prerequisites'
work_dir=
server_ns_created=0
client_ns_created=0
relay_ns_created=0
relay_server2_ns_created=0
relay_server2_pid=
relay_target2_pid=
server_pid=
target_pid=
smart_target_pid=
web_pid=
named_pid=
cover_pid=
wrong_relay_pid=
client_pid=
download_pid=
server_ns=pipe-srv
client_ns=pipe-cli
relay_ns=pipe-rly
relay_server2_ns=pipe-srv2
server_addr=10.83.0.1
client_addr=10.83.0.2
target_addr=11.0.0.80
target_port=8080
https_port=18443
mixed_port=17890
origin=origin.pipe.test
cdn=cdn.pipe.test
named=named.split.example.net
named_port=18448
# An address the server can't use, standing in for one an app found itself.
unusable_ipv6=2001:db8::80
client_ipv6=2001:db8:1::2
scenario=${1:-standalone}

fail() {
  printf 'FAIL %s\n' "$1" >&2
  if [[ -n $work_dir ]]; then
    for log in "$work_dir/server.log" "$work_dir/client.log" "$work_dir/target.log" "$work_dir/smart-target.log" \
      "$work_dir/web.log" "$work_dir/cover.log" "$work_dir/wrong-relay.log" \
      "$work_dir/relay-server2.log" "$work_dir/relay-target2.log"; do
      if [[ -s $log ]]; then
        tail -n 20 "$log" >&2
      fi
    done
  fi
  exit 1
}

pass() { printf 'PASS %s\n' "$1"; }

stop_pid() {
  if [[ -n $1 ]]; then
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
  fi
}

cleanup() {
  trap - ERR
  stop_pid "$download_pid"
  stop_pid "$client_pid"
  stop_pid "$server_pid"
  stop_pid "$web_pid"
  stop_pid "$named_pid"
  stop_pid "$cover_pid"
  stop_pid "$wrong_relay_pid"
  stop_pid "$relay_server2_pid"
  stop_pid "$relay_target2_pid"
  stop_pid "$smart_target_pid"
  stop_pid "$target_pid"
  if ((client_ns_created)); then ip netns del "$client_ns" || true; fi
  if ((server_ns_created)); then ip netns del "$server_ns" || true; fi
  if ((relay_server2_ns_created)); then ip netns del "$relay_server2_ns" || true; fi
  if ((relay_ns_created)); then ip netns del "$relay_ns" || true; fi
  if [[ -n $work_dir ]]; then rm -rf -- "$work_dir"; fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'fail "$check (line $LINENO)"' ERR

[[ $EUID == 0 ]] || fail 'root is required for the isolated network namespaces'
[[ $# -le 1 && ($scenario == standalone || $scenario == shared || $scenario == relay) ]] || fail 'usage: run.sh [standalone|shared|relay]'
for tool in ip tc nft curl python3 grep tail; do
  command -v "$tool" >/dev/null || fail "missing $tool"
done
umask 077
work_dir=$(mktemp -d /tmp/pipe-e2e.XXXXXX)
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cp "$repo_dir/go.mod" "$repo_dir/go.sum" "$work_dir/"
export PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
  GOFLAGS="-mod=mod -p=2 -modfile=$work_dir/go.mod" GOCACHE=/tmp/pipe-gocache CGO_ENABLED=0
fixture=$work_dir/fixture
(cd -- "$repo_dir" && go build -buildvcs=false -o "$fixture" ./test/e2e/fixture)
if [[ -n ${PIPE_BIN:-} ]]; then
  bin=$(realpath -- "$PIPE_BIN")
  [[ -x $bin ]] || fail "PIPE_BIN is not executable"
else
  bin=$work_dir/pipe
  (
    cd -- "$repo_dir"
    go build -buildvcs=false -trimpath -tags with_gvisor,with_quic,with_utls,with_acme,badlinkname,tfogo_checklinkname0 \
      -ldflags '-s -w -checklinkname=0' -o "$bin" ./cmd/pipe
  )
fi

wait_for_log() {
  python3 - "$@" <<'WAIT_FOR_LOG'
import os
import sys
import time

pid, log, line, seconds = sys.argv[1:]
pid, line = int(pid), line.encode()
deadline = time.monotonic() + float(seconds)
while time.monotonic() < deadline:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        sys.exit(1)
    with open(log, "rb") as stream:
        if any(entry.rstrip(b"\n") == line for entry in stream):
            sys.exit(0)
    time.sleep(0.1)
sys.exit(1)
WAIT_FOR_LOG
}

start_client() {
  local profile=$1 tier=$2 mode=${3:-global} client_log=$work_dir/client.log
  local -a address=(--test-address "$server_addr")
  if [[ $scenario == relay ]]; then address=(); fi
  : > "$client_log"
  ip netns exec "$client_ns" "$bin" run "$profile" --mode "$mode" --tier "$tier" \
    --listen "127.0.0.1:$mixed_port" --test-ca "$work_dir/ca" "${address[@]}" \
    --profile-dir "$work_dir/profiles" "${@:4}" \
    >> "$client_log" 2>&1 &
  client_pid=$!
  wait_for_log "$client_pid" "$client_log" "Client listening on 127.0.0.1:$mixed_port" 8 ||
    fail "$check (client exited or did not report readiness)"
  local deadline=$((SECONDS + 3))
  while ((SECONDS < deadline)); do
    kill -0 "$client_pid" 2>/dev/null || fail "$check (client exited during startup)"
    if ip netns exec "$client_ns" python3 -c \
      'import socket, sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), 0.2).close()' \
      "$mixed_port" >/dev/null 2>&1; then
      kill -0 "$client_pid" 2>/dev/null || fail "$check (client exited during startup)"
      return 0
    fi
    sleep .1
  done
  fail "$check (client mixed port did not accept TCP connections)"
}

stop_client() {
  stop_pid "$client_pid"
  client_pid=
}

proxied_curl() {
  ip netns exec "$client_ns" curl --noproxy '' --proxy "socks5h://127.0.0.1:$mixed_port" \
    --connect-timeout 4 --fail --silent --show-error "$@"
}

check_target() {
  local body
  body=$(proxied_curl --max-time 8 "http://$target_addr:$target_port/") || return 1
  [[ $body == 'pipe e2e target' ]]
}

cover_title() {
  sed -n 's/^[[:space:]]*<title>\(.*\)<\/title>$/\1/p' "$1"
}

check_cover_page() {
  local page=$1 title
  title=$(cover_title "$page")
  [[ -n $title ]] &&
    grep -iq '^<!doctype html>' "$page" &&
    grep -Fq "<h1>$title</h1>" "$page" &&
    grep -Fq '<style>' "$page" &&
    ! grep -Eiq 'pipe|proxy|vpn|sing-box' "$page"
}

check='isolated topology'
ip netns add "$server_ns"
server_ns_created=1
ip netns add "$client_ns"
client_ns_created=1
if [[ $scenario == relay ]]; then
  source "$repo_dir/test/e2e/relay.sh"
  relay_topology
else
  ip -n "$server_ns" link add veth-srv type veth peer name veth-cli netns "$client_ns"
  ip -n "$server_ns" addr add "$server_addr/24" dev veth-srv
  ip -n "$client_ns" addr add "$client_addr/24" dev veth-cli
fi
ip -n "$server_ns" addr add "$target_addr/32" dev lo
ip -n "$server_ns" link set lo up
ip -n "$client_ns" link set lo up
ip -n "$server_ns" link set veth-srv up
ip -n "$client_ns" link set veth-cli up

cat > "$work_dir/target.py" <<'PY'
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/slow":
            chunk = b"x" * 32768
            chunks = 64
            self.send_response(200)
            self.send_header("Content-Length", str(len(chunk) * chunks))
            self.end_headers()
            for _ in range(chunks):
                self.wfile.write(chunk)
                self.wfile.flush()
                time.sleep(0.35)
        else:
            body = (sys.argv[3] + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


with ThreadingHTTPServer((sys.argv[1], int(sys.argv[2])), Target) as server:
    print("Target ready", flush=True)
    server.serve_forever()
PY
: > "$work_dir/target.log"
ip netns exec "$server_ns" python3 -u "$work_dir/target.py" "$target_addr" "$target_port" 'pipe e2e target' \
  >> "$work_dir/target.log" 2>&1 &
target_pid=$!
wait_for_log "$target_pid" "$work_dir/target.log" 'Target ready' 8

if [[ $scenario == shared || $scenario == relay ]]; then
  source "$repo_dir/test/e2e/shared.sh"
  exit 0
fi

"$bin" server init --mode standalone --dir "$work_dir/state" --domain "$origin" --cdn-domain "$cdn" >/dev/null
"$bin" server add main --dir "$work_dir/state" --test-ports > "$work_dir/main.link"
"$bin" server add revoke-me --dir "$work_dir/state" --test-ports > "$work_dir/revoke.link"
IFS= read -r main_link < "$work_dir/main.link"
IFS= read -r revoked_link < "$work_dir/revoke.link"
main_proxy=$(sed -n 's/^export https_proxy=\([^ ]*\).*/\1/p' "$work_dir/main.link")
revoked_proxy=$(sed -n 's/^export https_proxy=\([^ ]*\).*/\1/p' "$work_dir/revoke.link")
[[ $main_proxy == https://main:* && $revoked_proxy == https://revoke-me:* ]]
tls_target_port=18447
"$fixture" cert "$work_dir/ca" "$target_addr" >/dev/null
: > "$work_dir/web.log"
ip netns exec "$server_ns" "$fixture" serve --listen "$target_addr:$tls_target_port" \
  --ca "$work_dir/ca" --host "$target_addr" --body 'pipe HTTPS target' >> "$work_dir/web.log" 2>&1 &
web_pid=$!
wait_for_log "$web_pid" "$work_dir/web.log" 'TLS fixture ready' 8
"$fixture" cert "$work_dir/ca" "$named" >/dev/null
: > "$work_dir/named.log"
ip netns exec "$server_ns" "$fixture" serve --listen "$target_addr:$named_port" \
  --ca "$work_dir/ca" --host "$named" --body 'pipe named target' >> "$work_dir/named.log" 2>&1 &
named_pid=$!
wait_for_log "$named_pid" "$work_dir/named.log" 'TLS fixture ready' 8
: > "$work_dir/server.log"
ip netns exec "$server_ns" "$bin" server run --dir "$work_dir/state" --test-ca "$work_dir/ca" \
  --test-ports --test-listen "$server_addr" --test-hosts "other.split.test=$target_addr" \
  --test-hosts "other.split.example.net=$target_addr" --test-hosts "other.split.example.org=$target_addr" \
  --test-hosts "$named=$target_addr" \
  >> "$work_dir/server.log" 2>&1 &
server_pid=$!
wait_for_log "$server_pid" "$work_dir/server.log" "Server listening on $server_addr:$https_port (TCP and UDP)" 8
pass "$check"

for tier in fast stealth rescue; do
  check="forced $tier tier"
  start_client "$main_link" "$tier"
  check_target
  stop_client
  pass "$check"
done

# In TUN mode, apps that go around Pipe's DNS (a browser's own DNS over HTTPS,
# a LAN resolver) arrive with real addresses the server may not reach: this
# server has no IPv6 at all. Every tier must send the TLS name instead, as it
# does for apps that use Pipe's DNS.
check='TUN sends the TLS name for a raw IPv6 address on every tier'
ip -n "$client_ns" route add default via "$server_addr"
# The client's network has IPv6 (a public address and a default route), so its
# TUN carries IPv6 (D45); the server still has none.
ip -n "$client_ns" addr add "$client_ipv6/64" dev veth-cli nodad
ip -n "$client_ns" -6 route add default dev veth-cli
for tier in fast stealth rescue; do
  : > "$work_dir/client.log"
  ip netns exec "$client_ns" "$bin" run "$main_link" --tun --mode global --tier "$tier" \
    --test-ca "$work_dir/ca" --test-address "$server_addr" >> "$work_dir/client.log" 2>&1 &
  client_pid=$!
  wait_for_log "$client_pid" "$work_dir/client.log" 'Client started in TUN mode' 8 ||
    fail "$check (TUN client exited or did not report readiness)"
  body=$(ip netns exec "$client_ns" curl --noproxy '*' --connect-timeout 4 --max-time 8 --fail --silent \
    --show-error --cacert "$work_dir/ca/ca.pem" --resolve "$named:$named_port:[$unusable_ipv6]" \
    "https://$named:$named_port/")
  [[ $body == 'pipe named target' ]]
  stop_client
done
ip -n "$client_ns" -6 route del default dev veth-cli
ip -n "$client_ns" addr del "$client_ipv6/64" dev veth-cli
ip -n "$client_ns" route del default via "$server_addr"
pass "$check"

check='REALITY authentication also accepts the CDN SNI'
cdn_sni_link=${main_link/"@$origin:"/"@$cdn:"}
start_client "$cdn_sni_link" stealth
check_target
stop_client
pass "$check"

check='standalone HTTPS serves a stable cover over HTTP/1.1 and HTTP/2'
for domain in "$origin" "$cdn"; do
  ip netns exec "$client_ns" curl --http1.1 --noproxy '*' --fail --silent --show-error --max-time 8 \
    --cacert "$work_dir/ca/ca.pem" --resolve "$domain:$https_port:$server_addr" \
    "https://$domain:$https_port/" > "$work_dir/decoy-$domain.html"
done
standalone_cover="$work_dir/decoy-$origin.html"
check_cover_page "$standalone_cover"
cmp "$standalone_cover" "$work_dir/decoy-$cdn.html"
version=$(ip netns exec "$client_ns" curl --http2 --noproxy '*' --fail --silent --show-error --max-time 8 \
  --cacert "$work_dir/ca/ca.pem" --resolve "$origin:$https_port:$server_addr" \
  --output "$work_dir/decoy-h2.html" --write-out '%{http_version}' "https://$origin:$https_port/")
[[ $version == 2 ]]
cmp "$standalone_cover" "$work_dir/decoy-h2.html"
pass "$check"

check='standalone HTTP/3 serves the same cover with a valid certificate'
ip netns exec "$client_ns" "$fixture" fetch-http3 "$server_addr:$https_port" \
  "https://$origin:$https_port/" "$work_dir/ca/ca.pem" > "$work_dir/decoy-h3.html"
cmp "$standalone_cover" "$work_dir/decoy-h3.html"
pass "$check"

source "$repo_dir/test/e2e/https-proxy.sh"
check_https_proxy

check='server denies loopback destinations'
mkdir "$work_dir/profiles"
printf '%s\n' "$main_link" > "$work_dir/profiles/main.link"
cat > "$work_dir/guard.yaml" <<'YAML'
server: main
rules:
  - 127.0.0.1/32 -> proxy
YAML
start_client "$work_dir/guard.yaml" fast
if proxied_curl --max-time 4 'http://127.0.0.1:18080/' > /dev/null 2>&1; then fail "$check"; fi
check_target
stop_client
pass "$check"

check='Smart mode sends the CN test hostname directly and proxies other destinations'
# SOCKS5h preserves the hostnames. Each namespace serves its own body at the
# same address, which is assigned only to loopback in this topology.
ip -n "$client_ns" addr add "$target_addr/32" dev lo
: > "$work_dir/smart-target.log"
ip netns exec "$client_ns" python3 -u "$work_dir/target.py" "$target_addr" "$target_port" 'pipe e2e direct target' \
  >> "$work_dir/smart-target.log" 2>&1 &
smart_target_pid=$!
wait_for_log "$smart_target_pid" "$work_dir/smart-target.log" 'Target ready' 8
# Private names (.test, .invalid, .local) always go direct, ahead of user
# rules, so the rules use example.net names. other.split.example.net has no
# user rule and exercises the implicit Smart fallback.
cat > "$work_dir/smart.yaml" <<'YAML'
server: main
rules:
  - cn.split.example.net -> direct
  - other.split.example.org -> proxy
YAML
start_client "$work_dir/smart.yaml" fast smart --test-hosts "cn.split.example.net=$target_addr"
body=$(proxied_curl --max-time 8 "http://cn.split.example.net:$target_port/")
[[ $body == 'pipe e2e direct target' ]]
body=$(proxied_curl --max-time 8 "http://other.split.example.org:$target_port/")
[[ $body == 'pipe e2e target' ]]
body=$(proxied_curl --max-time 8 "http://other.split.example.net:$target_port/")
[[ $body == 'pipe e2e target' ]]
stop_client
stop_pid "$smart_target_pid"
smart_target_pid=
ip -n "$client_ns" addr del "$target_addr/32" dev lo
pass "$check"

check='revocation preflight'
for tier in fast stealth rescue; do
  start_client "$revoked_link" "$tier"
  check_target
  stop_client
done
check='credential reload preserves an unrelated TCP download'
start_client "$main_link" stealth
ip netns exec "$client_ns" curl --noproxy '' --proxy "socks5h://127.0.0.1:$mixed_port" \
  --fail --silent --show-error --max-time 35 --output "$work_dir/reload.body" "http://$target_addr:$target_port/slow" &
download_pid=$!
start_deadline=$((SECONDS + 5))
while [[ ! -s $work_dir/reload.body ]]; do
  ((SECONDS < start_deadline)) || fail 'ongoing download did not start'
  kill -0 "$download_pid" 2>/dev/null || fail 'ongoing download ended before reload'
  sleep .1
done
"$bin" server revoke revoke-me --dir "$work_dir/state" >/dev/null
wait_for_log "$server_pid" "$work_dir/server.log" 'Reloaded 1 device credentials' 8
wait "$download_pid"
download_pid=
[[ $(wc -c < "$work_dir/reload.body") -eq 2097152 ]]
stop_client
pass "$check"
for tier in fast stealth rescue; do
  check="revoked device is denied on $tier"
  start_client "$revoked_link" "$tier"
  if proxied_curl --max-time 5 "http://$target_addr:$target_port/" > /dev/null 2>&1; then fail "$check"; fi
  stop_client
  start_client "$main_link" "$tier"
  check_target
  stop_client
  pass "$check"
done

check_https_proxy_revocation

check='latency under 100 ms delay and 2% loss'
ip netns exec "$client_ns" tc qdisc add dev veth-cli root netem delay 100ms loss 2%
for tier in fast stealth rescue; do
  start_client "$main_link" "$tier"
  ttfb=$(proxied_curl --max-time 15 --output "$work_dir/latency.body" --write-out '%{time_starttransfer}' \
    "http://$target_addr:$target_port/")
  grep -Fxq 'pipe e2e target' "$work_dir/latency.body"
  printf 'PASS %s TTFB %s s\n' "$tier" "$ttfb"
  stop_client
done
ip netns exec "$client_ns" tc qdisc del dev veth-cli root
pass "$check"

check='UDP loss triggers stealth within 15 seconds'
start_client "$main_link" auto
wait_for_log "$client_pid" "$work_dir/client.log" 'Tier fast' 4
ip netns exec "$client_ns" curl --noproxy '' --proxy "socks5h://127.0.0.1:$mixed_port" \
  --fail --silent --show-error --max-time 55 --output "$work_dir/slow.body" "http://$target_addr:$target_port/slow" &
download_pid=$!
# Reach the stall detector's minimum download volume before dropping packets.
start_deadline=$((SECONDS + 5))
while [[ ! -f $work_dir/slow.body ]] || (( $(wc -c < "$work_dir/slow.body") < 256 * 1024 )); do
  ((SECONDS < start_deadline)) || fail 'ongoing download did not reach 256 KiB before UDP loss'
  kill -0 "$download_pid" 2>/dev/null || fail 'ongoing download ended before UDP loss'
  sleep .1
done
# Drop packets on arrival so the client observes network loss.
ip netns exec "$server_ns" nft add table inet pipe_test
ip netns exec "$server_ns" nft 'add chain inet pipe_test input { type filter hook input priority 0; policy accept; }'
outage_start=$SECONDS
ip netns exec "$server_ns" nft add rule inet pipe_test input udp dport "$https_port" drop
wait_for_log "$client_pid" "$work_dir/client.log" 'Tier stealth' 15
kill -0 "$download_pid" 2>/dev/null || fail 'existing TCP download ended during UDP loss'
ip netns exec "$server_ns" nft delete table inet pipe_test
check_target
[[ $(grep '^Tier ' "$work_dir/client.log" | tail -n 1) == 'Tier stealth' ]]
pass "$check"

check='existing TCP download survives tier switch'
wait "$download_pid"
download_pid=
[[ $(wc -c < "$work_dir/slow.body") -eq 2097152 ]]
pass "$check"

check='fast stays in cooldown after UDP returns'
# The outage started before the controller entered cooldown. Use that time
# as the lower bound and let the fake-clock test check the exact boundary.
while ((SECONDS < outage_start + 300)); do
  kill -0 "$client_pid"
  [[ $(grep -Fxc 'Tier fast' "$work_dir/client.log") == 1 ]] || fail "$check"
  sleep 1
done
pass "$check"
