# SPDX-License-Identifier: GPL-3.0-or-later
# Sourced by run.sh after creating the isolated namespaces and target.

check='shared preserves an existing web server and installs Fast port hopping'
https_port=443
stealth_port=8443
rescue_port=10001
cdn=static.website.pipe.test
proxy_domain=gate.other.test
proxy_port=9443
tls_target_port=18447
state=$work_dir/state
profile_host=$server_addr
if [[ $scenario == relay ]]; then profile_host=$relay_target; fi
website_pin=$("$fixture" cert "$work_dir/ca" "$cdn")
rescue_address="127.0.0.1:$rescue_port"
: > "$work_dir/web.log"
ip netns exec "$server_ns" "$fixture" serve --listen "$server_addr:443" --http "$server_addr:80" \
  --ca "$work_dir/ca" --host "$cdn" --body 'existing website' --state "$state/server.json" \
  --rescue "$rescue_address" >> "$work_dir/web.log" 2>&1 &
web_pid=$!
wait_for_log "$web_pid" "$work_dir/web.log" 'TLS fixture ready' 8

ip netns exec "$server_ns" "$bin" server init --mode auto --dir "$state" --domain "$profile_host" --fast-sni "$origin" \
  --cdn-domain "$cdn" --rescue-listen "$rescue_address" --fast-hop 25000-25003 > "$work_dir/init.out"

proxy_pin=$("$fixture" cert "$work_dir/ca" "$proxy_domain")
[[ $website_pin != "$proxy_pin" ]]
"$fixture" cert "$work_dir/ca" "$target_addr" >/dev/null
printf '127.0.0.1 localhost\n%s %s\n' "$server_addr" "$proxy_domain" > "$work_dir/proxy-hosts"
# Map the proxy name only within this fixture command's private mount namespace.
ip netns exec "$server_ns" unshare --mount --propagation private -- bash -c '
  mount --bind "$1" /etc/hosts
  shift
  exec "$@"
' shared-proxy "$work_dir/proxy-hosts" "$bin" server proxy enable --dir "$state" --domain "$proxy_domain" \
  --cert "$work_dir/ca/$proxy_domain.pem" --key "$work_dir/ca/$proxy_domain-key.pem" > "$work_dir/proxy-enable.out"
grep -Fq "Open TCP $proxy_port" "$work_dir/proxy-enable.out"
grep -Fq 'Restart pipe server run' "$work_dir/proxy-enable.out"
: > "$work_dir/smart-target.log"
ip netns exec "$server_ns" "$fixture" serve --listen "$target_addr:$tls_target_port" \
  --ca "$work_dir/ca" --host "$target_addr" --body 'pipe HTTPS target' >> "$work_dir/smart-target.log" 2>&1 &
smart_target_pid=$!
wait_for_log "$smart_target_pid" "$work_dir/smart-target.log" 'TLS fixture ready' 8

if [[ $scenario == shared ]]; then
  ip netns exec "$server_ns" nft add table inet pipe_fixture
  for _ in 1 2; do
    ip netns exec "$server_ns" "$bin" server install --mode auto --dir "$state" > "$work_dir/install.out"
    grep -Fq 'Saved deployment mode shared.' "$work_dir/install.out"
    grep -Fq "Allow TCP $proxy_port for the HTTPS proxy" "$work_dir/install.out"
  done
  ip netns exec "$server_ns" "$bin" server uninstall --dir "$state"
fi
ip netns exec "$server_ns" "$bin" server hop-apply --fast-hop 25000-25003 --fast-port 443
ip netns exec "$server_ns" nft list table inet pipe > "$work_dir/hop.nft"
grep -Fq 'udp dport 25000-25003 redirect to :443' "$work_dir/hop.nft"
"$bin" server add main --dir "$state" > "$work_dir/main.link"
"$bin" server add revoke-me --dir "$state" > "$work_dir/revoke.link"
IFS= read -r main_link < "$work_dir/main.link"
IFS= read -r revoked_link < "$work_dir/revoke.link"
main_proxy=$(sed -n 's/^export https_proxy=\([^ ]*\).*/\1/p' "$work_dir/main.link")
revoked_proxy=$(sed -n 's/^export https_proxy=\([^ ]*\).*/\1/p' "$work_dir/revoke.link")
[[ $main_link == pipe://*@"$profile_host"\?* && $main_link == *"fsni=$origin"* ]]
[[ $main_proxy == https://main:*@"$proxy_domain:$proxy_port" && $revoked_proxy == https://revoke-me:*@"$proxy_domain:$proxy_port" ]]
[[ $("$bin" server proxy export main --dir "$state") == "export https_proxy=$main_proxy http_proxy=$main_proxy" ]]
ws_path=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ws_path"])' "$state/server.json")

: > "$work_dir/server.log"
ip netns exec "$server_ns" "$bin" server run --dir "$state" --test-ca "$work_dir/ca" \
  --test-ports --test-listen "$server_addr" >> "$work_dir/server.log" 2>&1 &
server_pid=$!
wait_for_log "$server_pid" "$work_dir/server.log" \
  "Server listening on $server_addr:443 (UDP Fast) and $server_addr:8443 (TCP Stealth)" 8
wait_for_log "$server_pid" "$work_dir/server.log" "HTTPS proxy listening on $server_addr:$proxy_port" 8
pass "$check"

if [[ $scenario == relay ]]; then
  relay_checks
  return
fi

mkdir "$work_dir/profiles"
printf '%s\n' "$main_link" > "$work_dir/profiles/main.link"
# Private and special-use names (pipe-probe.invalid among them) always go direct
# on the client, ahead of user rules, so the shared health probe is reached only
# by Pipe's own failover probes, which dial each tier directly.
cat > "$work_dir/shared-health.yaml" <<'YAML'
server: main
YAML
for tier in fast stealth rescue; do
  check="shared forced $tier tier"
  start_client "$work_dir/shared-health.yaml" "$tier"
  check_target
  stop_client
  pass "$check"
done

check='shared Fast rejects the wrong SPKI pin'
wrong_pin_link=$(python3 - "$work_dir/main.link" <<'PY'
import base64, pathlib, sys, urllib.parse
url = urllib.parse.urlsplit(pathlib.Path(sys.argv[1]).read_text().splitlines()[0])
query = urllib.parse.parse_qs(url.query)
pin = bytearray(base64.urlsafe_b64decode(query["pin"][0] + "="))
pin[0] ^= 1
query["pin"] = [base64.urlsafe_b64encode(pin).decode().rstrip("=")]
print(urllib.parse.urlunsplit(url._replace(query=urllib.parse.urlencode(query, doseq=True))))
PY
)
start_client "$wrong_pin_link" fast
if proxied_curl --max-time 4 "http://$target_addr:$target_port/" >/dev/null 2>&1; then
  fail "$check"
fi
stop_client
pass "$check"

check='shared HTTPS proxy rejects missing and wrong SNI'
if ip netns exec "$client_ns" curl --noproxy '*' --silent --insecure --max-time 5 \
  "https://$server_addr:$proxy_port/" >/dev/null; then
  fail "$check (bare-IP TLS handshake succeeded)"
fi
if ip netns exec "$client_ns" curl --noproxy '*' --silent --insecure --max-time 5 \
  --resolve "$cdn:$proxy_port:$server_addr" "https://$cdn:$proxy_port/" >/dev/null; then
  fail "$check (website SNI was accepted on the proxy port)"
fi
pass "$check"

source "$repo_dir/test/e2e/https-proxy.sh"
origin=$proxy_domain https_port=$proxy_port check_https_proxy

shared_https() {
  local name=$1 port=$2
  shift 2
  ip netns exec "$client_ns" curl --noproxy '*' --fail --silent --show-error --max-time 8 \
    --cacert "$work_dir/ca/ca.pem" --resolve "$name:$port:$server_addr" "$@" "https://$name:$port/"
}

# Stealth borrows our own HTTPS proxy site (D39): a visitor without a key gets
# that site's certificate and the same small website Fast shows.
check='shared Stealth and the HTTPS proxy serve the same cover over HTTP/1.1 and HTTP/2'
shared_https "$proxy_domain" "$stealth_port" --http1.1 --pinnedpubkey "$proxy_pin" > "$work_dir/shared-stealth.html"
cmp "$work_dir/proxy-site" "$work_dir/shared-stealth.html"
version=$(shared_https "$proxy_domain" "$proxy_port" --http2 --pinnedpubkey "$proxy_pin" \
  --output "$work_dir/shared-h2.html" --write-out '%{http_version}')
[[ $version == 2 ]]
cmp "$work_dir/proxy-site" "$work_dir/shared-h2.html"
pass "$check"

check='shared HTTP/3 serves the same cover'
python3 - "$state/server.json" > "$work_dir/fast-cert.der" <<'PY'
import base64
import json
import sys

with open(sys.argv[1]) as state:
    sys.stdout.buffer.write(base64.b64decode(json.load(state)["fast_certificate"]))
PY
ip netns exec "$client_ns" "$fixture" fetch-http3 "$server_addr:$https_port" \
  "https://$origin:$https_port/" "$work_dir/fast-cert.der" > "$work_dir/shared-h3.html"
cmp "$work_dir/proxy-site" "$work_dir/shared-h3.html"
pass "$check"

check='shared leaves the existing HTTP and HTTPS website intact'
body=$(shared_https "$cdn" 443 --pinnedpubkey "$website_pin")
[[ $body == 'existing website' ]]
body=$(ip netns exec "$client_ns" curl --noproxy '*' --fail --silent --show-error --max-time 8 "http://$server_addr/")
[[ $body == 'existing website' ]]
pass "$check"

check='shared Rescue gives a bare 404 without VMess authentication'
status=$(ip netns exec "$server_ns" curl --silent --show-error --max-time 5 --noproxy '*' \
  -H "Host: $cdn" -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Protocol: wrong' \
  -o "$work_dir/rescue-404" --write-out '%{http_code}' "http://$rescue_address$ws_path")
[[ $status == 404 && ! -s $work_dir/rescue-404 ]]
pass "$check"

check='shared revocation preflight'
for tier in fast stealth rescue; do
  start_client "$revoked_link" "$tier"
  check_target
  stop_client
done
"$bin" server revoke revoke-me --dir "$state" >/dev/null
wait_for_log "$server_pid" "$work_dir/server.log" 'Reloaded 1 device credentials' 8
for tier in fast stealth rescue; do
  check="shared revoked device is denied on $tier"
  start_client "$revoked_link" "$tier"
  if proxied_curl --max-time 5 "http://$target_addr:$target_port/" >/dev/null 2>&1; then fail "$check"; fi
  stop_client
  start_client "$main_link" "$tier"
  check_target
  stop_client
  pass "$check"
done

origin=$proxy_domain https_port=$proxy_port check_https_proxy_revocation

check='shared uninstall removes only the Fast hopping table'
ip netns exec "$server_ns" "$bin" server uninstall --dir "$state"
if ip netns exec "$server_ns" nft list table inet pipe > /dev/null 2>&1; then fail "$check"; fi
ip netns exec "$server_ns" nft list table inet pipe_fixture >/dev/null
pass "$check"
