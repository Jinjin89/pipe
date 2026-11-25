# SPDX-License-Identifier: GPL-3.0-or-later
# Sourced by run.sh for the relay scenario.

relay_topology() {
  relay_front=10.83.1.1
  client_addr=10.83.1.2
  relay_back=10.83.0.2
  relay_state=$work_dir/relay.conf
  relay_server2_addr=10.83.3.1
  # These public targets exist only in the fixture server namespaces.
  relay_target=11.83.0.1
  relay_target2=11.83.3.1
  ip netns add "$relay_ns"
  relay_ns_created=1
  ip netns add "$relay_server2_ns"
  relay_server2_ns_created=1
  ip netns exec "$relay_ns" sysctl -w net.ipv4.ip_forward=0 >/dev/null
  ip -n "$relay_ns" link add veth-rly-cli type veth peer name veth-cli netns "$client_ns"
  ip -n "$relay_ns" link add veth-rly-srv type veth peer name veth-srv netns "$server_ns"
  ip -n "$relay_ns" link add veth-rly-srv2 type veth peer name veth-srv netns "$relay_server2_ns"
  ip -n "$relay_ns" addr add "$relay_front/24" dev veth-rly-cli
  ip -n "$relay_ns" addr add "$relay_back/24" dev veth-rly-srv
  ip -n "$relay_ns" addr add 10.83.3.2/24 dev veth-rly-srv2
  ip -n "$client_ns" addr add "$client_addr/24" dev veth-cli
  ip -n "$server_ns" addr add "$server_addr/24" dev veth-srv
  ip -n "$server_ns" addr add "$relay_target/32" dev veth-srv
  ip -n "$relay_server2_ns" addr add "$relay_server2_addr/24" dev veth-srv
  ip -n "$relay_server2_ns" addr add "$relay_target2/32" dev veth-srv
  ip -n "$relay_server2_ns" addr add "$target_addr/32" dev lo
  ip -n "$relay_ns" link set lo up
  ip -n "$relay_ns" link set veth-rly-cli up
  ip -n "$relay_ns" link set veth-rly-srv up
  ip -n "$relay_ns" link set veth-rly-srv2 up
  ip -n "$client_ns" link set veth-cli up
  ip -n "$server_ns" link set veth-srv up
  ip -n "$relay_server2_ns" link set lo up
  ip -n "$relay_server2_ns" link set veth-srv up
  # Bring up the direct link now so IPv6 address setup settles before the fallback checks.
  ip -n "$server_ns" link add veth-direct-srv type veth peer name veth-direct-cli netns "$client_ns"
  ip -n "$server_ns" addr add 10.83.2.1/24 dev veth-direct-srv
  ip -n "$client_ns" addr add 10.83.2.2/24 dev veth-direct-cli
  ip -n "$server_ns" link set veth-direct-srv up
  ip -n "$client_ns" link set veth-direct-cli up
  ip -n "$client_ns" route add default via "$relay_front"
  ip -n "$relay_ns" route add default dev veth-rly-cli
  ip -n "$relay_ns" route add "$relay_target/32" via "$server_addr"
  ip -n "$relay_ns" route add "$relay_target2/32" via "$relay_server2_addr"
  ip -n "$relay_ns" route add "$target_addr/32" via "$server_addr"
  ip -n "$server_ns" route add "$client_addr/32" via "$relay_back"
}

relay_start_server2() {
  local state2=$1
  ip netns exec "$relay_server2_ns" "$bin" server init --mode shared --dir "$state2" \
    --domain "$relay_target2" --fast-sni "$origin" --fast-hop 25000-25003 >/dev/null
  printf '127.0.0.1 localhost\n%s %s\n' "$relay_server2_addr" "$proxy_domain" > "$work_dir/proxy-hosts2"
  ip netns exec "$relay_server2_ns" unshare --mount --propagation private -- bash -c '
    mount --bind "$1" /etc/hosts
    shift
    exec "$@"
  ' relay-proxy "$work_dir/proxy-hosts2" "$bin" server proxy enable --dir "$state2" --domain "$proxy_domain" \
    --cert "$work_dir/ca/$proxy_domain.pem" --key "$work_dir/ca/$proxy_domain-key.pem" >/dev/null

  ip netns exec "$relay_server2_ns" "$bin" server add main --dir "$state2" > "$work_dir/main2.link"
  : > "$work_dir/relay-server2.log"
  ip netns exec "$relay_server2_ns" "$bin" server run --dir "$state2" --test-ca "$work_dir/ca" \
    --test-ports --test-listen "$relay_server2_addr" >> "$work_dir/relay-server2.log" 2>&1 &
  relay_server2_pid=$!
  wait_for_log "$relay_server2_pid" "$work_dir/relay-server2.log" \
    "Server listening on $relay_server2_addr:443 (UDP Fast) and $relay_server2_addr:8443 (TCP Stealth)" 8
  wait_for_log "$relay_server2_pid" "$work_dir/relay-server2.log" \
    "HTTPS proxy listening on $relay_server2_addr:$proxy_port" 8

  : > "$work_dir/relay-target2.log"
  ip netns exec "$relay_server2_ns" python3 -u "$work_dir/target.py" "$target_addr" "$target_port" 'pipe e2e target 2' \
    >> "$work_dir/relay-target2.log" 2>&1 &
  relay_target2_pid=$!
  wait_for_log "$relay_target2_pid" "$work_dir/relay-target2.log" 'Target ready' 8
}

relay_node() {
  ip netns exec "$relay_ns" "$bin" relay "$@" --state "$relay_state"
}

relay_add_server() {
  local ns=$1 dir=$2 target=$3 line
  shift 3
  line=$(ip netns exec "$ns" "$bin" server relay-command --dir "$dir") || return
  [[ $line == "pipe relay add --to $target --tcp $stealth_port --udp $https_port,25000-25003" ]] || return
  local -a args
  read -r -a args <<<"$line"
  relay_node "${args[@]:2}" "$@"
}

relay_packets() {
  relay_node status | awk -v target="$1" -v protocol="$2" '
    $1 == target {
      for (i = 3; i+2 <= NF; i++) if ($i == protocol && $(i+2) == "packets") count = $(i+1)
    }
    END { print count+0 }
  '
}

relay_cover() {
  local ip=$1 port=$2
  ip netns exec "$client_ns" curl --noproxy '*' --fail --silent --show-error --max-time 6 \
    --cacert "$work_dir/ca/ca.pem" --pinnedpubkey "$proxy_pin" \
    --resolve "$proxy_domain:$port:$ip" "https://$proxy_domain:$port/"
}

relay_request_body() {
  local body
  body=$(proxied_curl --max-time 8 "http://$target_addr:$target_port/") || return 1
  [[ $body == "$1" ]]
}

check_relay_request() {
  if relay_request_body "$1"; then return; fi
  # A startup interface update can close the first in-flight request.
  grep -Fq ': network changed' "$work_dir/client.log" || return 1
  relay_request_body "$1"
}

relay_check_via() {
  local profile=$1 code=$2 target=$3 body=$4 tier protocol before
  for tier in fast stealth; do
    check="$tier through the relay to $target"
    protocol=TCP
    if [[ $tier == fast ]]; then protocol=UDP; fi
    before=$(relay_packets "$target" "$protocol")
    start_client "$profile" "$tier" global --relay "$code"
    check_relay_request "$body"
    wait_for_log "$client_pid" "$work_dir/client.log" "Relay $relay_front: in use" 8
    (( $(relay_packets "$target" "$protocol") > before ))
    stop_client
    pass "$check"
  done
}

relay_checks() {
  check='start the second shared server behind the relay'
  local state2=$work_dir/state2 second_link
  relay_start_server2 "$state2"
  IFS= read -r second_link < "$work_dir/main2.link"
  pass "$check"

  check='add two kernel relay routes from the server commands'
  command -v awk >/dev/null || fail 'missing awk'
  local initial_forwarding
  initial_forwarding=$(ip netns exec "$relay_ns" sysctl -n net.ipv4.ip_forward)
  # Only the first server has a direct hop path. The relay always sends to the base Fast port.
  ip netns exec "$server_ns" nft -f - <<RULES
table inet pipe_relay_fixture {
  chain prerouting {
    type nat hook prerouting priority dstnat - 1; policy accept;
    ip daddr $relay_target tcp dport { $stealth_port, $proxy_port } dnat ip to $server_addr
    ip daddr $relay_target udp dport { $https_port, 25000-25003 } dnat ip to $server_addr:$https_port
  }
}
RULES
  ip netns exec "$relay_server2_ns" nft -f - <<RULES
table inet pipe_relay_fixture {
  chain prerouting {
    type nat hook prerouting priority dstnat - 1; policy accept;
    ip daddr $relay_target2 tcp dport $stealth_port dnat ip to $relay_server2_addr
    ip daddr $relay_target2 udp dport $https_port dnat ip to $relay_server2_addr:$https_port
  }
}
RULES
  if ip netns exec "$relay_ns" "$bin" relay status > "$work_dir/default-state.out" 2>&1; then
    fail "$check (default state allowed in a separate namespace)"
  fi
  grep -Fq 'requires a non-default --state file' "$work_dir/default-state.out"
  local output code1 code2
  output=$(relay_add_server "$server_ns" "$state" "$relay_target" 2>"$work_dir/relay-host.log")
  grep -Fq 'Use --host' "$work_dir/relay-host.log"
  code1=${output%%$'\n'*}
  [[ $output == "$relay_front"$'\n'"Open on this VPS: TCP $stealth_port, UDP 25000-25003" ]]
  output=$(relay_add_server "$relay_server2_ns" "$state2" "$relay_target2" --host "$relay_front")
  code2=${output%%$'\n'*}
  [[ $output == "$relay_front:8444/25004-25007"$'\n'"Open on this VPS: TCP 8444, UDP 25004-25007" ]]
  [[ $(relay_add_server "$server_ns" "$state" "$relay_target" --host "$relay_front") == "$code1"$'\n'"Open on this VPS: TCP $stealth_port, UDP 25000-25003" ]]
  [[ $(relay_add_server "$relay_server2_ns" "$state2" "$relay_target2" --host "$relay_front") == "$output" ]]
  mkdir "$work_dir/profiles"
  pass "$check"

  check='apply saved relay state before routes exist'
  ip netns exec "$relay_ns" nft delete table inet pipe_relay
  grep -Fq 'no kernel table' <<<"$(relay_node status)"
  ip -n "$relay_ns" route del default
  ip -n "$relay_ns" route del "$relay_target/32"
  ip -n "$relay_ns" route del "$relay_target2/32"
  # In this fixture there is no boot sysctl file, so restore the baseline of a fresh boot.
  ip netns exec "$relay_ns" sysctl -w "net.ipv4.ip_forward=$initial_forwarding" >/dev/null
  relay_node apply
  ip -n "$relay_ns" route add default dev veth-rly-cli
  ip -n "$relay_ns" route add "$relay_target/32" via "$server_addr"
  ip -n "$relay_ns" route add "$relay_target2/32" via "$relay_server2_addr"
  pass "$check"

  relay_check_via "$main_link" "$code1" "$relay_target" 'pipe e2e target'
  relay_check_via "$second_link" "$code2" "$relay_target2" 'pipe e2e target 2'

  local tier protocol before body direct_body
  check='unauthenticated TLS visitors see each server’s own cover through the relay'
  relay_cover "$relay_front" "$stealth_port" > "$work_dir/relay-cover1.html"
  relay_cover "$relay_front" 8444 > "$work_dir/relay-cover2.html"
  check_cover_page "$work_dir/relay-cover1.html"
  check_cover_page "$work_dir/relay-cover2.html"
  [[ $(cover_title "$work_dir/relay-cover1.html") != $(cover_title "$work_dir/relay-cover2.html") ]]
  body=$(cat "$work_dir/relay-cover1.html")
  pass "$check"

  check='the relay does not forward other ports or destinations'
  before=$(relay_packets "$relay_target" TCP)
  if relay_cover "$relay_front" "$proxy_port" >/dev/null 2>&1; then fail "$check (proxy port)"; fi
  if relay_cover "$relay_target" "$stealth_port" >/dev/null 2>&1; then fail "$check (direct route)"; fi
  : > "$work_dir/cover.log"
  ip netns exec "$server_ns" python3 -u "$work_dir/target.py" "$target_addr" "$stealth_port" 'other host' \
    >> "$work_dir/cover.log" 2>&1 &
  cover_pid=$!
  wait_for_log "$cover_pid" "$work_dir/cover.log" 'Target ready' 8
  if ip netns exec "$client_ns" curl --noproxy '*' --silent --fail --max-time 3 \
    "http://$target_addr:$stealth_port/" >/dev/null; then fail "$check (other host)"; fi
  (( $(relay_packets "$relay_target" TCP) == before ))
  pass "$check"

  check='remove only the first relay route and open its direct path'
  relay_node remove --to "$relay_target"
  output=$(relay_node status)
  [[ $output != *"$relay_target "* && $output == "$relay_target2 $code2 "* ]]
  [[ $(ip netns exec "$relay_ns" sysctl -n net.ipv4.ip_forward) == 1 ]]
  # The client binds off-link sockets to the default interface.
  ip -n "$client_ns" route replace default via 10.83.2.1
  direct_body=$(relay_cover "$relay_target" "$stealth_port")
  [[ $body == "$direct_body" ]]
  relay_cover "$relay_target" "$proxy_port" >/dev/null
  pass "$check"

  for tier in fast stealth; do
    check="$tier falls back to the direct server after route removal"
    start_client "$main_link" "$tier" global --relay "$code1"
    check_relay_request 'pipe e2e target'
    wait_for_log "$client_pid" "$work_dir/client.log" "Relay $relay_front: not reachable, going direct" 8
    stop_client
    pass "$check"
  done
  relay_check_via "$second_link" "$code2" "$relay_target2" 'pipe e2e target 2'

  for tier in fast stealth; do
    check="$tier rejects a relay code for the other server"
    start_client "$main_link" "$tier" global --relay "$code2"
    check_relay_request 'pipe e2e target'
    wait_for_log "$client_pid" "$work_dir/client.log" "Relay $relay_front: not reachable, going direct" 8
    stop_client
    pass "$check"
  done

  check='ordinary listeners on the vacated relay ports'
  : > "$work_dir/wrong-relay.log"
  ip netns exec "$relay_ns" python3 -u "$repo_dir/test/e2e/wrong_relay.py" "$relay_front" \
    "$stealth_port" "$https_port" 25000 25001 25002 25003 >> "$work_dir/wrong-relay.log" 2>&1 &
  wrong_relay_pid=$!
  wait_for_log "$wrong_relay_pid" "$work_dir/wrong-relay.log" 'Wrong relay ready' 8
  for tier in fast stealth; do
    check="$tier falls back from a relay running an ordinary listener"
    protocol=TCP
    if [[ $tier == fast ]]; then protocol=UDP; fi
    start_client "$main_link" "$tier" global --relay "$code1"
    check_relay_request 'pipe e2e target'
    wait_for_log "$wrong_relay_pid" "$work_dir/wrong-relay.log" "$protocol received" 8
    wait_for_log "$client_pid" "$work_dir/client.log" "Relay $relay_front: not reachable, going direct" 8
    stop_client
    pass "$check"
  done
  stop_pid "$wrong_relay_pid"
  wrong_relay_pid=

  relay_ipv6_sysctls

  check='removing the last route removes state and restores forwarding'
  relay_node remove --to "$relay_target2"
  relay_node remove
  [[ ! -e $relay_state ]]
  [[ $(relay_node status) == 'Pipe relay is not installed.' ]]
  [[ $(ip netns exec "$relay_ns" sysctl -n net.ipv4.ip_forward) == "$initial_forwarding" ]]
  pass "$check"

  check='existing routed traffic continues with the relay installed'
  ip -n "$client_ns" route replace default via "$relay_front"
  ip netns exec "$relay_ns" sysctl -w net.ipv4.ip_forward=1 >/dev/null
  relay_add_server "$server_ns" "$state" "$relay_target" --host "$relay_front"
  [[ $(ip netns exec "$client_ns" curl --noproxy '*' --silent --fail --max-time 3 \
    "http://$target_addr:$stealth_port/") == 'other host' ]]
  relay_node remove
  [[ ! -e $relay_state ]]
  [[ $(ip netns exec "$relay_ns" sysctl -n net.ipv4.ip_forward) == 1 ]]
  ip netns exec "$relay_ns" sysctl -w "net.ipv4.ip_forward=$initial_forwarding" >/dev/null
  pass "$check"
}

relay_ipv6_sysctls() {
  check='removing the last IPv6 route restores accept_ra with IPv4 still active'
  local conf=net/ipv6/conf/veth-rly-srv
  if [[ $(ip netns exec "$relay_ns" sysctl -e -n "$conf/disable_ipv6") != 0 ||
        $(ip netns exec "$server_ns" sysctl -e -n net/ipv6/conf/veth-srv/disable_ipv6) != 0 ]]; then
    printf 'SKIP %s (IPv6 is disabled in the fixture)\n' "$check"
    return
  fi
  # The target and the matching on-link route exist only in these namespaces.
  local ipv6_target=2606:4700:83::1 forwarding=net.ipv6.conf.all.forwarding output
  ip -n "$server_ns" -6 addr add "$ipv6_target/64" dev veth-srv nodad
  ip -n "$relay_ns" -6 addr add 2606:4700:83::2/64 dev veth-rly-srv nodad
  ip netns exec "$relay_ns" sysctl -w "$forwarding=0" "$conf/accept_ra=1" >/dev/null
  for _ in 1 2; do
    output=$(relay_node add --to "$ipv6_target" --tcp "$stealth_port")
    [[ $output == "[2606:4700:83::2]:$stealth_port"$'\n'"Open on this VPS: TCP $stealth_port" ]]
    [[ $(ip netns exec "$relay_ns" sysctl -n "$conf/accept_ra") == 2 ]]
    [[ $(ip netns exec "$relay_ns" sysctl -n "$forwarding") == 1 ]]
  done
  relay_node remove --to "$ipv6_target"
  [[ $(ip netns exec "$relay_ns" sysctl -n "$conf/accept_ra") == 1 ]]
  [[ $(ip netns exec "$relay_ns" sysctl -n "$forwarding") == 0 ]]
  [[ $(ip netns exec "$relay_ns" sysctl -n net.ipv4.ip_forward) == 1 ]]
  ip -n "$relay_ns" -6 addr del 2606:4700:83::2/64 dev veth-rly-srv
  ip -n "$server_ns" -6 addr del "$ipv6_target/64" dev veth-srv
  pass "$check"
}
