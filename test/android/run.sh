#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set +x
set -Eeuo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd -- "$repo"
check=prerequisites
lab=
server_pid=
target_pid=
emulator_pid=
request_pid=
pss_pid=
switch_pid=
adb_started=0
device=()

app_denials() {
  awk -v pid="${vpn_process:-}" -v uid="${app_uid:-}" '
    /avc: +denied/ && (/io\.pipe\.app/ ||
      (pid != "" && $3 == pid) ||
      (pid != "" && $0 ~ ("(^|[[:space:]])pid=" pid "([^0-9]|$)")) ||
      (uid != "" && $0 ~ ("(^|[[:space:]])uid=" uid "([^0-9]|$)")))
  ' "$1"
}

write_diagnostics() (
  trap - ERR
  set +e
  local failure=$1 diagnostic_lab=$lab output copy
  if [[ -z $diagnostic_lab ]]; then
    diagnostic_lab=$(mktemp -d /tmp/pipe-android-diag.XXXXXX) || return
  fi
  output=$diagnostic_lab/diagnostics.txt
  {
    printf 'FAIL %s\n' "$failure"
    if (( adb_started )); then
      printf '\nAndroid interfaces\n'
      timeout 5 "${device[@]}" shell ls /sys/class/net
      printf '\nAndroid VPN connectivity\n'
      timeout 8 "${device[@]}" shell dumpsys connectivity | grep -i vpn
      printf '\nAndroid UI text\n'
      if timeout 8 "${device[@]}" shell uiautomator dump "$guest_ui" >/dev/null 2>&1; then
        timeout 5 "${device[@]}" exec-out cat "$guest_ui" > "$diagnostic_lab/diagnostic-ui.xml"
      fi
      python3 - "$diagnostic_lab/diagnostic-ui.xml" "$diagnostic_lab/ui.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET

for path in sys.argv[1:]:
    try:
        for node in ET.parse(path).iter("node"):
            if text := node.get("text"):
                print(text)
        break
    except (OSError, ET.ParseError):
        pass
PY
      printf '\nAndroid logcat (Pipe and SELinux denials)\n'
      timeout 10 "${device[@]}" logcat -b all -d -v threadtime 2>&1 |
        grep -E 'io\.pipe\.app|avc: +denied' | tail -n 200
    fi
    for log in "$diagnostic_lab"/{server,avd,emulator,target,switch}.log "$diagnostic_lab"/*.{client,sockets}.log; do
      if [[ -f $log ]]; then
        printf '\n%s\n' "${log##*/}"
        tail -n 100 "$log"
      fi
    done
  } 2>&1 | sed -E 's@pipe://[^[:space:]]+@<redacted profile>@g' > "$output"
  copy=$(mktemp /tmp/pipe-android-last-diag.XXXXXX) || return
  if cp -- "$output" "$copy" && mv -Tf -- "$copy" /tmp/pipe-android-last-diag.txt; then
    printf 'Diagnostics saved to /tmp/pipe-android-last-diag.txt\n' >&2
  else
    rm -f -- "$copy"
  fi
  if [[ -z $lab ]]; then rm -rf -- "$diagnostic_lab"; fi
)

fail() {
  trap - ERR
  write_diagnostics "$1" || true
  printf 'FAIL %s\n' "$1" >&2
  exit 1
}

pass() { printf 'PASS %s\n' "$1"; }

check_memory() {
  local available
  available=$(awk '$1 == "MemAvailable:" {print $2; exit}' /proc/meminfo)
  [[ $available =~ ^[0-9]+$ ]] && (( available >= 3 * 1024 * 1024 )) ||
    fail 'the emulator requires at least 3 GiB of available host RAM'
}

[[ $EUID == 0 ]] || fail 'root is required for the isolated host network namespace'
[[ -r /dev/kvm && -w /dev/kvm ]] || fail 'KVM is required'
check_memory
for tool in ip unshare mount ss timeout python3; do
  command -v "$tool" >/dev/null || fail "missing $tool"
done
if [[ ${1:-} != --isolated ]]; then
  # Keep emulator NAT, ADB, and both targets on loopback in a fresh namespace.
  # The guest reaches the namespace's loopback as 10.0.2.2.
  parent_network=$(readlink /proc/self/ns/net)
  shopt -s execfail
  exec unshare --net -- "$repo/test/android/run.sh" --isolated "$parent_network" ||
    fail 'could not start the isolated emulator lab'
fi
[[ -n ${2:-} && $(readlink /proc/self/ns/net) != "$2" && ! /proc/self/ns/net -ef /proc/1/ns/net ]] ||
  fail 'the emulator lab requires a separate network namespace'
trap '[[ $BASHPID != $$ ]] || fail "$check (line $LINENO)"' ERR

export ANDROID_HOME=${ANDROID_HOME:-/opt/android-sdk}
export JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}
adb=$ANDROID_HOME/platform-tools/adb
emulator=$ANDROID_HOME/emulator/emulator
avdmanager=$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager
image='system-images;android-36;google_apis;x86_64'
apk=${PIPE_ANDROID_APK:-$repo/android/app/build/outputs/apk/debug/app-x86_64-debug.apk}
package=io.pipe.app
activity=$package/.MainActivity
origin_host=origin.pipe.test
fast_sni=fast.pipe.test
https_port=18443
target_addr=11.0.0.80
target_port=18081
direct_port=18082
target_name=other.split.example.net
guest_ui=/data/local/tmp/pipe-ui.xml
adb_host=("$adb" -P 5037)
device=("${adb_host[@]}" -s emulator-5554)

for tool in "$adb" "$emulator" "$avdmanager" "$JAVA_HOME/bin/java"; do
  [[ -x $tool ]] || fail "missing $tool"
done
[[ -d $ANDROID_HOME/system-images/android-36/google_apis/x86_64 ]] || fail "missing emulator image $image"
[[ -s $apk ]] || fail 'build the x86_64 debug APK first'

stop_pid() {
  local pid=$1 deadline=$((SECONDS + 15))
  [[ -n $pid ]] || return 0
  if kill -TERM "$pid" 2>/dev/null; then
    while kill -0 "$pid" 2>/dev/null; do
      if (( SECONDS >= deadline )); then
        kill -KILL "$pid" 2>/dev/null || true
        break
      fi
      sleep .1
    done
  fi
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  trap - ERR
  stop_pid "$switch_pid"
  stop_pid "$pss_pid"
  stop_pid "$request_pid"
  if (( adb_started )); then
    timeout 5 "${device[@]}" emu kill >/dev/null 2>&1 || true
  fi
  stop_pid "$emulator_pid"
  if (( adb_started )); then
    timeout 5 "${adb_host[@]}" kill-server >/dev/null 2>&1 || true
  fi
  stop_pid "$server_pid"
  stop_pid "$target_pid"
  rm -rf -- "$lab"
}

lab=$(mktemp -d /tmp/pipe-android-e2e.XXXXXX)
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export ANDROID_USER_HOME="$lab/android" ANDROID_EMULATOR_HOME="$lab/android"
unset ANDROID_PREFS_ROOT
export ANDROID_AVD_HOME="$lab/android/avd"
export ANDROID_ADB_LOG_PATH="$lab/adb.log"
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Duser.home=$lab/java"
mkdir -p "$ANDROID_AVD_HOME" "$lab/java"

if [[ -n ${PIPE_BIN:-} ]]; then
  pipe=$(realpath -- "$PIPE_BIN")
  [[ -x $pipe ]] || fail 'PIPE_BIN is not executable'
else
  pipe=$lab/pipe
  (
    export PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
    export GOFLAGS=-mod=mod GOCACHE=/tmp/pipe-gocache CGO_ENABLED=0
    go build -buildvcs=false -trimpath -tags with_gvisor,with_quic,with_utls,with_acme,badlinkname,tfogo_checklinkname0 \
      -ldflags '-s -w -checklinkname=0' -o "$pipe" ./cmd/pipe
  )
fi

wait_log() {
  local pid=$1 log=$2 line=$3 deadline=$((SECONDS + $4))
  while (( SECONDS < deadline )); do
    kill -0 "$pid" 2>/dev/null || return 1
    if grep -Fxq -- "$line" "$log"; then return 0; fi
    sleep .1
  done
  return 1
}

check='isolated Pipe server and HTTP targets'
ip link set lo up
ip addr add "$target_addr/32" dev lo
cat > "$lab/target.py" <<'PY'
import pathlib
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

address, target_port, direct_port, work = sys.argv[1:]
work = pathlib.Path(work)


class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/switch/"):
            self.check_switch_connection()
            return
        tier = self.path.removeprefix("/")
        if tier not in ("fast", "stealth", "rescue"):
            self.send_error(404)
            return
        print("Request " + tier, flush=True)
        # Keep the socket open while the runner verifies its owning process.
        deadline = time.monotonic() + 9
        while not (work / (tier + ".forwarded")).exists():
            if time.monotonic() >= deadline:
                self.send_error(504)
                return
            time.sleep(0.05)
        respond(self, "pipe android target " + tier)

    def check_switch_connection(self):
        # Check the peer port of this specific HTTP connection.
        peer_port = self.client_address[1]
        sockets = subprocess.check_output(
            ["ss", "-Hntp", "sport", "=", f":{peer_port}", "and", "dport", "=", f":{target_port}"],
            text=True,
        )
        pid = (work / "server.pid").read_text().strip()
        if f"pid={pid}," in sockets:
            respond(self, "switch via Pipe")
        elif "pid=" in sockets:
            print("Direct " + self.path, flush=True)
            respond(self, "switch direct")
        else:
            self.send_error(503)


class Direct(BaseHTTPRequestHandler):
    def do_GET(self):
        respond(self, "pipe android host")


def respond(handler, body):
    payload = (body + "\n").encode()
    handler.send_response(200)
    handler.send_header("Content-Type", "text/plain")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


with ThreadingHTTPServer((address, int(target_port)), Target) as target:
    with ThreadingHTTPServer(("127.0.0.1", int(direct_port)), Direct) as direct:
        threading.Thread(target=direct.serve_forever, daemon=True).start()
        print("Targets ready", flush=True)
        target.serve_forever()
PY
: > "$lab/target.log"
python3 -u "$lab/target.py" "$target_addr" "$target_port" "$direct_port" "$lab" >> "$lab/target.log" 2>&1 &
target_pid=$!
wait_log "$target_pid" "$lab/target.log" 'Targets ready' 8

# A distinct Fast TLS name makes enrollment carry explicit M3 endpoint details.
"$pipe" server init --dir "$lab/state" --domain "$origin_host" --fast-sni "$fast_sni" \
  --cdn-domain cdn.pipe.test >/dev/null
"$pipe" server add android-e2e --dir "$lab/state" --test-ports > "$lab/device.link"
IFS= read -r profile < "$lab/device.link"
[[ $profile == pipe://* && $profile != *"'"* ]] || fail 'unexpected test profile format'
: > "$lab/server.log"
"$pipe" server run --dir "$lab/state" --test-ca "$lab/ca" --test-ports \
  --test-hosts "$target_name=$target_addr" >> "$lab/server.log" 2>&1 &
server_pid=$!
printf '%s\n' "$server_pid" > "$lab/server.pid"
wait_log "$server_pid" "$lab/server.log" "Server listening on 127.0.0.1:$https_port (TCP and UDP)" 8
pass "$check"

check='boot the offline Android 36 emulator'
printf 'no\n' | "$avdmanager" create avd --name pipe-e2e -k "$image" \
  --path "$ANDROID_AVD_HOME/pipe-e2e.avd" > "$lab/avd.log" 2>&1 ||
  fail "$check (avdmanager could not create the AVD)"
"$adb" keygen "$ANDROID_USER_HOME/adbkey" >/dev/null
export ADB_VENDOR_KEYS="$ANDROID_USER_HOME/adbkey"
# The packaged ADB also looks under the login home for its default key. Give
# its server a temporary home mount scoped to the server's mount namespace.
mkdir -p "$lab/adb-home"
ln -s "$ANDROID_USER_HOME" "$lab/adb-home/.android"
adb_started=1
timeout 15 unshare --mount --propagation private -- bash -c '
  mount --bind "$1" "$2" || exit
  shift 2
  exec "$@"
' adb-server "$lab/adb-home" "$HOME" "${adb_host[@]}" start-server >/dev/null
check_memory
"$emulator" -avd pipe-e2e -ports 5554,5555 -no-window -no-audio -no-boot-anim \
  -no-snapshot -gpu swiftshader_indirect -accel on -memory 1536 -cores 2 > "$lab/emulator.log" 2>&1 &
emulator_pid=$!
timeout 150 "${device[@]}" wait-for-device
boot_deadline=$((SECONDS + 240))
until [[ $(timeout 5 "${device[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r') == 1 ]]; do
  (( SECONDS < boot_deadline )) && kill -0 "$emulator_pid" 2>/dev/null || fail "$check"
  sleep 2
done
"${device[@]}" shell input keyevent KEYCODE_WAKEUP
"${device[@]}" shell wm dismiss-keyguard
"${device[@]}" shell wm size 1080x1920
"${device[@]}" shell wm density 320
"${device[@]}" shell settings put global hide_error_dialogs 1
"${device[@]}" shell settings put global window_animation_scale 0
"${device[@]}" shell settings put global transition_animation_scale 0
"${device[@]}" shell settings put global animator_duration_scale 0
sleep 20
pass "$check"

check='install debug APK and grant VPN consent'
timeout 60 "${device[@]}" install "$apk" > "$lab/install.log"
app_uid=$("${device[@]}" shell cmd package list packages -U "$package" | tr -d '\r' |
  awk -v package="package:$package" '$1 == package && $2 ~ /^uid:[0-9]+$/ {sub(/^uid:/, "", $2); print $2}')
[[ $app_uid =~ ^[0-9]+$ ]] || fail "$check (could not identify the app UID)"
"${device[@]}" shell appops set "$package" ACTIVATE_VPN allow
"${device[@]}" shell pm grant "$package" android.permission.POST_NOTIFICATIONS
# The test uses the VPN's resolver directly through the Android system path.
"${device[@]}" shell settings put global private_dns_mode off
"${device[@]}" shell run-as "$package" mkdir -p no_backup
"${device[@]}" shell -T "run-as $package sh -c 'cat > no_backup/test-ca.pem'" < "$lab/ca/ca.pem"
printf '10.0.2.2\n' | "${device[@]}" shell -T "run-as $package sh -c 'cat > no_backup/test-address'"
pass "$check"

ui_node() {
  local kind=$1 value=$2 deadline=$((SECONDS + ${3:-45})) want=${4:-present}
  local dump_timeout=20 read_timeout=5
  while (( SECONDS < deadline )); do
    if [[ $want == absent ]]; then
      dump_timeout=$((deadline - SECONDS))
      (( dump_timeout > 0 )) || break
    fi
    if timeout "$dump_timeout" "${device[@]}" shell uiautomator dump "$guest_ui" >/dev/null 2>&1 &&
      { [[ $want == present ]] || (( (read_timeout = deadline - SECONDS) > 0 )); } &&
      timeout "$read_timeout" "${device[@]}" exec-out cat "$guest_ui" > "$lab/ui.xml" &&
      python3 - "$lab/ui.xml" "$kind" "$value" "$want" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET

file, kind, expected, want = sys.argv[1:]
try:
    root = ET.parse(file).getroot()
except (OSError, ET.ParseError):
    sys.exit(1)
if root.tag != "hierarchy":
    sys.exit(1)
for node in root.iter("node"):
    text = node.get("text", "")
    resource = node.get("resource-id", "")
    if kind == "status":
        matched = resource == "io.pipe.app:id/status" and text.startswith(expected)
    elif kind == "detail":
        matched = resource == "io.pipe.app:id/detail" and expected in text
    elif kind == "id":
        matched = resource == "io.pipe.app:id/" + expected
    elif kind == "contains":
        matched = expected in text
    elif kind == "lines":
        matched = set(expected.splitlines()).issubset(text.splitlines())
    else:
        matched = text.casefold() == expected.casefold()
    if not matched:
        continue
    if want == "absent":
        sys.exit(1)
    if node.get("enabled") != "true":
        continue
    bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
    if bounds:
        left, top, right, bottom = map(int, bounds.groups())
        if right > left and bottom > top:
            print((left + right) // 2, (top + bottom) // 2)
            sys.exit(0)
sys.exit(0 if want == "absent" else 1)
PY
    then
      return 0
    fi
    sleep .2
  done
  return 1
}

ui_gone() {
  ui_node "$1" "$2" "${3:-20}" absent
}

tap() {
  local at x y
  at=$(ui_node "$@") || { cp -f "$lab/ui.xml" /tmp/pipe-android-last-ui.xml 2>/dev/null || true; fail "$check (missing $2)"; }
  read -r x y <<< "$at"
  "${device[@]}" shell input tap "$x" "$y"
}

open_profile() {
  local raw=${1:-$profile}
  # Pass the temporary link on stdin and keep Android's intent output private.
  printf "am start -W -a android.intent.action.VIEW -d '%s' -n '%s'\n" "$raw" "$activity" |
    timeout 20 "${device[@]}" shell -T sh > "$lab/import.log" 2>&1
}

check='confirm deep-link import before saving'
open_profile
ui_node text 'Confirm profile import' >/dev/null
ui_node lines "Fast: $origin_host:$https_port (TLS name $fast_sni)
Stealth: $origin_host:$https_port" >/dev/null
open_profile
ui_node text 'Confirm profile import' >/dev/null
if "${device[@]}" shell run-as "$package" test -f no_backup/profiles.enc; then
  fail "$check (profile saved before confirmation)"
fi
tap text Cancel
ui_gone text 'Confirm profile import' ||
  fail "$check (an earlier import dialog is still open)"
ui_node text 'No server imported' >/dev/null
open_profile
ui_node text 'Confirm profile import' >/dev/null
tap text Add
ui_gone text 'Confirm profile import' || fail "$check (the import dialog did not close)"
ui_node text android-e2e >/dev/null
"${device[@]}" shell run-as "$package" test -s no_backup/profiles.enc
pass "$check"

check='explicitly replace unreadable encrypted profiles'
printf 'corrupt test profile' |
  "${device[@]}" shell -T "run-as $package sh -c 'cat > no_backup/profiles.enc'"
open_profile
ui_node contains 'Saved profiles are unreadable' >/dev/null
tap text Cancel
ui_gone text 'Confirm profile import' || fail "$check (the import dialog did not close)"
[[ $("${device[@]}" exec-out run-as "$package" cat no_backup/profiles.enc) == 'corrupt test profile' ]]
open_profile
tap text Replace
ui_gone text 'Confirm profile import' || fail "$check (the import dialog did not close)"
ui_node text android-e2e >/dev/null
"${device[@]}" shell run-as "$package" test -s no_backup/profiles.enc
pass "$check"

guest_http() (
  local addr=$1 port=$2 path=$3 host=$4
  local input=$lab/http.stdin request_fd
  # Toybox nc sends a TCP FIN when stdin reaches EOF. Keep its input open
  # until the server sends the HTTP response and closes the connection.
  mkfifo -- "$input"
  exec {request_fd}<>"$input"
  rm -- "$input"
  printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$path" "$host" >&"$request_fd"
  timeout 16 "${device[@]}" shell -T "toybox nc -w 12 $addr $port" <&"$request_fd"
)

check_body() {
  python3 - "$1" "$2" <<'PY'
import pathlib
import sys

response = pathlib.Path(sys.argv[1]).read_bytes()
head, _, body = response.partition(b"\r\n\r\n")
if not head.startswith(b"HTTP/1.0 200 ") or body != (sys.argv[2] + "\n").encode():
    sys.exit("unexpected HTTP response from the test target")
PY
}

select_tier() {
  tap id tab_routing
  tap id "tier_${1,,}"
  tap id tab_home
  ui_node id connect >/dev/null
}

vpn_interfaces() {
  local interfaces
  interfaces=$(timeout 5 "${device[@]}" shell -T ls /sys/class/net) || return 1
  tr -d '\r' <<< "$interfaces" | awk '/^tun[0-9]+$/'
}

tun_present() {
  local interfaces
  interfaces=$(vpn_interfaces) || fail "$check (could not list Android interfaces)"
  [[ -n $interfaces ]]
}

wait_for_tun_replacement() {
  local previous=$1 current deadline=$((SECONDS + 15))
  while true; do
    current=$(vpn_interfaces)
    [[ -n $current ]] || fail "$check (the VPN had no TUN during replacement)"
    if [[ $current =~ ^tun[0-9]+$ && $current != "$previous" ]]; then return; fi
    (( SECONDS < deadline )) || fail "$check (the replacement TUN did not appear)"
    sleep .2
  done
}

vpn_pss() {
  timeout 10 "${device[@]}" shell dumpsys meminfo "$vpn_process" | awk '
    $1 == "TOTAL" && $2 == "PSS:" {pss=$3}
    $1 == "TOTAL" && $2 ~ /^[0-9]+$/ {total=$2}
    END {
      if (pss ~ /^[0-9]+$/) print pss
      else if (total ~ /^[0-9]+$/) print total
      else exit 1
    }
  '
}

resolve_fake_ip() {
  local lookup
  lookup=$(timeout 12 "${device[@]}" shell ping -c 1 -W 1 "$target_name" 2>&1) || true
  if [[ $lookup =~ \((198\.1[89]\.[0-9]+\.[0-9]+)\) ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  else
    return 1
  fi
}

fetch_through_server() {
  local tier=$1 fake_ip=$2 sockets deadline
  (trap - ERR; guest_http "$fake_ip" "$target_port" "/$tier" "$target_name") \
    > "$lab/$tier.http" 2> "$lab/$tier.client.log" &
  request_pid=$!
  deadline=$((SECONDS + 8))
  until [[ -f $lab/$tier.forwarded ]]; do
    kill -0 "$request_pid" 2>/dev/null || fail "$check (guest HTTP exited before the forwarding check)"
    (( SECONDS < deadline )) || fail "$check (could not verify the Pipe server's target socket)"
    if grep -Fxq -- "Request $tier" "$lab/target.log"; then
      sockets=$(ss -Hntp dst "$target_addr:$target_port")
      printf '%s\n' "$sockets" > "$lab/$tier.sockets.log"
      if [[ $sockets == *"pid=$server_pid,"* ]]; then
        : > "$lab/$tier.forwarded"
      fi
    fi
    sleep .05
  done
  wait "$request_pid"
  request_pid=
  check_body "$lab/$tier.http" "pipe android target $tier"
}

check='forced Fast over the Android VPN'
select_tier Fast
tap id connect
ui_node detail '· Fast' >/dev/null
tun_present
vpn_process=$(timeout 5 "${device[@]}" shell pidof "$package:vpn" | tr -d '\r')
[[ $vpn_process =~ ^[0-9]+$ ]]
fake_ip=$(resolve_fake_ip) || fail 'DNS through the Android VPN did not return a FakeIP'
pass 'DNS through the Android VPN returns a FakeIP'
fetch_through_server fast "$fake_ip"
pass "$check"

for tier in Stealth Rescue; do
  check="forced $tier over the Android VPN"
  select_tier "$tier"
  ui_node detail "· $tier" >/dev/null
  [[ $(timeout 5 "${device[@]}" shell pidof "$package:vpn" | tr -d '\r') == "$vpn_process" ]]
  fake_ip=$(resolve_fake_ip) || fail "$check (DNS lookup failed)"
  fetch_through_server "${tier,,}" "$fake_ip"
  pass "$check"
done

check='replacing the tunnel for IPv6 and per-app changes'
cached_fake_ip=$fake_ip
previous_tun=$(vpn_interfaces)
[[ $previous_tun =~ ^tun[0-9]+$ ]]
tap id tab_settings
tap id open_apps
tap id ipv6
tap id per_app
tap text 'Bypass selected'

# Probe an address that the emulator can also reach directly. The target
# identifies each connection's owner, including any connection that bypasses
# the VPN. A connection that entered the old TUN may close at handover.
(
  trap - ERR
  attempt=0
  until [[ -e $lab/switch.stop ]]; do
    active_tuns=$(vpn_interfaces)
    [[ -n $active_tuns ]] || { printf 'No TUN during replacement\n'; exit 1; }
    (( attempt += 1 ))
    if guest_http "$target_addr" "$target_port" "/switch/$attempt" "$target_name" > "$lab/switch.http" &&
       check_body "$lab/switch.http" 'switch via Pipe'; then
      : > "$lab/switch.ready"
      if [[ $active_tuns != *"$previous_tun"* ]]; then : > "$lab/switch.new"; fi
    elif [[ $active_tuns != *"$previous_tun"* ]]; then
      printf 'A fresh connection on the replacement TUN failed\n'
      exit 1
    fi
    sleep .05
  done
) > "$lab/switch.log" 2>&1 &
switch_pid=$!
deadline=$((SECONDS + 12))
until [[ -e $lab/switch.ready ]]; do
  (( SECONDS < deadline )) && kill -0 "$switch_pid" 2>/dev/null || fail "$check (no initial probe)"
  sleep .05
done
tap id save
tap id tab_home
wait_for_tun_replacement "$previous_tun"
ui_node detail '· Rescue' >/dev/null
[[ $(timeout 5 "${device[@]}" shell pidof "$package:vpn" | tr -d '\r') == "$vpn_process" ]]
deadline=$((SECONDS + 12))
until [[ -e $lab/switch.new ]]; do
  (( SECONDS < deadline )) && kill -0 "$switch_pid" 2>/dev/null ||
    fail "$check (no successful fresh connection on the replacement TUN)"
  sleep .05
done
: > "$lab/switch.stop"
wait "$switch_pid" || fail "$check (continuous probe failed)"
switch_pid=
guest_http "$cached_fake_ip" "$target_port" /switch/cached "$target_name" > "$lab/switch-cached.http"
check_body "$lab/switch-cached.http" 'switch via Pipe'
if grep -q '^Direct /switch/' "$lab/target.log"; then
  fail "$check (traffic bypassed the VPN)"
fi
pass "$check"

check='mode switch within the 90 MB VPN PSS budget'
previous_tun=$(vpn_interfaces)
[[ $previous_tun =~ ^tun[0-9]+$ ]]
before_pss=$(vpn_pss) || fail "$check (could not read PSS before switching)"
(
  trap - ERR
  while [[ ! -e $lab/mode-pss.stop ]]; do
    vpn_pss
    sleep .05
  done
) > "$lab/mode-pss.kib" &
pss_pid=$!
deadline=$((SECONDS + 10))
until [[ -s $lab/mode-pss.kib ]]; do
  (( SECONDS < deadline )) && kill -0 "$pss_pid" 2>/dev/null ||
    fail "$check (could not start PSS sampling)"
  sleep .05
done
tap id global
wait_for_tun_replacement "$previous_tun"
: > "$lab/mode-pss.stop"
wait "$pss_pid"
pss_pid=
after_pss=$(vpn_pss) || fail "$check (could not read PSS after switching)"
printf '%s\n' "$before_pss" "$after_pss" >> "$lab/mode-pss.kib"
peak_pss=$(awk '$1 > peak {peak=$1} END {print peak}' "$lab/mode-pss.kib")
[[ $(timeout 5 "${device[@]}" shell pidof "$package:vpn" | tr -d '\r') == "$vpn_process" ]]
printf '%s:vpn mode switch PSS %s KiB before, %s KiB after, %s KiB sampled peak\n' \
  "$package" "$before_pss" "$after_pss" "$peak_pss"
(( peak_pss * 1024 <= 90 * 1000 * 1000 )) || fail "$check (sampled peak exceeded 90 MB)"
pass "$check"

check='VPN stays active with the UI in the background'
"${device[@]}" shell input keyevent KEYCODE_HOME
pss=$(vpn_pss) || fail "$check (could not read VPN PSS)"
tun_present
printf '%s:vpn PSS %s KiB\n' "$package" "$pss"
pass "$check"

check='stopping the VPN restores normal host networking'
"${device[@]}" shell am start -W -n "$activity" > /dev/null
ui_node detail '· Rescue' >/dev/null
tap id connect
ui_node status 'Not connected' >/dev/null
stop_deadline=$((SECONDS + 10))
while tun_present; do
  (( SECONDS < stop_deadline )) || fail "$check (TUN interface is still active)"
  sleep .2
done
guest_http 10.0.2.2 "$direct_port" / 10.0.2.2 > "$lab/direct.http"
check_body "$lab/direct.http" 'pipe android host'
guest_http "$target_addr" "$target_port" /switch/control "$target_name" > "$lab/switch-control.http"
check_body "$lab/switch-control.http" 'switch direct'
pass "$check"

check='reconnect with a profile that has no Rescue tier'
without_cdn=$(printf '%s\n' "$profile" | python3 -c '
from sys import stdin
from urllib.parse import parse_qsl, urlencode, urlsplit

profile = urlsplit(stdin.readline().strip())
options = urlencode([(key, value) for key, value in parse_qsl(profile.query) if key not in ("cdn", "wsp")])
print(profile._replace(query=options, fragment="android-no-cdn").geturl())
')
open_profile "$without_cdn"
tap text Add
ui_gone text 'Confirm profile import' || fail "$check (the import dialog did not close)"
ui_node text android-no-cdn >/dev/null
tap id connect
ui_node detail '· Fast' >/dev/null
tun_present
tap id tab_routing
ui_node id tier_stealth >/dev/null
if ui_node id tier_rescue 1 >/dev/null; then
  fail "$check (Rescue is enabled for a profile without a CDN)"
fi
tap id tab_home
ui_node detail '· Fast' >/dev/null
tap id connect
ui_node status 'Not connected' >/dev/null
pass "$check"

check='no Android SELinux denials for Pipe'
timeout 10 "${device[@]}" logcat -b all -d -v threadtime > "$lab/logcat.txt"
denials=$(app_denials "$lab/logcat.txt")
[[ -z $denials ]] || fail "$check"
pass "$check"
