# SPDX-License-Identifier: GPL-3.0-or-later
# Sourced by both deployment scenarios.

https_curl() {
  local proxy=$1
  shift
  ip netns exec "$client_ns" env https_proxy="$proxy" curl --noproxy '' --silent --show-error --max-time 8 \
    --proxy-cacert "$work_dir/ca/ca.pem" --cacert "$work_dir/ca/ca.pem" \
    --resolve "$origin:$https_port:$server_addr" "$@"
}

decoy_proxy_request() {
  ip netns exec "$client_ns" curl --noproxy '*' --http1.1 --silent --show-error --max-time 8 \
    --cacert "$work_dir/ca/ca.pem" --resolve "$origin:$https_port:$server_addr" "$@"
}

check_https_proxy() {
  local body address status wrong_auth actual expected declared cover=${1:-site}
  check='HTTPS forward proxy carries CONNECT and absolute-form requests'
  body=$(https_curl "$main_proxy" --fail "https://$target_addr:$tls_target_port/")
  [[ $body == 'pipe HTTPS target' ]]
  body=$(https_curl "$main_proxy" --proxy "$main_proxy" --fail "http://$target_addr:$target_port/")
  [[ $body == 'pipe e2e target' ]]
  body=$(https_curl "$main_proxy" --proxy "$main_proxy" --fail \
    --request-target "https://$target_addr:$tls_target_port/" "http://$target_addr:$target_port/")
  [[ $body == 'pipe HTTPS target' ]]
  pass "$check"

  if curl --help all | grep -F -- '--proxy-http2' >/dev/null && curl --version | grep -w HTTP2 >/dev/null; then
    check='HTTPS forward proxy falls back to HTTP/1.1 when curl offers proxy HTTP/2'
    actual=$(https_curl "$main_proxy" --proxy-http2 --proxy "$main_proxy" --fail \
      --output "$work_dir/proxy-negotiated" --write-out '%{http_version}' "http://$target_addr:$target_port/")
    [[ $actual == 1.1 && $(cat "$work_dir/proxy-negotiated") == 'pipe e2e target' ]]
    body=$(https_curl "$main_proxy" --proxy-http2 --fail "https://$target_addr:$tls_target_port/")
    [[ $body == 'pipe HTTPS target' ]]
    pass "$check"
  fi

  if [[ $scenario != relay ]]; then
    check='HTTPS proxy enforces the persisted NAT egress block at startup'
    body=$(ip netns exec "$server_ns" curl --noproxy '*' --silent --show-error --fail --max-time 4 "http://$blocked_addr:$target_port/")
    [[ $body == 'pipe e2e target' ]]
    status=$(https_curl "$main_proxy" --proxy "$main_proxy" --output /dev/null --write-out '%{http_code}' \
      "http://$blocked_addr:$target_port/")
    [[ $status == 502 ]]
    pass "$check"
  fi

  check='HTTPS proxy rejects CONNECT to loopback and private addresses'
  for address in 127.0.0.1 "$server_addr"; do
    if status=$(https_curl "$main_proxy" --write-out '%{http_connect}' \
      "https://$address:$tls_target_port/" 2>/dev/null); then
      fail "$check (CONNECT unexpectedly completed)"
    fi
    [[ $status == 502 ]]
  done
  pass "$check"

  check='missing and wrong HTTPS proxy credentials get the normal site response'
  decoy_url="https://$origin:$https_port/"
  absolute="http://$target_addr:$target_port/"
  wrong_auth='Proxy-Authorization: Basic bWFpbjp3cm9uZw=='
  expected=$(decoy_proxy_request --write-out '%{http_code}' "$decoy_url" -o "$work_dir/proxy-site")
  if [[ $cover == plain-404 ]]; then
    [[ $expected == 404 ]]
    printf '404 page not found\n' | cmp - "$work_dir/proxy-site"
  else
    [[ $expected == 200 ]]
    check_cover_page "$work_dir/proxy-site"
  fi
  for declared in missing wrong; do
    local headers=()
    if [[ $declared == wrong ]]; then headers=(-H "$wrong_auth"); fi
    actual=$(decoy_proxy_request --request-target "$absolute" "${headers[@]}" --write-out '%{http_code}' \
      -D "$work_dir/proxy-headers" -o "$work_dir/proxy-absolute-$declared" "$decoy_url")
    [[ $actual == "$expected" ]]
    cmp "$work_dir/proxy-site" "$work_dir/proxy-absolute-$declared"
    if grep -iq '^proxy-authenticate:' "$work_dir/proxy-headers"; then fail "$check"; fi
    actual=$(decoy_proxy_request -X CONNECT --request-target "$target_addr:$tls_target_port" \
      "${headers[@]}" --write-out '%{http_code}' -D "$work_dir/proxy-headers" \
      -o "$work_dir/proxy-connect-$declared" "$decoy_url")
    [[ $actual != 407 ]]
    if [[ $cover == plain-404 ]]; then
      [[ $actual == 404 ]]
      cmp "$work_dir/proxy-site" "$work_dir/proxy-connect-$declared"
    fi
    if grep -iq '^proxy-authenticate:' "$work_dir/proxy-headers"; then fail "$check"; fi
  done
  cmp "$work_dir/proxy-connect-missing" "$work_dir/proxy-connect-wrong"
  pass "$check"
}

check_https_proxy_revocation() {
  local revoked_auth body
  check='revoked HTTPS proxy credentials get the decoy'
  body=$(https_curl "$main_proxy" --fail "https://$target_addr:$tls_target_port/")
  [[ $body == 'pipe HTTPS target' ]]
  if https_curl "$revoked_proxy" --fail "https://$target_addr:$tls_target_port/" >/dev/null 2>&1; then
    fail "$check (CONNECT accepted a revoked device)"
  fi
  revoked_auth="Proxy-Authorization: Basic $(printf '%s' "${revoked_proxy#https://}" | cut -d@ -f1 | base64 -w0)"
  decoy_proxy_request --request-target "$absolute" -H "$revoked_auth" "$decoy_url" > "$work_dir/proxy-revoked"
  cmp "$work_dir/proxy-site" "$work_dir/proxy-revoked"
  body=$(https_curl "$main_proxy" --fail "https://$target_addr:$tls_target_port/")
  [[ $body == 'pipe HTTPS target' ]]
  pass "$check"
}
