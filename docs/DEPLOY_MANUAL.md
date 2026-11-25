# Manual deployment

Most people should use `sudo pipe server setup` (see the README). This page lists the same steps done by hand, for when you want full control or are debugging setup.

All server commands run on the server as root. The state lives in `/var/lib/pipe` (owner-only, never commit it).

## 0. Install the binary (both modes)
```sh
useradd --system --home-dir /var/lib/pipe --shell /usr/sbin/nologin pipe
install -m 0755 pipe /usr/local/bin/pipe
install -d -m 0700 -o pipe -g pipe /var/lib/pipe
alias pipe-srv='runuser -u pipe -- /usr/local/bin/pipe server'
```

## A. Pipe-only server (uses ports 80 + 443)
Pipe is the web server: it gets and renews its own certificate, serves a cover website, and runs the HTTPS proxy on 443.
```sh
pipe-srv init --dir /var/lib/pipe --mode standalone --domain vpn.example.com \
         --fast-hop 20000-40000                   # optional: add --cdn-domain cdn.example.com for Rescue
pipe-srv install --dir /var/lib/pipe              # writes /var/lib/pipe/install/*
```

## B. Next to an existing website (nginx keeps 80/443)
Fast and Stealth use their own DNS-only name, separate from your website. Rescue goes through Cloudflare on a subdomain.
```sh
pipe-srv init --dir /var/lib/pipe --mode shared \
  --domain <server-IP> --fast-sni <DNS-only name> \
  --cdn-domain static.example.com --rescue-listen <docker-bridge-gateway>:18080 \
  --fast-hop 20000-40000
pipe-srv proxy enable --dir /var/lib/pipe --domain <DNS-only name> \
  --cert-method dns --dns cloudflare --dns-token-file <token file>
pipe-srv install --dir /var/lib/pipe
```
- Stealth borrows the HTTPS proxy's own site on that name, so it never forwards strangers to anyone else's site. Without the HTTPS proxy, shared mode runs Fast and Rescue only.
- Find the Docker bridge gateway with `docker inspect <nginx-container> --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}'`.
- **Cloudflare:** create a proxied (orange cloud) record `static.example.com` pointing at the server. Turn WebSockets on, use SSL Full (strict), and exempt this subdomain from Bot Fight Mode.
- **nginx:** copy `/var/lib/pipe/install/pipe-nginx.conf` (complete `server {}` blocks for the Rescue subdomain, plus the port-80 certificate block when the proxy uses `nginx`) into your nginx config directory with `install -m 0600`. Then run `nginx -t` and reload. The file contains a secret path, so do not commit it.

## Start it (both modes)
```sh
cp /var/lib/pipe/install/pipe.service /var/lib/pipe/install/pipe-hop.service /etc/systemd/system/
cp /var/lib/pipe/install/90-pipe.conf /etc/sysctl.d/ && sysctl -p /etc/sysctl.d/90-pipe.conf   # BBR
systemctl daemon-reload && systemctl enable --now pipe-hop pipe
```
(`pipe-hop` exists only with `--fast-hop`.) Open these ports in your provider's firewall: UDP 443, UDP 20000-40000 and TCP 8443 (shared mode), or TCP 80/443 + UDP 443 (pipe-only mode).

## HTTPS proxy on a second domain (shared mode)
Point a **DNS-only** record such as `proxy.other-domain.com` at the server, then:
```sh
pipe-srv proxy enable --dir /var/lib/pipe --domain proxy.other-domain.com   # --cert-method auto
pipe-srv install --dir /var/lib/pipe      # rewrites install/pipe-nginx.conf for the nginx method
systemctl restart pipe
```
`auto` picks one of these. You can also force one with `--cert-method`:
- **`files`:** `--cert F --key F`. Both files must be readable by user `pipe`; they are reloaded when they change.
- **`dns`:** `--dns alidns` or `--dns cloudflare`. Pipe asks for the key (hidden input), or takes it from `--dns-key-file F` / `--dns-token-file F` (owner-only files).
- **`http`:** used when port 80 is free. Pipe answers Let's Encrypt on port 80 itself.
- **`nginx`:** used when nginx owns port 80.
  - Pipe answers on a private address (`--acme-listen`, default `<rescue IP>:18081`).
  - Copy the port-80 block from `install/pipe-nginx.conf` into nginx and reload.
  - TCP 80 must be open to everyone.

For `http` and `nginx`, the certificate is requested when `pipe server run` starts. Check it with `pipe-srv proxy status --dir /var/lib/pipe`. Open TCP 9443. Visitors without a key see the server's own cover site.
