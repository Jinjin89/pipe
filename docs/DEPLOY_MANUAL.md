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

## B. Next to an existing website (it keeps 80/443)
Pipe never touches the website. Fast and Stealth use their own DNS-only name; Rescue goes through Cloudflare to pipe's own TLS port (default 2053).
```sh
pipe-srv init --dir /var/lib/pipe --mode shared --domain <server-IP> --fast-sni <DNS-only name> \
  --fast-hop 20000-40000
pipe-srv proxy enable --dir /var/lib/pipe --domain <DNS-only name> \
  --cert-method dns --dns cloudflare --dns-token-file <token file>
pipe-srv rescue --dir /var/lib/pipe --cdn-domain static.example.com \
  --rescue-cert <origin cert file> --rescue-key <origin key file>     # optional: --rescue-port 2083
pipe-srv install --dir /var/lib/pipe
```
- Stealth borrows the HTTPS proxy's own site on that name, so it never forwards strangers to anyone else's site. Without the HTTPS proxy, shared mode runs Fast and Rescue only.
- **Cloudflare:** create a proxied (orange cloud) record `static.example.com` pointing at the server. Turn WebSockets on and use SSL Full (strict). If Bot Fight Mode blocks the app, turn it off for the zone (it cannot skip one name). Optional: turn on Authenticated Origin Pulls in Cloudflare and start pipe with `--cf-origin-ca <Cloudflare's origin-pull CA file>`, so only Cloudflare can complete TLS on the Rescue port. The Origin CA certificate lasts 15 years; pipe warns in its log 30 days before it expires. (to replace it, see below). Create the certificate under SSL/TLS > Origin Server > Create Certificate (valid 15 years) and save its two parts as the files above; the key must be owner-only.
- Cloudflare passes HTTPS only on ports 443, 2053, 2083, 2087, 2096 and 8443, so pick `--rescue-port` from those. Pipe accepts connections on it only from Cloudflare's published addresses.
- `pipe-srv rescue --dir /var/lib/pipe --cdn-domain ""` turns Rescue off. Running it again with new files or a new port changes them; then restart pipe. Keys and devices stay.

## Start it (both modes)
```sh
pipe server setup --yes --dir /var/lib/pipe --fast-hop 20000-40000 --fast-port 443
systemctl restart pipe
```
On the first setup after manual initialization, pass the hopping range and Fast UDP port you configured. Omit the Fast flags if you initialized without hopping. On later runs setup can reuse the values from the installed root-owned `pipe-hop.service`. Setup writes the units and BBR settings as root. Treat `/var/lib/pipe/install/` as a reference because the `pipe` user can change its contents.

Open these ports in your provider's firewall: UDP 443 and UDP 20000-40000, plus TCP 8443 and 9443 next to a website, or TCP 80/443 when pipe has them to itself. Open the Rescue port (2053) only to Cloudflare's addresses if your provider's firewall can do that; pipe refuses everyone else there anyway.

## HTTPS proxy on a second domain (shared mode)
Point a **DNS-only** record such as `proxy.other-domain.com` at the server, then:
```sh
pipe-srv proxy enable --dir /var/lib/pipe --domain proxy.other-domain.com   # --cert-method auto
systemctl restart pipe
```
`auto` picks `http` when port 80 is free; otherwise choose `dns` or `files` with `--cert-method`:
- **`files`:** `--cert F --key F`. Both files must be readable by user `pipe`; they are reloaded when they change.
- **`dns`:** `--dns alidns` or `--dns cloudflare`. Pipe asks for the key (hidden input), or takes it from `--dns-key-file F` / `--dns-token-file F` (owner-only files).
- **`http`:** used when port 80 is free. Pipe answers Let's Encrypt on port 80 itself.
For `http`, the certificate is requested when `pipe server run` starts. Check it with `pipe-srv proxy status --dir /var/lib/pipe`. Open TCP 9443. Visitors without a key see the server's own cover site.
