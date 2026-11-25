# pipe

Your own private VPN: one small server, and apps on your phone and laptop that connect to it. Only your devices can use it. To everyone else, the server looks like an ordinary website.

## Concepts

- **Server:** the `pipe` program running on your VPS. Your devices connect to it, and it fetches the internet for them.
- **Client:** the pipe app on your phone, or `pipe run` on your laptop.
- **Device link:** a `pipe://…` text, also shown as a QR code. It holds the server address and one device's secret key.
  - Every device gets its own link, and you can revoke any one of them.
  - Anyone without a link only sees a normal website.
- **Routes:** a client reaches the server in 3 ways. It picks the best one by itself and switches when one stops working:
  - **Fast:** the quickest. It uses UDP, like video calls do.
  - **Stealth:** it looks exactly like visiting a normal website. It's used when UDP is blocked or slow.
  - **Rescue:** it goes through Cloudflare, so nobody sees your server's IP. It's used when that IP is blocked.
- **Modes**, which you pick in the client:
  - **Smart:** Chinese and local sites go direct, and everything else goes through pipe.
  - **Global:** everything goes through pipe.
  - **Direct:** pipe is paused.
- **Layout:** setup checks your server and picks one by itself.
  - **standalone:** ports 80/443 are free, so pipe takes them and is the website.
  - **shared:** a website (e.g. nginx) already uses 80/443, so pipe runs beside it and doesn't touch it.
- **HTTPS proxy:** a small website with a real certificate on your own DNS-only name. It has two jobs:
  - **Stealth's cover site.** In the shared layout, Stealth needs it (see below).
  - **Terminal proxy (optional).** A single `export https_proxy=… http_proxy=…` line lets any terminal use your server with nothing installed.

## How the data flows

The shared layout is shown. Names are examples: `vpn.example.org` is your own DNS-only name, and `rescue.example.com` is your Cloudflare name.

```
                        Your server (<server IP>)
                        name: vpn.example.org
 Phone / laptop
 ┌──────────┐
 │ pipe app │── Fast ──── UDP 443 ──────────► Hysteria2 ─────────────────► Internet
 │          │
 │          │── Stealth ─ TCP 8443 ─────────► REALITY
 │          │   (looks like HTTPS to           │ has your key? ── yes ──► Internet
 │          │    vpn.example.org)              │
 │          │                                  └─ no key (censor or stranger)
 │          │                                       ▼
 │          │                        HTTPS proxy site (local, TCP 9443)
 │          │                        real certificate and a small web page:
 │          │                        they see a normal website, nothing else
 │          │
 │          │── Rescue ── rescue.example.com ─► Cloudflare ─► nginx ─► pipe ─► Internet
 └──────────┘

 Terminal (optional):
   export https_proxy=… ── TCP 9443 ──► HTTPS proxy (password) ────────────► Internet
```

- **Why Stealth uses the HTTPS proxy's name.** A censor sees the name in each connection and may check whether it is a real website. REALITY passes anyone without a key on to the real site behind that name: your own HTTPS proxy site, on the same machine. The disguise is real, and strangers can reach nothing else. Borrowing someone else's site instead let strangers use the server as a free relay, so pipe no longer allows it.
- **Fast uses the same name too.** All direct routes look like one ordinary website.
- **REALITY can't run through Cloudflare.** Its key hides inside the TLS handshake, and Cloudflare completes every handshake itself, so the key never arrives. That is why Rescue wraps traffic as normal web traffic (WebSocket), which Cloudflare forwards.

**Who sees which IP:**

| | Your device's IP | Your server's IP |
|---|---|---|
| Websites you visit | hidden on every route | visible |
| Your ISP or a censor, on Fast and Stealth | visible | visible (you connect to it directly) |
| Your ISP or a censor, on Rescue | visible | hidden (they only see Cloudflare) |

Auto tries Fast, then Stealth, then Rescue. To never show the server IP on your network, pin the Rescue route. It is slower.

The standalone layout is the same, except that pipe owns TCP 443: Stealth and the cover site are on 443.

# Part 1: Deploy the server

There are 3 steps: **get pipe → generate the config → run**. Do them on your VPS as **root**.

### Step 1: Get pipe
Download the latest release (`uname -m` says `x86_64` → `amd64`, `aarch64` → `arm64`):
```sh
curl -fLO https://github.com/Jinjin89/pipe/releases/latest/download/pipe-linux-amd64.tar.gz
tar -xzf pipe-linux-amd64.tar.gz
```
Result: a file called `pipe`. Setup installs it to `/usr/local/bin/pipe`.

To build it yourself instead (Go 1.27):
```sh
git clone https://github.com/Jinjin89/pipe.git && cd pipe
go build -trimpath -tags with_gvisor,with_quic,with_utls,with_acme,badlinkname,tfogo_checklinkname0 \
  -ldflags '-s -w -checklinkname=0' -o pipe ./cmd/pipe
```

### Step 2: Generate the config
**Fastest, on a new server with nothing else on it:** point a DNS name at the server (an `A` record, DNS only), then run one line and skip to the **Next steps** below:
```sh
./pipe server setup --yes --mode standalone --domain vpn.example.com --fast-hop 20000-40000 --device phone
```
pipe gets its own certificate for that name. For anything else, use a template:

1. **Pick the template for your situation** and copy it to `setup.json`:

   | Your situation | Template |
   |---|---|
   | New server, nothing else on it | `standalone.json` |
   | New server, plus Rescue through Cloudflare (your domain's DNS is on Cloudflare) | `standalone-cloudflare.json` |
   | A website already runs on the server; just Fast (no Stealth without a proxy domain) | `shared-basic.json` |
   | Website on **nginx in Docker**; plus Rescue + HTTPS proxy | `shared-nginx-docker.json` |
   | Website on **nginx installed on the server**; plus Rescue + HTTPS proxy | `shared-nginx-host.json` |
   | HTTPS proxy whose certificate comes through an **Alibaba Cloud DNS** key | `shared-proxy-alidns.json` |
   | HTTPS proxy whose certificate comes through a **Cloudflare DNS** token | `shared-proxy-cloudflare-dns.json` |
   | HTTPS proxy with **your own certificate files** | `shared-proxy-own-cert.json` |

   ```sh
   cp templates/shared-nginx-docker.json setup.json      # use your template's name
   ```
   Or let pipe write one pre-filled with this server's IP and Docker network: `./pipe server setup --template > setup.json`.
2. **Replace the example values** (`example.com`, `203.0.113.7` …) with yours:

   | Field | Must fill? | What it is: where to find it |
   |---|---|---|
   | `mode` | yes | `standalone` if nothing uses ports 80/443, `shared` if a website does. Check with `ss -ltn \| grep -E ':(80\|443) '`. Pre-filled. |
   | `domain` | yes | standalone: a DNS name with an `A` record pointing at the server. shared: the server's public IP (`curl -4 ifconfig.me`). Pre-filled in shared. |
   | `fast_sni` | shared | any domain you own; it needs no DNS record. Tip: the same as `proxy_domain`. |
   | `cdn_domain` | recommended | the Rescue subdomain, e.g. `static.your-site.com`. In Cloudflare: add an `A` record pointing at the server with the orange cloud ON, set SSL to Full (strict) and turn WebSockets ON. `""` = no Rescue. |
   | `rescue_listen` | if `cdn_domain` | where nginx reaches pipe. nginx in Docker: `docker inspect <nginx> --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}'` + `:18080`. nginx on the host: `127.0.0.1:18080`. |
   | `reality_dest` | no | Leave out, or `self`. Stealth in shared mode always borrows your own HTTPS proxy site, so it needs `proxy_domain`. Without a proxy domain you get Fast and Rescue only, and setup says so. Any other value is refused. |
   | `fast_hop` | recommended | keep `20000-40000`, and open that UDP range in the firewall. |
   | `proxy_domain` | for Stealth in shared mode | also for `export https_proxy`: a **second** domain with an `A` record pointing at the server, DNS only. `""` = no Stealth in shared mode. |
   | `proxy_cert_method` | optional | keep `auto` (no API key needed). |
   | `device` | yes | a name for your first device, e.g. `phone`. |
   | `dns`, `dns_key_file`, `dns_token_file` | only for `"dns"` | the DNS provider (`alidns` or `cloudflare`) and the key/token file. Alibaba: RAM console > Users > Create AccessKey; Cloudflare: My Profile > API Tokens. |
   | `cert`, `key` | only for `"files"` | your certificate chain and private key files, e.g. certbot's `fullchain.pem` and `privkey.pem`. |

   **Moving an older shared server to `self`:** older versions could borrow a third-party site. That is no longer supported: the server still starts, but Stealth stays off (Fast, Rescue and the HTTPS proxy keep running). Put `"reality_dest": "self"` in the file (the server needs a proxy domain) and run setup again, or run `pipe server reality`. Only the Stealth target changes. Keys, devices and all other settings stay. Saved device links need the new Stealth name: set `rsni=<proxy domain>` in each link, or add the device again.

3. **Run setup with it:**
   ```sh
   ./pipe server setup --config setup.json
   ```

Setup writes these files:

| File | What it holds |
|---|---|
| `/var/lib/pipe/server.json` | the server config |
| `/var/lib/pipe/devices.json` and the key files | your devices' keys |
| `/var/lib/pipe/install/` | the service files, plus `pipe-nginx.conf` for the shared layout |

It also prints your phone's **device link and QR code**. The server shows it only once. After you import it, Pipe keeps it for you: **Profiles → Device link → Show** (desktop) or **Settings → Device link → Show** (Android) shows the link, its QR code and the HTTPS proxy line again. They stay hidden until you click.

Before you run pipe, finish the parts outside it (setup prints these as **Next steps**):
1. **DNS:** point each domain you entered at the server IP.
   - The Rescue subdomain: Cloudflare **orange cloud on**. In Cloudflare, also turn **WebSockets** on and set SSL to **Full (strict)**.
   - Every other domain: **DNS only**.
2. **nginx** (shared layout only): give nginx the file setup wrote, then reload it:
   ```sh
   install -m 0600 /var/lib/pipe/install/pipe-nginx.conf /etc/nginx/conf.d/pipe.conf
   nginx -t && nginx -s reload
   ```
   For nginx in Docker, put the file in its mounted config folder instead, then run `docker exec <container> nginx -t` and `docker exec <container> nginx -s reload`.
3. **Firewall:** in your VPS provider's panel, open the ports setup listed.
   - standalone: TCP 80, TCP 443, UDP 443 and UDP 20000-40000
   - shared: UDP 443, UDP 20000-40000 and TCP 8443. With the HTTPS proxy, also TCP 9443, and TCP 80 open to everyone.

### Step 3: Run it
```sh
systemctl restart pipe           # start pipe (it also starts on every boot)
systemctl status pipe            # should say: active (running)
```
Other commands:
- `journalctl -u pipe -n 50` shows the log.
- `systemctl stop pipe` stops pipe.
- After changing the config (for example, running setup again), run `systemctl restart pipe`.

The server is done ✅

# Part 2: Set up the clients

**One link or one per device?** One `pipe://` link works on several devices at the same time. Give each device its own link (`pipe server add NAME`) if you want to cut off one device without touching the others.

Get the apps from **Releases** on GitHub (open the latest release and look under **Assets**). Nothing needs building.

| Your device | Download |
|---|---|
| Android phone | `pipe-android-arm64.apk` |
| Mac with an M chip | `pipe-macos-arm64.zip` |
| Intel Mac | `pipe-macos-amd64.zip` |
| Windows | `pipe-windows-amd64.zip` |
| Linux | `pipe-linux-amd64.tar.gz` (ARM: `pipe-linux-arm64.tar.gz`) |

### Phone (Android)
1. Open the release on the phone, tap the APK, and install it. If Android asks, allow installing from the browser.
2. Open pipe and tap **Scan QR** to scan the code from Part 1, or **From image** for a screenshot or a photo you received, or **Paste** for a copied `pipe://` link. Then tap **Add**.
3. Tap the big round button. **Smart** mode is the default.
4. Recommended: in Android **Settings → Network → VPN → Pipe**, turn on **Always-on VPN** and **Block connections without VPN**. Then nothing leaves the phone outside pipe, not even for the instant pipe needs to rebuild its tunnel after you change a setting.

### Computer (Mac, Windows or Linux)
1. Unzip the download and open **Pipe**:
   - **Mac:** move `Pipe.app` to Applications. Pipe isn't signed by Apple, so the first time macOS may say it **is damaged** (it isn't). Open **Terminal**, run `xattr -cr /Applications/Pipe.app` once, then open Pipe. That removes only the "downloaded from the internet" flag. If macOS instead says it can't verify the app, open **System Settings → Privacy & Security** and click **Open Anyway**.
   - **Windows:** open `Pipe.exe`. If SmartScreen appears, click **More info → Run anyway**.
   - **Linux:** run `./pipe app --install-desktop-entry` once. Pipe then appears in your app menu.
2. Paste your `pipe://` link into **Add your server**, check the server shown, and click **Save**.
3. Click the big round button. Pipe sets the system proxy, so browsers and most apps use it.

On a Mac, **TUN** on Home sends every app through Pipe. While it's on, Pipe sets the Mac's DNS to `223.5.5.5` and puts your own DNS settings back when TUN stops, even after a crash.

On macOS, Pipe opens in its own window, with a Dock icon while it's open, and it stays in the menu bar after you close it. On Windows and Linux it opens in Edge, Chrome, Brave or Chromium as its own app window. Windows always has Edge. Without one of those it opens a browser tab. Closing the window while connected keeps Pipe running. Open Pipe again to get the window back, or click **Quit** in the sidebar.

**What the pages do:**

| Page | What it's for |
|---|---|
| Home | Connect, and watch the live path: your computer, the relay if one is used, and the server, with sending and receiving flowing in both directions. Also shows the route, its speed and the mode |
| Routing | **Mode:** Smart (China and local sites direct), Global (everything through pipe), Direct (pipe off). **Route:** Auto picks Fast, then Stealth, then Rescue. **Rules:** your own exceptions, checked first |
| Profiles | Add, rename or switch servers, and set a relay. With two or more, **Test all** measures Fast, Stealth and Rescue for each profile side by side |
| Logs | What pipe is doing. **Every connection** (in Settings) shows each site and the route it took. Logs stay in memory only |
| Settings | Start at login, system proxy, port, IPv6, theme |

### Terminal only (optional, needs the HTTPS proxy)
Paste the `export https_proxy=…` line that `pipe server add` printed. That terminal now uses your server.

---
Everything below is reference.

## Manage devices
Run these on the server as root. `runuser` makes the files stay owned by the `pipe` user:
```sh
alias pipe-srv='runuser -u pipe -- pipe server'
pipe-srv add laptop --dir /var/lib/pipe      # prints the pipe:// link, a QR code and the export line
pipe-srv list --dir /var/lib/pipe
pipe-srv revoke laptop --dir /var/lib/pipe   # takes effect immediately on all routes
```
A link is shown only once, so save it somewhere private. Lost it? Revoke the device and add it again.

## Speed-up relay (optional)
If the direct path to your server is slow, put a relay in between: client → relay → server. The relay is a **second VPS** with a better route, in any region, and one relay can serve all your servers. It only forwards encrypted packets in the kernel. It holds no keys and runs no Pipe process, so it can't read or change your traffic. It can see your IP address and how much you send, and it can slow you down, in which case you switch it off.

**You need:** a Linux VPS with systemd, nftables and a public IP, and root on it. Pick one with a good route both to you and to your servers. Nothing changes on your servers.

1. **On each server**, print its relay line. It contains only the server's IP and ports, no secret:
   ```sh
   pipe server relay-command --dir /var/lib/pipe
   # prints e.g.: pipe relay add --to 203.0.113.7 --tcp 8443 --udp 443,20000-40000
   ```
2. **On the relay VPS**, as root:
   - Download pipe as in Part 1, Step 1, then `install -m 0755 pipe /usr/local/bin/pipe`. Leave it there, because the relay's boot service runs it from that path.
   - Install nftables if it's missing (Debian or Ubuntu: `apt install nftables`).
   - Run each server's line from step 1. Each run prints that server's **relay code** and the ports it uses:
     ```
     198.51.100.4:8444/30000-39999
     Open on this VPS: TCP 8444, UDP 30000-39999
     ```
     The relay gives every server its own ports and never takes a port a service on the VPS already uses. The first server usually keeps its normal ports, and its code is just the relay's IP.
   - In your provider's firewall for this VPS, open the ports each run printed.
3. **On each device**, open the server's profile in the app, paste that server's relay code under **Relay**, and switch it on. In a terminal, use `pipe run 'pipe://…' --relay <relay code>`. The home screen shows "via <relay>" while the relay is used.

- **The relay fails or is switched off:** Pipe goes direct within a second and tries the relay again a minute later (sooner after a network change). The status then shows "relay not reachable, direct". A code that belongs to another server fails the same safe way.
- **Fast uses the relay only when the link has a Fast pin** (shared-mode servers, where the server's line includes `--udp`). Standalone servers relay Stealth only. Rescue never uses the relay.
- **The code shows a private IP** (some cloud VPSes): run the line again with `--host <the VPS's public IP or name>` added.
- **A server's IP or ports changed:** run its new line on the relay. A server keeps its relay ports, and so its code, whenever they're still free.
- **On the relay:** `pipe relay status` lists each server with its code and traffic. `pipe relay remove --to <server IP>` drops one server, and `pipe relay remove` deletes everything and restores the VPS's network settings. A new `pipe` binary on the relay needs no reinstall.

## Troubleshoot
```sh
pipe server proxy status --dir /var/lib/pipe   # HTTPS proxy: method and certificate expiry
pipe run 'pipe://…' --tier fast                # on a laptop: test one route (fast, stealth or rescue)
```
- **Fast fails but Stealth works:** UDP is blocked or throttled on that network. Pipe switches to Stealth automatically.
- **Only Rescue works:** the server IP is blocked. Rescue still reaches it through Cloudflare.
- **Fast broke after a firewall reload:** `systemctl restart pipe-hop` (a reload with `flush ruleset` removes the hop rule).
- **HTTPS proxy certificate not issued yet:**
  - the proxy domain's DNS record must point at the server (DNS only)
  - for `http`/`nginx`, TCP 80 must be open to everyone
  - for `nginx`, the nginx file must be copied and nginx reloaded
  - then run `systemctl restart pipe`
- **The `https_proxy` line is detectable from inside China** (TLS inside TLS). Inside China, use `pipe run` or the app instead.

## Command-line client (no window)
```sh
pipe run 'pipe://…'                  # local proxy on 127.0.0.1:7890 (Smart mode)
pipe run 'pipe://…' --system-proxy   # also set the OS proxy
sudo pipe run 'pipe://…' --tun       # whole-device VPN
```
Options: `--mode smart|global|direct`, `--tier auto|fast|stealth|rescue`, `--listen 127.0.0.1:7890`.

To keep the link out of your shell history, save it as `laptop.link` (mode 0600) in `pipe/profiles` under your user config directory (`~/.config` on Linux). Then run `pipe run pipe.yaml` with a `pipe.yaml` like this:
```yaml
server: laptop
mode: smart
rules:
  - netflix.com -> proxy
  - 192.0.2.0/24 -> direct
```

With `pipe run` running, a terminal can use it too: `export https_proxy=http://127.0.0.1:7890`.

## Server reference

### HTTPS proxy certificate
The HTTPS proxy uses a second, DNS-only domain on TCP 9443. Pipe gets and renews its certificate by itself, with one of four methods. `auto` picks the method for you:

| Method | When | What you do |
|---|---|---|
| `http` | nothing listens on port 80 | open TCP 80 |
| `nginx` | nginx owns port 80 | copy the nginx file setup writes; open TCP 80 to everyone |
| `dns` | port 80 is not usable | paste your DNS key when asked (it is hidden and stored owner-only) |
| `files` | you already have a certificate | give `--cert` and `--key` (both readable by user `pipe`) |

DNS keys need only small permissions:
- **Alibaba:** a RAM sub-user with `alidns:AddDomainRecord`, `DeleteDomainRecord` and `DescribeDomainRecords` on `acs:alidns:*:*:domain/<your-domain>`, plus `alidns:DescribeDomains` on `"*"`.
- **Cloudflare:** a token with Zone:Read + DNS:Edit on that one zone.

### Without questions
Setup also runs non-interactively, for scripts:
```sh
./pipe server setup --yes --mode shared --domain 203.0.113.7 --fast-sni www.example.com \
  --cdn-domain static.example.com --rescue-listen 172.17.0.1:18080 \
  --fast-hop 20000-40000 \
  --proxy-domain proxy.example.org --device phone
```
`pipe server setup --help` lists every flag. To do every step by hand, see `docs/DEPLOY_MANUAL.md`.

### Update or remove
```sh
./pipe server setup                 # with a new binary: upgrades and keeps all devices and keys
pipe server uninstall --dir /var/lib/pipe           # stops pipe, removes its services, keeps the state
pipe server uninstall --dir /var/lib/pipe --purge   # also deletes /var/lib/pipe and every device key
```

## Development
```sh
go test -tags with_gvisor,with_quic,with_utls,with_acme,badlinkname,tfogo_checklinkname0 \
  -ldflags '-checklinkname=0' ./...      # unit tests
./test/e2e/run.sh standalone|shared       # root network tests
./test/android/run.sh                     # Android emulator test
./scripts/package-desktop.sh              # desktop apps into dist/
./scripts/build-android.sh                # Android APKs
```
The app design and its decisions are in `docs/APP_DESIGN.md`.
Design notes are in `docs/DECISIONS.md`. License: GPL-3.0-or-later.
