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
- **Layout:** you never pick it; setup checks your server.
  - **Alone:** TCP 80/443 are free, so pipe takes them and is the website.
  - **Next to a website:** a website already uses 80/443, so pipe uses its own ports and never touches it.
- **HTTPS proxy:** a small website with a real certificate on your own DNS-only name. It has two jobs:
  - **Stealth's cover site.** Next to a website, Stealth needs it (see below).
  - **Terminal proxy (optional).** A single `export https_proxy=… http_proxy=…` line lets any terminal use your server with nothing installed.

## How the data flows

The next-to-a-website layout is shown. Names are examples: `vpn.example.org` is your own DNS-only name, and `rescue.example.com` is your Cloudflare name.

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
 │          │── Rescue ── rescue.example.com ─► Cloudflare ─► TCP 2053 ─► pipe ─► Internet
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

When pipe has 80/443 to itself it is the same, except that Stealth, the cover site and Rescue are all on TCP 443.

# Part 1: Deploy the server

On your Linux VPS, use an account with `sudo` access to install Pipe, configure it, and start the service.

### Step 1: Get pipe
Download the Linux release and verify it with OpenSSL 3 before installing. Use `amd64` for `x86_64` or change `arch` to `arm64` for `aarch64`.

```sh
(
  set -eu
  work=$(mktemp -d)
  trap 'rm -rf -- "$work"' EXIT
  cd "$work"
  version=0.7.7-alpha
  arch=amd64
  archive="pipe-linux-$arch.tar.gz"
  release="https://github.com/Jinjin89/pipe/releases/download/v$version"
  for asset in "$archive" SHA256SUMS SHA256SUMS.sig; do
    curl -fLO "$release/$asset"
  done

  printf '%s\n' '-----BEGIN PUBLIC KEY-----' \
    'MCowBQYDK2VwAyEA7evMPdWmNXKsBfAyKYviEzA3mzwJb3PV2ZJggn/GCDI=' \
    '-----END PUBLIC KEY-----' > pipe-release.pub
  openssl pkeyutl -verify -pubin -inkey pipe-release.pub -rawin \
    -in SHA256SUMS -sigfile SHA256SUMS.sig
  test "$(sed -n '2p' SHA256SUMS)" = "version $version"
  awk -v name="$archive" '$3 == name {print $5 "  " $3}' SHA256SUMS | sha256sum -c -
  tar -xzf "$archive"
  sudo install -m 0755 -o root -g root ./pipe /usr/local/bin/pipe
  # sudo /usr/local/bin/pipe update --from "$work"  # Upgrade relay and Linux Helper copies
)
```

For the one-time upgrade from 0.7.5, follow this step and restart the service as in Step 3. On hosts also running `pipe-relay` or the Linux Pipe Helper, uncomment the offline update command to upgrade those copies before the verified files are removed. Use `sudo pipe update` for later upgrades.

You can also build and install from source with Go 1.27.

```sh
git clone https://github.com/Jinjin89/pipe.git && cd pipe &&
go build -trimpath -tags with_gvisor,with_quic,with_utls,with_acme,badlinkname,tfogo_checklinkname0 \
  -ldflags '-s -w -checklinkname=0' -o pipe ./cmd/pipe &&
sudo install -m 0755 -o root -g root ./pipe /usr/local/bin/pipe
```

### Step 2: Generate the config
On a new server with no website, point a DNS-only `A` record at the server, then run this command and continue to **Next steps** below.

```sh
sudo /usr/local/bin/pipe server setup --yes --sni vpn.example.com --fast-hop 20000-40000 --device my-device
```
Pipe gets its own certificate for that name. For other layouts, use a setup file.

1. **Write the template.** It shows the detected server address and ports.
   ```sh
   sudo /usr/local/bin/pipe server setup --template > setup.json
   ```
   ```json
   {
     "ip": "203.0.113.7",
     "sni": "proxy.example.com",
     "cert": { "dns": "cloudflare", "token_file": "cf-token" },
     "fast": { "port": 443, "hop": "20000-40000" },
     "stealth": { "port": 8443 },
     "proxy": { "port": 9443 },
     "rescue": { "sni": "static.example.com", "port": 2053, "cert": "origin.pem", "key": "origin.key" },
     "device": "my-device"
   }
   ```
2. **Fill in your settings.** Relative paths start from the directory containing `setup.json`.

   | Key | What it is |
   |---|---|
   | `ip` | the address your devices connect to. Leave it out to use `sni`. |
   | `sni` | your own DNS-only name (an `A` record pointing at the server, grey cloud). Fast, Stealth and the HTTPS proxy use it. |
   | `cert` | how `sni` gets its certificate. Leave it out when TCP 80 is free (automatic). Otherwise `{ "dns": "cloudflare", "token_file": … }` (a token with Zone Read and DNS Edit on that zone), `{ "dns": "alidns", "key_file": … }`, or `{ "file": …, "key": … }`. |
   | `fast` | UDP `port` and the optional `hop` range (open it in the firewall). |
   | `stealth`, `proxy` | their TCP `port`. `proxy` is the HTTPS proxy for `export https_proxy`; Stealth borrows its site, so without `proxy` there is no Stealth when port 443 is taken. |
   | `rescue` | `sni`: your Cloudflare name (orange cloud, different from `sni` above). `port`: Cloudflare passes HTTPS only on 443, 2053, 2083, 2087, 2096 and 8443. `cert`/`key`: a Cloudflare **Origin Certificate** for that name (SSL/TLS > Origin Server > Create Certificate, valid 15 years). Pipe answers on that port only to Cloudflare's addresses. |
   | `device` | a name for your first device. |

   **Leave out `proxy` or `rescue` and that part is off.** Fast always runs. Stealth needs a real website to hide behind: it always runs when pipe has port 443, and next to a website it runs only with `proxy` (without it, pick Auto in the app; the Stealth route won't connect). The `fast` and `stealth` sections only set ports. There is no mode to pick: when TCP 80 and 443 are free, pipe uses them itself (everything on 443, certificates automatic) and ignores the ports and certificates above; when a website already has them, pipe uses its own ports and never touches the website. Setup says which one it chose.

   **Moving a server set up before 0.7.3:** update your apps to 0.7.3 first. Write the full file with your current names (a `proxy` or `rescue` you leave out is turned off), add the `rescue` section, and run setup again. Keys, devices and all other settings stay. Then open the Rescue port and remove pipe's old file from your nginx. Saved device links need the Rescue port: change `cdn=<name>` to `cdn=<name>:2053` in each link (setup prints the exact value), or add the device again under a new name.
3. **Run setup.**
   ```sh
   sudo /usr/local/bin/pipe server setup --config setup.json
   ```

   From a root shell, run the command directly. If `setup.json` is in another user's home directory, add `--operator <user>` with that account's login name.

Setup writes these files:

| File | What it holds |
|---|---|
| `/var/lib/pipe/server.json` | the server config |
| `/var/lib/pipe/devices.json` and the key files | your devices' keys |
| `/var/lib/pipe/install/` | the service files |

For these unattended commands, setup writes the new **device link** to an owner-only `.link` file and prints its path. Import the link into the app. To view it again, use **Profiles → Device link → Show** on desktop or **Settings → Device link → Show** on Android.

Before you run pipe, finish the parts outside it (setup prints these as **Next steps**):
1. **DNS:** point each name you entered at the server IP.
   - The Rescue name: Cloudflare **orange cloud on**. In Cloudflare, also turn **WebSockets** on and set SSL to **Full (strict)**.
   - `sni`: **DNS only**.
2. **Firewall:** in your VPS provider's panel, open the ports setup listed.
   - pipe has 80/443 to itself: TCP 80, TCP 443, the Fast UDP port (443) and the hop range
   - next to a website: the Fast UDP port (443), the hop range and the TCP ports in your file (8443, 9443 and 2053 by default). If your provider's firewall can, open the Rescue port only to [Cloudflare's addresses](https://www.cloudflare.com/ips/); pipe refuses everyone else there anyway.

### Step 3: Run it
```sh
sudo systemctl restart pipe      # Pipe also starts on every boot
sudo systemctl status pipe       # confirm it is active (running)
```
Other commands:
- `sudo journalctl -u pipe -n 50` shows the log.
- `sudo systemctl stop pipe` stops Pipe.
- After editing the server config, run `sudo systemctl restart pipe`.

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

On a Mac, **TUN** on Home sends every app through Pipe. Pipe points the Mac's DNS into the tunnel. It restores the previous settings when TUN stops and repairs stale settings on the next startup after a crash.

On macOS, Pipe opens in its own window, with a Dock icon while it's open, and it stays in the menu bar after you close it. On Windows and Linux it opens in Edge, Chrome, Brave or Chromium as its own app window. Windows always has Edge. Without one of those it opens a browser tab. Closing the window while connected keeps Pipe running. Open Pipe again to get the window back, or click **Quit** in the sidebar.

**What the pages do:**

| Page | What it's for |
|---|---|
| Home | Connect, and watch the live path: your computer, the relay if one is used, and the server, with sending and receiving flowing in both directions. Also shows the route, its speed and the mode |
| Routing | **Mode:** Smart (China and local sites direct), Global (everything through pipe), Direct (pipe off). **Route:** Auto picks Fast, then Stealth, then Rescue. **Rules:** your own exceptions, checked first |
| Profiles | One line per server: its country and its Fast, Stealth and Rescue times. **Test** measures every profile; **Use** switches. Click a name for its relay, device link, Rename and Delete. |
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
   - Download and install Pipe as in Part 1, Step 1.
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
- **Fast uses the relay only when the link has a Fast pin** (servers next to a website, where the server's line includes `--udp`). A server that has 80/443 to itself relays Stealth only. Rescue never uses the relay.
- **The code shows a private IP** (some cloud VPSes): run the line again with `--host <the VPS's public IP or name>` added.
- **A server's IP or ports changed:** run its new line on the relay. A server keeps its relay ports, and so its code, whenever they're still free.
- **On the relay:** `pipe relay status` lists each server with its code and traffic. `pipe relay remove --to <server IP>` drops one server, and `pipe relay remove` deletes everything and restores the VPS's network settings. Use `sudo pipe update` to update the command and its boot copy together.

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
  - for `http`, TCP 80 must be open to everyone
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
The HTTPS proxy uses a second, DNS-only domain on TCP 9443. Pipe gets and renews its certificate by itself, with one of three methods. `auto` picks `http` when port 80 is free:

| Method | When | What you do |
|---|---|---|
| `http` | nothing listens on port 80 | open TCP 80 |
| `dns` | port 80 is used by a website | paste your DNS key when asked (it is hidden and stored owner-only) |
| `files` | you already have a certificate | give `--cert` and `--key` (both readable by user `pipe`) |

DNS keys need only small permissions:
- **Alibaba:** a RAM sub-user with `alidns:AddDomainRecord`, `DeleteDomainRecord` and `DescribeDomainRecords` on `acs:alidns:*:*:domain/<your-domain>`, plus `alidns:DescribeDomains` on `"*"`.
- **Cloudflare:** a token with Zone:Read + DNS:Edit on that one zone.

### Without questions
Setup also runs non-interactively for scripts.

```sh
sudo /usr/local/bin/pipe server setup --yes --ip 203.0.113.7 --sni proxy.example.org --fast-hop 20000-40000 \
  --dns cloudflare --dns-token-file cf-token \
  --rescue-sni static.example.com --rescue-cert origin.pem --rescue-key origin.key \
  --device my-device
```
`pipe server setup --help` lists every flag. To do every step by hand, see `docs/DEPLOY_MANUAL.md`.

### Update or remove

Use the signed updater on Linux starting with Pipe 0.7.6-alpha.

- `sudo pipe update` fetches and verifies the release against its Ed25519-signed manifest. It updates the installed server, relay, and Pipe Helper binaries and restarts active daemons. The relay uses the new binary on its next apply or boot.
- `sudo pipe update --check` previews installed and offered versions, target paths, and planned restarts.
- `sudo pipe update --from <dir-or-archive>` updates offline. Keep `SHA256SUMS`, `SHA256SUMS.sig`, and the release archive together. Sources in `/home` or `/tmp` work.
- `sudo pipe update --proxy <url>` updates online through an HTTP(S) or SOCKS5 proxy. The updater also honors `HTTPS_PROXY` in its environment.

Disconnect and quit the Pipe app before updating a Helper with an active TUN session.

```sh
sudo pipe server uninstall --dir /var/lib/pipe         # remove services and keep state
sudo pipe server uninstall --dir /var/lib/pipe --purge # also delete state and device keys
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
