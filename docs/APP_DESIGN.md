# pipe apps v0.5.0-alpha: design and contract

The design of the Pipe apps (desktop, Android, Pipe Helper and the macOS menu bar).

## 0. Decisions

| # | Question | Decision | Why |
|---|---|---|---|
| D1 | Simple VPN app or detailed Verge app? | **Both, layered.** A Verge-style sidebar app whose Home page is a plain VPN screen (one big power button + 3 cards). Everything else (Routing, Logs, Profiles, Settings) is one click away. | Beginners see one button; power users get Verge depth. |
| D2 | Desktop tech | Pure-Go local web UI in a Chromium `--app` window with a private profile. | Builds for every OS from Linux and adds about 0.3 MB. No Electron, no Java, no cgo. |
| D3 | Routing model ("router") | **Three layers, evaluated in this order:** (1) **Rules**: ordered, first match wins, actions Proxy/Direct/Block. (2) **Mode**: Smart (China and LAN direct, the rest through pipe), Global (all through pipe), Direct (pipe off). (3) **Route**, which tunnel proxied traffic uses: Auto (Fast → Stealth → Rescue failover), or Fast, Stealth or Rescue pinned. LAN and private addresses always go direct. | This is the real data flow of the engine. Showing it in this order teaches the user how decisions are made. |
| D4 | Rule types | Domain (exact), Domain suffix, Keyword, IP/CIDR, **App** (process name on desktop, package on Android). | These already exist in `config.parseRule`. App rules are the most-requested Verge feature. |
| D5 | Latency | A "Test" button on the Route card probes each available route once and shows ms per route. The active route's latency comes from failover probes and the connect-time probe. There is no constant background probing (keeps D16's quiet pattern). | Verge-style delay test without extra traffic fingerprints. |
| D6 | Logs | Live page with a level filter (Errors / Warnings / Info / Debug), search, pause, copy and clear. Memory only (1,000 lines), **never written to disk**. Normal stream-close noise is demoted to Debug. **Info** shows every connection and which route it took, so the logs explain routing. Default level: Warnings (setting: "Log detail: Normal / Every connection"). | The user wants real logs. Memory-only keeps the privacy of the browsing record. |
| D7 | System proxy | On by default when connecting from the desktop app. pipe sets and clears the OS proxy itself, with a bypass list and crash repair. If the OS isn't supported (Linux without GNOME/KDE), the app shows "Local proxy only: set your apps to 127.0.0.1:7890". | Works for browsers and most apps without admin rights. |
| D8 | Full VPN (TUN) on desktop | Not in the app for v0.5 (needs admin). The Settings → Advanced card shows the exact terminal command. | Ships sooner; the CLI covers it. |
| D9 | Window lifecycle | Closing the window while **disconnected** quits pipe. Closing while **connected** keeps pipe running in the background (traffic keeps flowing). Opening Pipe again brings the window back. **Quit** is in the sidebar. | There's no tray in v0.5, so this is the least surprising behaviour. |
| D10 | Start at login | Setting, default off. Starts in the background without a window and connects if "Connect when Pipe starts" is on. | Fits a background service. |
| D11 | Profiles | Import by pasting a `pipe://` link. A confirm sheet shows the server, routes and key fingerprint before saving (D8 of BETA). Rename, delete, set active. **One link can be shared by several devices** (verified 2026-11-23). | Matches the server design. |
| D12 | Look | Verge-like: left sidebar, rounded cards, soft shadows, indigo primary, teal "connected", light and dark following the OS (override in Settings). System fonts. Subtle motion only. | Clean, familiar, light. |
| D13 | Version | `0.5.0-alpha` everywhere (CLI, desktop, Android `versionName`, `versionCode` 5). | One release line. |
| D14 | Home router (OpenWrt) | Not in v0.5. Recorded as a later milestone (linux-arm64/mipsle `pipe run --tun` with LAN sharing). | Different product surface. |

## 1. Shared Go pieces (builder A1)

### 1.1 `internal/version`
`const Version = "0.5.0-alpha"`. It's used by `pipe version`, `mobile.Version()` and the desktop API.

### 1.2 `internal/logring`
- `Ring` keeps the last N entries (default 1,000) with a monotonically increasing `Seq uint64`.
- Entry: `{seq, time (RFC3339 ms), level ("error"|"warn"|"info"|"debug"), source ("pipe"|"core"), message}`.
- Functions:
  - `Add(level, source, msg)`
  - `Since(after uint64, limit int) (entries []Entry, next uint64)`
  - `Clear()`
  - `SetLevel(minLevel)`: entries below the level are dropped on Add
  - `Writer() log.PlatformWriter`: adapts sing-box `WriteMessage(level, msg)`
- **Noise filter:** messages matching any of these are demoted to `debug`:
  - `canceled by remote with error code 0`
  - `use of closed network connection`
  - `context canceled`
  - `: EOF` at the end
  - `connection reset by peer` on upload/download close
  - `i/o timeout` in "connection upload/download closed" lines
- The ANSI color codes sing-box may add are stripped.
- Messages are capped at 2 KB and are safe for concurrent use.
- The CLI (`pipe run`) prints through the same filter to stderr (warn and above), so the user's "stream canceled… error code 0" line disappears.

### 1.3 Engine plumbing (`internal/engine`)
- `Options.CountBytes func(up, down int64)` at the **top level**, working for mixed and TUN inbounds. `VPN.CountBytes` keeps working: Android passes it there, or the code moves it, but behaviour stays the same.
- `Options.LogWriter log.PlatformWriter` → `box.Options.PlatformLogWriter`. When set, nothing is written to stderr by sing-box.
- `Instance.Probe` also reports latency. Either change the signature to `ProbeLatency(ctx, tier, burst) (time.Duration, bool, error)` and keep `Probe` as a wrapper, or add a callback. The latency is the round-trip time of the probe request.

### 1.4 `config`
- Export `ParseRule(text string) (Rule, error)` (wrapping `parseRule`) and `FormatRule(Rule) string`.
- Add `ClientOptions.LogLevel` ("warn" default | "info" | "debug") → sing-box `log.level`.

### 1.5 `internal/clientctl`: desktop session controller (new; Android keeps `mobile/bridge.go`)

```go
type Options struct {
    Profile  link.Profile
    Mode     string        // smart|global|direct
    Tier     failover.Tier // auto|fast|stealth|rescue
    IPv6     bool
    Rules    []config.Rule
    Listen   string        // loopback addr:port, default 127.0.0.1:7890
    LogLevel string        // warn|info|debug
}
type RouteLatency struct { Ms int64 `json:"ms"`; OK bool `json:"ok"`; At time.Time `json:"at"` }
type Status struct {
    State           string                   `json:"state"`  // off|connecting|on|error
    Profile         string                   `json:"profile"`
    Server          string                   `json:"server"` // host only
    Mode            string                   `json:"mode"`
    TierPreference  string                   `json:"tierPreference"`
    Tier            string                   `json:"tier"`   // active route: fast|stealth|rescue|direct|""
    RescueAvailable bool                     `json:"rescueAvailable"`
    LatencyMs       *int64                   `json:"latencyMs"` // null until measured
    Routes          map[string]RouteLatency  `json:"routes"`
    Listen          string                   `json:"listen"`
    UpBytes, DownBytes int64                 // json upBytes, downBytes
    UpRate, DownRate   int64                 // json upBytesPerSecond, downBytesPerSecond
    ConnectedSince  *time.Time               `json:"connectedSince"`
    LastError       string                   `json:"lastError"`
}
func New(logs *logring.Ring) *Controller
func (c *Controller) Start(opts Options) error   // starts or replaces; returns after the listener is up
func (c *Controller) Stop() error
func (c *Controller) Status() Status
func (c *Controller) SetMode(mode string) error  // live, rebuilds the engine
func (c *Controller) SetTier(tier string) error  // live, no rebuild when possible
func (c *Controller) Apply(opts Options) error   // re-apply rules/ipv6/listen/log level if running
func (c *Controller) TestRoutes(ctx context.Context) map[string]RouteLatency // probes each available route once
```

- Behaviour mirrors `cmd/pipe/run`: failover controller in Auto, `OnNetworkChange` reset, byte counting with 1 s rates.
- State goes off → connecting → on, or error with a short friendly `LastError`.
- Lifecycle events go to the ring as `source:"pipe"` info lines:
  - "Connected to phone via Fast (42 ms)"
  - "Route switched: Fast → Stealth (Fast stopped answering)"
  - "Disconnected"
- **It never touches OS proxy settings;** the desktop layer does that.

### 1.6 `mobile/` additions (Android API, keep everything existing working)
- **Status JSON** gains `latencyMs` (number or null), `routes` (same shape as desktop) and `connectedSince` (unix ms or 0).
- **Prefs JSON** gains:
  - `rules`: a list of rule objects (§3.4)
  - `logLevel`: "warn"|"info"
- **New functions:**
  - `func Logs(after int64) string` → `{"next":N,"entries":[…]}`
  - `func ClearLogs()`
  - `func TestRoutes() string` (blocking, at most 12 s, JSON map; also stored in status)
  - `Version()` returns `version.Version`
- One process-wide ring feeds the bridge's engine through `Options.LogWriter`.

## 2. Desktop app (builder A2: Go server; builder B: web UI)

### 2.1 Commands and binaries
- `pipe app [--background] [--no-window] [--dir DIR]`. `--no-window` prints the URL (for tests and headless use).
- Build-time default: `-ldflags "-X main.defaultCommand=app"` makes a binary with no arguments run `pipe app`. This is used for `Pipe.exe` (also `-H=windowsgui`) and for the macOS `Pipe.app` binary.
- **macOS hand-off (D37):** when `pipe app` runs from inside `*.app/Contents/MacOS/` without `--background` or `--no-window`, it starts a detached copy of itself (new session, `PIPE_APP_DETACHED=1`) and exits. This way macOS never keeps a running Pipe.app to send "reopen" requests to, which pipe can't answer. The copy does the normal startup below.
- `pipe app --install-desktop-entry` (Linux) writes `~/.local/share/applications/pipe.desktop` and the icon, so Pipe appears in the app menu.
- Config dir: `os.UserConfigDir()/pipe` (Windows `%APPDATA%\pipe`), holding:
  - `app.json`: settings and rules, 0600
  - `profiles/NAME.link`: 0600, the same dir the CLI uses, so profiles are shared with `pipe run`
  - `ui-profile/`: the browser profile
  - `app.lock`, `app.instance` (port + show-secret), `proxy.armed`

### 2.2 Server
- Listens on `127.0.0.1:0` (random port).
- Startup sequence: **single-instance lock** (flock / CreateMutexW).
  - If another instance holds it: read `app.instance`, POST `/internal/show` with its secret (header `X-Pipe-Show`), then exit 0.
  - If the holder is dead (health probe fails): take over.
- **Window:** look for Edge/Chrome/Chromium/Brave per OS and launch:
  ```
  --app=http://127.0.0.1:PORT/#boot=NONCE --user-data-dir=<cfg>/ui-profile
  --no-first-run --no-default-browser-check --disable-extensions
  --no-proxy-server --window-size=1040,700
  ```
  If none is found, open the default browser (`open` / `xdg-open` / `rundll32 url.dll,FileProtocolHandler`).
  - Watch the window process. When it exits and the state is off, quit the app (D9).
- **Session:** each `#boot=` nonce is single-use with a 10 s TTL.
  - `POST /api/session {"nonce":"…"}` → `Set-Cookie: pipe_session=<256-bit>; HttpOnly; SameSite=Strict; Path=/`.
  - Every `/api/*` call (except session) needs the cookie.
  - Every non-GET call also needs `X-Pipe-CSRF: 1`, `Origin` equal to `http://127.0.0.1:PORT`, and (when sent) `Sec-Fetch-Site: same-origin`.
  - Host must equal `127.0.0.1:PORT` exactly, otherwise 403.
- **Headers:** `Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'`, plus `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
- **Static files:** UI files are embedded from `internal/desktop/ui/` (`//go:embed ui`).

### 2.3 OS integration
- **System proxy** (`internal/sysproxy`, per OS, pure Go):
  - **Windows:** HKCU `Internet Settings` ProxyEnable/ProxyServer/ProxyOverride (`<local>;localhost;127.*;10.*;172.16.*` … `192.168.*`), then `InternetSetOptionW` (wininet via x/sys/windows LazyDLL) to refresh.
  - **macOS:** `networksetup` for every enabled network service: `-setwebproxy`, `-setsecurewebproxy`, `-setsocksfirewallproxy`, and `-setproxybypassdomains` with local, LAN and *.local entries.
  - **Linux:** `gsettings` (GNOME) or `kwriteconfig5/6` (KDE). Anything else → `ErrUnsupported`, which the UI shows as "Local proxy only".
  - **Crash repair:** before setting, save the previous values to `proxy.armed` (0600). On clean disconnect, quit or SIGTERM, restore and delete the file. On startup, if `proxy.armed` exists, restore from it first.
- **Autostart:**
  - Windows: HKCU `…\Run\Pipe` = `"<exe>" app --background`
  - macOS: `~/Library/LaunchAgents/io.pipe.app.plist`
  - Linux: `~/.config/autostart/pipe.desktop`
- **Single instance:** `flock` on Unix, a named mutex on Windows.

### 2.4 HTTP API (JSON; errors return `{"error":"friendly text"}` with 4xx/5xx)

| Method & path | Body → Response |
|---|---|
| POST `/api/session` | `{nonce}` → 204 + cookie |
| GET `/api/status` | → `Status` (§1.5) plus `"systemProxy": "on"\|"off"\|"unsupported"\|"error"` and `"systemProxyNote"` |
| POST `/api/connect` | `{}` → Status (uses the active profile and saved settings) |
| POST `/api/disconnect` | → Status |
| PUT `/api/mode` | `{"mode":"smart"}` → Status (saved too) |
| PUT `/api/tier` | `{"tier":"auto"}` → Status (saved too) |
| POST `/api/routes/test` | → `{"routes":{"fast":{"ms":42,"ok":true,"at":"…"},…}}` (requires connected) |
| GET `/api/profiles` | → `{"active":"phone","profiles":[{"name","server","routes":["fast","stealth","rescue"],"fingerprint"}]}`. **Never returns the link.** |
| POST `/api/profiles/preview` | `{"link"}` → `{"name","server","routes","fingerprint","exists":bool}` |
| POST `/api/profiles` | `{"link","name"}` → profile (name: `[a-z0-9][a-z0-9-_]{0,31}` after lowercasing; default is the link's name) |
| PATCH `/api/profiles/{name}` | `{"name":"new"}` → profile |
| DELETE `/api/profiles/{name}` | → 204 (disconnects first if it's in use) |
| POST `/api/profiles/{name}/activate` | → Status (reconnects if connected) |
| GET `/api/routing` | → `{"mode","tier","rules":[{"type","value","action"}]}` |
| PUT `/api/routing` | same shape → saved and applied live; `400 {"error","index"}` for a bad rule |
| GET `/api/settings` | → `{"systemProxy":true,"connectOnLaunch":false,"startAtLogin":false,"listenPort":7890,"ipv6":true,"logDetail":"normal"\|"connections","theme":"system"\|"light"\|"dark"}` |
| PUT `/api/settings` | same → saved and applied (port/IPv6/log changes re-apply live) |
| GET `/api/logs?after=N&limit=500` | → `{"next":N,"entries":[…]}` |
| DELETE `/api/logs` | → 204 |
| GET `/api/about` | → `{"version","os","arch","configDir","cliCommand":"pipe run --tun …"}` |
| POST `/api/quit` | → 204; disconnects, restores the proxy, exits |

### 2.5 Rule object (desktop API and Android prefs)
`{"type":"domain"|"suffix"|"keyword"|"ip"|"app","value":"…","action":"proxy"|"direct"|"block"}`
- The mapping to `config.ParseRule` text:
  - `domain` → `value`
  - `suffix` → `suffix:value`
  - `keyword` → `keyword:value`
  - `ip` → `value` (IP or CIDR)
  - `app`: desktop → `process:value`; Android → `app:value`
- At most 500 rules.

## 3. Desktop UI (builder B), `internal/desktop/ui/`

- **Files:** `index.html`, `app.css`, `app.js`, `logo.svg` and `favicon.svg`. Vanilla JS with ES modules allowed; no frameworks, no CDN. Under 80 KB total, uncompressed.
- **Window:** 1040×700, minimum 820×560. Left sidebar 216 px: the logo plus the word **pipe**, then nav items with simple inline SVG icons:
  - **Home**
  - **Routing**
  - **Profiles**
  - **Logs**
  - **Settings**

  At the bottom of the sidebar: a live ↑/↓ speed, a status dot, and **Quit**.
- **Home:**
  - The hero card holds a 120 px round power button. Off is grey, Connecting is an indigo spinning ring, On is teal with a soft glow.
  - Next to it, big text: "Connected" / "Not connected" / "Connecting…", then a sub-line: "phone · Fast · 42 ms".
  - Below, a three-card grid:
    - **Route:** the active route with a colored pill and latency, and a Test button.
    - **Mode:** a segmented control Smart / Global / Direct, each with a one-line explanation.
    - **Traffic:** ↑↓ rates, a 60 s sparkline (canvas) and session totals.
  - A thin strip shows "System proxy on · 127.0.0.1:7890", with a copy button for `export https_proxy=http://127.0.0.1:7890 http_proxy=…`.
  - Errors appear as a red inline banner with the friendly message.
  - **Empty state** (no profile): a friendly card, "Add your server", with a paste field and an Import button.
- **Routing:**
  - **Header:** a diagram of the 3 layers (Rules → Mode → Route) as three connected chips that explain the order.
  - **Section "Mode":** three large selectable tiles with icons and explanations:
    - Smart: China and local sites go direct, everything else through pipe.
    - Global: everything goes through pipe.
    - Direct: pipe is not used.
  - **Section "Route":** four tiles:
    - **Auto** (recommended): Fast first, switches to Stealth or Rescue if needed.
    - **Fast**: Hysteria2 over UDP, the quickest.
    - **Stealth**: REALITY over TCP, looks like a normal website.
    - **Rescue**: through Cloudflare, works when the others are blocked.

    Each tile shows its latency badge after Test; Rescue is disabled with a note if the profile has no Rescue.
  - **Section "Rules":**
    - an ordered table (#, type, value, action pill: Proxy indigo / Direct teal / Block red)
    - row actions: move up, move down, delete
    - an "Add rule" row: type select, value input, action select, Add
    - Save is automatic with a toast ("Rules applied"), and the UI validates as you type
    - help text: "Rules are checked top to bottom before the mode. LAN is always direct."
- **Profiles:**
  - Profile cards show the name, server, route badges and a short fingerprint, with Active as a check/badge. Actions: Use, Rename, Delete (confirm).
  - "Add profile": a paste textarea → Preview → a confirm sheet (server, routes, fingerprint, editable name) → Save.
- **Logs:**
  - Toolbar: level segmented (Errors / Warnings / Info / All), search, Pause/Resume, Copy, Clear.
  - A virtual-free simple list capped at 1,000 rows: monospace, time, colored level, source tag, message.
  - Auto-scroll unless the user has scrolled up. Poll `/api/logs` every 1 s only while the page is visible.
- **Settings** (grouped cards):
  - **General:** Start at login · Connect when Pipe starts · Theme (System/Light/Dark)
  - **Network:** Set system proxy when connected · Local proxy port · IPv6
  - **Logs:** Log detail (Normal / Every connection)
  - **Advanced:** "Full VPN (all apps)" explanation with the copyable CLI command (D8); config folder path
  - **About:** version, OS
- **Behaviour:**
  - Poll `/api/status` every 1 s while visible (`document.visibilityState`).
  - Optimistic UI with rollback on error, keyboard accessible, `prefers-reduced-motion` respected.
  - **Boot:** read `#boot=`, POST `/api/session`, then `history.replaceState` to `/`. If the session fails, show "Open Pipe again from your apps".
- **Palette** (CSS variables):

  | Role | Light | Dark |
  |---|---|---|
  | primary | `#4F46E5` | `#818CF8` |
  | connected | `#0D9488` | `#2DD4BF` |
  | danger | `#DC2626` | `#F87171` |
  | warn | `#D97706` | |
  | bg | `#F4F5F9` | `#0F1115` |
  | surface | `#FFFFFF` | `#181B22` |
  | surface-2 | `#F0F1F6` | `#20242D` |
  | text | `#1E2230` | `#E7E9EF` |
  | muted | `#6B7280` | `#9BA3B1` |
  | border | `#E4E6EC` | `#2A2F3A` |

  Radius 14 px, shadow `0 1px 2px rgba(0,0,0,.06), 0 4px 16px rgba(0,0,0,.05)`.
- **Logo:** a rounded square with an indigo→teal diagonal gradient and a white stylized "p" formed by a tunnel arc. The same mark is used for the app icons (§4) and Android.

## 4. Packaging (builder A2), `scripts/package-desktop.sh` → `dist/`

| Output | Contents |
|---|---|
| `pipe-macos-arm64.zip`, `pipe-macos-amd64.zip` | `Pipe.app`: Info.plist with `LSUIElement` true, bundle id `io.pipe.app`, `CFBundleExecutable` Pipe, the icon `Pipe.icns`, plus `Contents/MacOS/Pipe` built with `defaultCommand=app`. Zipped with Python's zipfile, keeping mode 0755 via `external_attr`. Also contains the CLI `pipe`. |
| `pipe-windows-amd64.zip` | `Pipe.exe` (windowsgui, `defaultCommand=app`, icon and manifest via a committed `.syso` from go-winres: asInvoker, PerMonitorV2 DPI) and `pipe.exe` (console CLI) |
| `pipe-linux-amd64.tar.gz`, `pipe-linux-arm64.tar.gz` | `pipe`, `README.txt` ("run `./pipe app --install-desktop-entry` once") |

- Icons (`packaging/icons/`, committed) are made from `logo.svg`: PNGs at 16–1024, plus `pipe.ico` and `pipe.icns` (Pillow can write both).
- Sizes are reported in the summary. The goal is under 32 MB per binary.

## 5. Android refresh (builder C), plain framework views, no new libraries

- **Theme:** `Theme.Material.Light.NoActionBar`, plus `values-night` `Theme.Material.NoActionBar` with the §3 palette as semantic colors.
- **Navigation:** a bottom bar with 4 tabs, done with plain views in one activity, swapping content: **Home · Routing · Logs · Settings**. Settings keeps the existing per-app screen and profiles.
- **Home:**
  - a 168 dp round power button (custom-drawn View: ring and glow animated with ValueAnimator)
  - a status line
  - a profile chip (tap to switch profiles)
  - cards for Route (with Test → `Mobile.testRoutes()` on a background thread), Mode (segmented) and Traffic (rates and totals)
- **Routing:**
  - Mode tiles and Route tiles as on desktop
  - a Rules list with add, delete and move, with rule type App = package picker from the installed apps
  - saved into prefs `rules` and applied live with `ApplyPreferences`
- **Logs:**
  - polls `Mobile.logs(after)` every 1 s while visible
  - level filter, search, copy, clear
- **Kept:** VPN service, tile, QR/link import with confirm (D8), per-app, network handling, `test/android/run.sh` ids (update the test where ids change).
- **Icon:** adaptive icon from the same mark (vector).
- **Version:** `versionName 0.5.0-alpha`, `versionCode 5`.
- **Budget:** the release APK stays within +300 KB of today's 10.85 MB (arm64).

## 7. Changes from agy's contract review (these override the sections above)

1. **Engine logs (A1):** keep `box.Options.PlatformLogWriter` **nil**.
   - Setting it forces `./cache.db` in the working directory and doesn't silence stderr.
   - Instead, after `box.New` and before `Start`, call `service.FromContext[log.Factory](ctx).AttachPlatformWriter(w)` (or the v1.14.4 equivalent), and set the decoded `Log.Output` to `os.DevNull` when `LogWriter != nil`.
   - On Android, don't force `Disabled: true` when a LogWriter is set.
2. **Android process boundary (C, A1):**
   - The Go engine lives in the `:vpn` process, so `Mobile.logs()`, `Mobile.clearLogs()` and `Mobile.testRoutes()` must be called **inside PipeVpnService** and relayed to the UI over the existing `VpnControl` Messenger IPC. Replies are capped at 64 KB, and logs are paged with `after`.
   - **Android has no `app` rule type in v0.5.** Per-app VPN in Settings already covers it, and `FindConnectionOwner` is a stub there.
   - Desktop keeps `app` (`process_name`, exact file name such as `chrome.exe` or `Google Chrome`).
3. **Routing order (A1):**
   - In `clientRoute`, private domains and `ip_is_private → lan` must come **before** user rules, so LAN is always direct (D3).
   - **Direct mode in the apps ignores all rules** (Clash-like: "pipe is not used"). clientctl and mobile drop `Rules` when `Mode == direct`. The CLI keeps its current behaviour.
4. **Contract gaps:**
   - **Reload (B):** on load without `#boot=`, first try `GET /api/status` with the cookie. Only show "Open Pipe again" on 401.
   - **Status everywhere (A2):** every endpoint documented as returning Status returns the **desktop-wrapped** status (`systemProxy`, `systemProxyNote`) with `routes` always an object (`{}`, never null).
     - `PUT /api/routing` returns the saved routing object.
     - `POST /api/routes/test` returns **409** `{"error":"Connect first"}` when off. Its results persist in `Status.routes` and `latencyMs`, so the 1 s poll shows them.
   - **Logs (A1, B):** `Since(0, limit)` returns the **newest** `limit` entries. The UI's "All" filter shows whatever was captured; capture level follows Settings → Log detail (Normal = warn, Every connection = info).
   - **Rules (A2):** after `config.ParseRule`, assert the resulting Field matches the requested `type`, so that `domain:"1.2.3.4"` or `ip:"example.com"` is a 400 with `index`.
   - **Profile names (A2):** must satisfy `config.ValidAlias`. Preview suggests a slug of `link.Name` (lowercase, invalid chars → `-`, trimmed, max 32, fallback `server`).
   - `connectedSince`: desktop uses RFC3339 (or null); Android uses unix ms (or 0).
5. **Hardening (A2):**
   - `/internal/show` requires the exact Host, a constant-time `X-Pipe-Show` compare, and **no** Origin header.
   - `POST /api/session` also requires the exact Host, the Origin and `X-Pipe-CSRF: 1`.
   - All JSON bodies are capped (64 KB; rules 256 KB).
   - Read `app.instance` and `proxy.armed` with `localfile.Read(…, true)`, which refuses symlinks.
   - The kernel lock is authoritative: never take over while it's held (retry reading `app.instance` for about 3 s).
   - Crash repair restores the saved proxy **only if the OS proxy still points at pipe's address**.
   - Windows GUI logout can't be caught reliably in v0.5, so crash repair on the next launch covers it (documented).
   - Escape paths in plist, `.desktop` and Registry values.

## 8. M6 (v0.5.1-alpha): TUN from the app, macOS menu bar

This section is the contract and overrides earlier sections where they differ (D8 and, on macOS, D9).

### 8.1 Decisions
- **TUN** runs inside **Pipe Helper**, a root service installed once through the OS password prompt. Only macOS and Linux get it; Windows keeps the terminal command for now.
- **Quit, Disconnect and app crashes always leave the system clean.** A session in the helper lives only while the app holds a lease (§8.2). The helper stays installed but idle.
- **Menu bar:** native macOS menu bar icon in pure Go (purego). On macOS, closing the window never quits.
- **Version:** `0.5.1-alpha` for everything, released together with the D37 reopen fix.

### 8.2 Wire protocol (app ↔ helper)
- A Unix stream socket at `helper.PathsFor(goos).Socket`.
- **Exchange:** the client sends one `Request` JSON line; the helper answers one `Response` line and closes the connection. `hold` is the only exception.
- **Limits:** a request line is at most 512 KB and must arrive within 5 s. An answer can take up to 25 s (`start`, `testRoutes`).
- **Peer check, before reading:** the kernel peer uid must equal the owner record or 0. On macOS that's `unix.GetsockoptXucred(fd, SOL_LOCAL, LOCAL_PEERCRED)`, on Linux `unix.GetsockoptUcred(fd, SOL_SOCKET, SO_PEERCRED)`. Anyone else gets `{"error":"Pipe Helper belongs to another user on this computer."}`.
- **Methods** (the params are the JSON shown):

| Method | Params | Result |
|---|---|---|
| `hello` | | `{"version","protocol"}` |
| `start` | `SessionOptions` | `clientctl.Status` |
| `apply` | `SessionOptions` | `clientctl.Status` |
| `stop` | | `clientctl.Status` |
| `status` | | `clientctl.Status` |
| `setMode` | `{"mode"}` | `clientctl.Status` |
| `setTier` | `{"tier"}` | `clientctl.Status` |
| `testRoutes` | | `{"routes":{…}}` |
| `logs` | `{"after":N,"limit":N}` | `{"entries":[…],"next":N}` |
| `hold` | | `{}` at once, then the connection stays open until EOF |

- **Lease:**
  - After `start`, the session needs at least one open `hold`. If none arrives within 10 s, the helper stops the session; the same happens 5 s after the last `hold` closes. Stopping removes the TUN and its routes.
  - The app opens `hold` right after `start` succeeds. If the hold drops while the session should run, it re-dials every 1 s. `Stop` closes it.
- **Validation in the helper** (`DecodeOptions`):
  - `link.Parse` must succeed; mode and tier must be valid.
  - At most 500 rules, each at most 1 KB, and each passes `config.ParseRule`.
  - `listen` is `127.0.0.1:P` with P from 1024 to 65535; `logLevel` is warn, info or debug.
  - TUN is always on, and its addresses, name and stack are fixed by the helper.
- **Privacy:** the helper never writes the link, rules or traffic to disk or stderr. Its log ring is memory-only, and stderr gets only start and fatal lines.

### 8.3 `internal/helper` (builder B1)
- **App side, `Remote`** (signatures in `remote.go`):
  - **`Start`/`Apply`:** encode with `EncodeOptions` (`profile.Encode()`, `config.FormatRule`) and call the helper. After a successful `Start`, also hold the lease and pump the helper's `logs` into `RemoteOptions.Logs` every 1 s.
  - **`Stop`:** sends stop with a 3 s timeout, then closes the hold and the pump. With no session it's a quick no-op.
  - **`Status`:** has a 2 s timeout. When the helper doesn't answer it returns `State:"error"`, `LastError:"Pipe Helper isn't answering."` and an empty `Routes` map.
  - **`Info`:** cached for 3 s, from `hello` with a 1 s timeout:
    - no socket or refused → `missing` ("Pipe Helper isn't installed.")
    - another version → `outdated` ("Pipe Helper needs an update.")
    - an error answer → `error`, with its text
    - otherwise `ok`
    - an OS without paths → `unsupported`
  - **`Install`/`Remove`:** run `<Exe> helper install --uid <os.Getuid()>` (or `helper remove`) with elevation, then drop the Info cache and wait up to 5 s for `ok` (or `missing`):
    - **macOS:** `osascript -e 'on run argv' -e 'do shell script (quoted form of item 1 of argv) & " helper install --uid " & item 2 of argv with prompt "Pipe wants to install Pipe Helper so TUN can start without asking again." with administrator privileges' -e 'end run' <exe> <uid>`. Output containing `-128` means `ErrCanceled`.
    - **Linux:** `pkexec <exe> helper install --uid <uid>`. Exit 126 means `ErrCanceled`. When pkexec is missing, the error says: "Run this once in a terminal: sudo '<exe>' helper install --uid <uid>".
- **Service side, `pipe helper …`** (`cmd/pipe/helper.go`):
  - **`run`:** root only. Reads the owner record and serves the socket. It removes a stale path only if that path is a socket, and sets the socket to mode 0600 owned by the owner uid. Uses `clientctl.New(ring)`; on SIGTERM or SIGINT it stops the session and exits.
  - **`install --uid N`:** root only. N must be > 0 and an existing user.
    - Copies its own resolved executable to `Paths.Binary` (temp file in the same dir, fsync, 0755, root owner, rename) and writes `Paths.Owner` (`N\n`, 0644).
    - **macOS:** writes the LaunchDaemon (Label `io.pipe.helper`, ProgramArguments `[Binary, "helper", "run"]`, RunAtLoad, KeepAlive), then runs `launchctl bootout system/io.pipe.helper` (errors ignored) and `launchctl bootstrap system <plist>`.
    - **Linux:** writes the unit (`ExecStart=<Binary> helper run`, `Restart=always`, `RestartSec=2`, `RuntimeDirectory=pipe-helper`, `NoNewPrivileges=yes`, `ProtectHome=yes`, `PrivateTmp=yes`, `WantedBy=multi-user.target`), then runs `systemctl daemon-reload`, `enable`, `restart`.
    - Running it again is an upgrade.
  - **`remove`:** root only. Stops and unloads the service and deletes exactly the four paths, plus the owner directory if it's empty.
  - **`status`:** any user. Prints Info in plain words.
- **Never** run or read anything from the user's folders as root, except copying the executable at install time.

### 8.4 Engine (builder B2)
- `config.ClientOptions.TUNListen bool`: with `TUN`, also add the loopback `mixed` inbound on `Listen` (no `set_system_proxy`). Routing treats both inbounds the same; DNS hijack stays TUN-only. Not for Mobile.
- `clientctl.build` sets `TUN` and `TUNListen` from `Options.TUN`. `friendly()` maps TUN creation failures to "Pipe Helper couldn't create the TUN device. Another VPN may be using it." It checks TUN before the port messages.

### 8.5 Desktop server (builder B2)
- **Routing the session:**
  - `Settings.TUN` (default false). The server keeps `via` ("", "proxy" or "tun") under `s.mu`.
  - `active()` is `cfg.Helper` when via is tun, otherwise `cfg.Controller`. Every session call uses `active()`: status, StateIsOff, live mode/tier/apply, testRoutes.
- **`connect()`:**
  - **With TUN:** `cfg.Helper == nil` is a 400 "TUN isn't available on this system yet.". If Info isn't ok, it's a 409 with code `needHelper` and the Info note. Otherwise stop the local session, clear the proxy, and start in the helper with `opts.TUN = true`; via becomes tun.
  - **Without TUN:** stop the helper session if via is tun, then go local exactly as today.
- **`Shutdown()`** stops both sessions (`Helper.Stop()` when the helper isn't nil) and restores the proxy. via becomes "".
- **`StatusResponse`:** `Via` is via while running, otherwise "". `Helper` is `Info()`, or `{state:"unsupported"}` when there's no helper. `systemProxy` is off while via is tun.
- **`putSettings`:**
  - Turning `tun` on when the helper isn't ok is a 409 `needHelper`, and nothing is saved.
  - Changing `tun` while connected reconnects through the other path, inside `transact`.
  - In TUN mode, `systemProxy` is saved but not applied.
- `apiError` gets `code` (JSON `"code"`).
- **New endpoints:**
  - `GET /api/helper` → Info
  - `POST /api/helper/install` → Info, or 400 `{"error":"Cancelled.","code":"canceled"}`
  - `POST /api/helper/remove`: when via is tun, disconnect first and save `tun:false`, then remove → Info
- **`inproc.go`:**
  - `SetSystemProxy(on)` is the same as the settings change.
  - `SetTUN(on)` installs the helper first when it isn't ok (blocks on the OS prompt), then does the same as the settings change.
- The app hooks in `app.go` (`Started`, `KeepRunning`, `Server()`, `Show()`, `SetKeepRunning`) and `cmd/pipe/ui_*.go` are already done; keep them.
- Tests use a fake Helper.

### 8.6 macOS menu bar (builder B3, `internal/menubar/*_darwin.go`)
- **Setup:** use purego (`github.com/ebitengine/purego` and its `objc` package, v0.10.0 from the module cache) to load AppKit. Then `NSApplication sharedApplication`, `setActivationPolicy: 1` (accessory), and one registered delegate class.
- **Delegate methods:**
  - `applicationShouldHandleReopen:hasVisibleWindows:` → `go Open()`; return NO.
  - `applicationShouldTerminate:` → `go Quit()`; return NSTerminateLater. When Stop comes, reply YES.
  - `menuNeedsUpdate:` and the item actions.
- **Main-thread rule:** never call `Actions.State` on the main thread (it can wait on a connect). A goroutine polls `State()` every 1 s into an atomic. A 1 s `NSTimer` on the main thread and `menuNeedsUpdate:` read only that cache. Actions run with `go`.
- **Status item:** a template image, an outline glyph when off and a filled glyph when on. While connecting it's dimmed (`appearsDisabled`). The tooltip comes from State.
- **Menu:** as described here. Route lists Rescue only when available. The TUN item is hidden when `!TUNAvailable`. System proxy is disabled while TUN is on. Quit has the ⌘Q key equivalent.
- **`Stop()`:** works from any goroutine, by `dispatch_async_f` to the main queue. It replies YES to a pending terminate, otherwise calls `[NSApp stop:nil]` and posts a dummy application-defined event. A Stop before Run makes Run return nil.
- **Errors:** any setup failure returns an error and Pipe runs without the icon.
- **Icons:** made by `scripts/make-menubar-icons.py` (PIL) from the logo shape: black and alpha, 36×36, shown at 18 pt. The PNGs are committed and embedded.

### 8.7 Web UI (builder B4, `internal/desktop/ui/`)
- **Home:**
  - A **System proxy | TUN** segmented switch under the power button, reflecting `settings.tun`. TUN is disabled with an explanation when `status.helper.state` is unsupported.
  - Choosing TUN while the helper isn't ok opens a sheet. Title: "Turn on TUN?". Text: "TUN sends every app on this Mac through pipe, including Terminal and games. Your Mac asks for your password once to install Pipe Helper. After that, TUN starts by itself." ("computer" instead of "Mac" off macOS; for outdated: "Pipe Helper needs an update.") Buttons: **Install and turn on** / Cancel. While waiting, the button reads "Waiting for your password…".
  - After the sheet: `POST /api/helper/install` → `PUT /api/settings` with `tun:true`. A canceled install shows the toast "Cancelled.".
  - The status card shows a "TUN" badge when `status.via` is tun. The system proxy line reads "Not needed in TUN mode".
- **Settings:**
  - The System proxy toggle is disabled with that note while TUN is on.
  - Advanced: the **Pipe Helper** card replaces the terminal-command card. It shows "Not installed" / "Running v… " / "Needs update" / the error note, with Install/Update and Remove buttons (Remove asks first). When unsupported, it shows the old `cliCommand`.
- Keep the CSP (no inline script or style), and match the existing look.
