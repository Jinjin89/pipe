// Pipe desktop UI. Vanilla JS, no dependencies, no external requests.
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const ICONS = {
  home: '<path d="M3 11l9-7 9 7v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/>',
  routing: '<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="12" r="2"/><path d="M6 7v10M8 5h3a5 5 0 0 1 5 5v0M8 19h3a5 5 0 0 0 5-5v0"/>',
  chain: '<path d="M10 13a4 4 0 0 0 6 .3l4-4a4 4 0 0 0-6-5.3l-2.3 2.3M14 11a4 4 0 0 0-6-.3l-4 4a4 4 0 0 0 6 5.3l2.3-2.3"/>',
  profiles: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  logs: '<path d="M5 4h14v16H5z"/><path d="M8 9h8M8 13h8M8 17h5"/>',
  settings: '<path d="M4 7h10M18 7h2M4 17h2M10 17h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/>',
  quit: '<path d="M10 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h5M16 8l4 4-4 4M20 12H9"/>',
  power: '<path d="M12 3v8"/><path d="M6.4 6.6a8 8 0 1 0 11.2 0"/>',
  smart: '<path d="M12 3l2.2 5.8L20 11l-5.8 2.2L12 19l-2.2-5.8L4 11l5.8-2.2z"/>',
  global: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
  direct: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  auto: '<path d="M12 3l2.2 5.8L20 11l-5.8 2.2L12 19l-2.2-5.8L4 11l5.8-2.2z"/>',
  fast: '<path d="M13 3L5 14h6l-1 7 8-11h-6z"/>',
  stealth: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  computer: '<rect x="3" y="4.5" width="18" height="12" rx="2"/><path d="M12 16.5v3m-4 0h8"/>',
  relay: '<path d="M3.5 8h16m-4-4 4 4-4 4M20.5 16h-16m4-4-4 4 4 4"/>',
  cloud: '<path d="M7 18.5a4.5 4.5 0 0 1-.6-9 5.7 5.7 0 0 1 10.8-.6 4.8 4.8 0 0 1 0 9.6Z"/>',
  server: '<rect x="4" y="4.5" width="16" height="6" rx="2"/><rect x="4" y="13.5" width="16" height="6" rx="2"/><path d="M8 7.5h.1M8 16.5h.1M12 7.5h4m-4 9h4"/>',
  internet: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
  rescue: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.5"/><path d="M5.6 5.6l3.9 3.9M14.5 14.5l3.9 3.9M18.4 5.6l-3.9 3.9M9.5 14.5l-3.9 3.9"/>',
};
const icon = (n) => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[n] || ''}</svg>`;

const MODES = {
  smart: ['Smart', 'China and local sites go direct, everything else goes through pipe.'],
  global: ['Global', 'Routes apps using the system proxy through Pipe. Your bypass rules still apply.'],
  direct: ['Direct', 'Pipe is not used. Your normal connection is used.'],
};
const TIERS = {
  auto: ['Auto', 'Recommended. Fast first, switches to Stealth or Rescue if needed.'],
  fast: ['Fast', 'Hysteria2 over UDP, the quickest.'],
  stealth: ['Stealth', 'REALITY over TCP, looks like a normal website.'],
  rescue: ['Rescue', 'Through Cloudflare, works when the others are blocked.'],
};
function modeSummary(mode, via) {
  if (mode === 'global') {
    if (via === 'tun' || (!via && S.settings?.tun)) return 'Routes device traffic through Pipe. Your bypass rules still apply.';
    if (S.settings?.systemProxy === false) return 'Routes apps using the local proxy through Pipe. Your bypass rules still apply.';
  }
  return MODES[mode]?.[1] || '';
}
const tierName = (t) => (TIERS[t] ? TIERS[t][0] : t === 'direct' ? 'Direct' : t || '');

// ---------- helpers ----------
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'html') e.innerHTML = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(c));
  return e;
}
const fmtRate = (b) => (b < 1024 ? `${Math.round(b)} B/s` : b < 1048576 ? `${(b / 1024).toFixed(b < 10240 ? 1 : 0)} KB/s` : `${(b / 1048576).toFixed(1)} MB/s`);
const fmtBytes = (b) => (b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(0)} KB` : b < 1073741824 ? `${(b / 1048576).toFixed(1)} MB` : `${(b / 1073741824).toFixed(2)} GB`);
function fmtDur(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const hr = Math.floor(m / 60);
  return hr < 24 ? `${hr}h ${m % 60}m` : `${Math.floor(hr / 24)}d ${hr % 24}h`;
}
const fmtTime = (iso) => { const d = new Date(iso); return isNaN(d) ? '' : d.toTimeString().slice(0, 8); };

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2400);
}
async function copy(text, msg = 'Copied') {
  try { await navigator.clipboard.writeText(text); } catch {
    const ta = h('textarea', { class: 'sr' });
    let ok = false;
    try { ta.value = text; document.body.append(ta); ta.select(); ok = document.execCommand('copy'); } finally { ta.value = ''; ta.remove(); }
    if (!ok) { toast('Could not copy to clipboard.'); return false; }
  }
  toast(msg);
  return true;
}
function showBanner(msg) {
  const b = $('#banner');
  b.textContent = msg || '';
  b.hidden = !msg;
}

// ---------- API ----------
const sessionKey = 'pipe.session';
let sessionToken = '';

function saveSessionToken(token) {
  sessionToken = token;
  try {
    if (token) window.sessionStorage.setItem(sessionKey, token);
    else window.sessionStorage.removeItem(sessionKey);
  } catch { /* the browser may block session storage */ }
}

function restoreSessionToken() {
  try { return window.sessionStorage.getItem(sessionKey) || ''; }
  catch { return ''; }
}

async function api(method, path, body, signal) {
  const bearer = sessionToken;
  const o = { method, credentials: 'omit', headers: {}, signal };
  if (bearer) o.headers.Authorization = 'Bearer ' + bearer;
  if (method !== 'GET') o.headers['X-Pipe-CSRF'] = '1';
  if (body !== undefined) { o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(body); }
  const r = await fetch('/api' + path, o);
  if (r.status === 204) return null;
  let j = null;
  try { j = await r.json(); } catch { /* no body */ }
  if (!r.ok) {
    if (bearer === sessionToken && (r.status === 401 || (r.status === 403 && path === '/status'))) {
      saveSessionToken('');
      hideSecrets();
      cancelProfileTests();
      veil('Open Pipe again from your apps', 'This window is not connected to Pipe any more.');
    }
    const e = new Error((j && j.error) || 'Something went wrong. Please try again.');
    e.status = r.status; e.index = j && j.index; e.code = j && j.code;
    throw e;
  }
  return j;
}

// ---------- state ----------
const S = { status: null, profiles: null, routing: null, settings: null, about: null, page: 'home', fails: 0 };
const spark = { down: Array(60).fill(0), up: Array(60).fill(0) };
const activeProfile = () => S.profiles?.profiles.find((p) => p.name === S.profiles.active);

// ---------- sheet (modal) ----------
function sheet(title, body, actions) {
  hideSecrets();
  const d = $('#sheet');
  $('#sheet-title').textContent = title;
  const b = $('#sheet-body'); b.replaceChildren(body);
  const a = $('#sheet-actions'); a.replaceChildren();
  const close = () => d.open && d.close();
  for (const x of actions) {
    a.append(h('button', { class: 'btn ' + (x.kind || ''), type: 'button', onclick: async (ev) => {
      if (x.run) { ev.target.disabled = true; try { if ((await x.run()) === false) return; } finally { ev.target.disabled = false; } }
      close();
    } }, x.label));
  }
  if (!d.open) d.showModal();
  const f = $('input,button.primary', d) || $('button', a);
  if (f) f.focus();
}
const confirmSheet = (title, text, label, run) =>
  sheet(title, h('p', { class: 'muted' }, text), [{ label: 'Cancel' }, { label, kind: 'primary', run }]);

// ---------- rendering: status ----------
function canDisconnect(st) {
  return !!st && (st.guarded || st.state === 'on' || st.state === 'connecting' || (st.state === 'error' && st.via === 'tun'));
}

function applyStatus(st) {
  if (!st) return;
  S.status = st;
  const on = st.state === 'on', busy = st.state === 'connecting', err = st.state === 'error';
  const key = on ? 'on' : busy ? 'connecting' : err ? 'error' : 'off';
  const p = $('#power');
  p.dataset.s = key;
  const disconnect = canDisconnect(st);
  p.setAttribute('aria-label', disconnect ? 'Disconnect' : 'Connect');
  p.setAttribute('aria-pressed', String(on || !!st.guarded));
  $('#hero-title').textContent = st.guarded ? 'Network traffic paused' : on ? 'Connected' : busy ? 'Connecting…' : err ? 'Could not connect' : 'Not connected';
  let sub;
  if (st.guarded) sub = 'Disconnect to release TUN.';
  else if (on) {
    const parts = [st.profile, tierName(st.tier)];
    if (st.relayState === 'via') parts.push(`via ${st.relay}`);
    else if (st.relayState === 'direct') parts.push('relay not reachable, direct');
    const measured = st.measurement?.routes?.[st.tier];
    if (measured?.ms > 0) parts.push(measured.ms + ' ms');
    sub = parts.filter(Boolean).join(' · ');
    if (st.connectedSince) sub += ` · Connected for ${fmtDur(Date.now() - new Date(st.connectedSince))}`;
  } else if (busy) sub = `Reaching ${st.server || st.profile || 'your server'}…`;
  else if (disconnect) sub = 'Disconnect to release Pipe Helper.';
  else sub = st.profile ? `${st.profile} · Tap the button to connect` : 'Tap the button to connect';
  $('#hero-sub').textContent = sub;
  showBanner(err ? st.lastError || 'Something went wrong while connecting.' : (S.note || ''));

  const strip = $('#proxy-strip');
  strip.hidden = !on;
  if (on) {
    const sp = st.systemProxy, addr = st.listen || '127.0.0.1:7890';
    $('#proxy-dot').className = 'dot ' + (sp === 'on' ? 'on' : sp === 'error' ? 'err' : '');
    const tunMode = st.via === 'tun';
    $('#copy-proxy').hidden = tunMode;
    $('#tun-badge').hidden = st.via !== 'tun';
    $('#proxy-text').textContent = tunMode ? 'Pipe Helper is routing this device' : sp === 'on' ? `System proxy on · ${addr}`
      : sp === 'unsupported' ? `Local proxy only: set your apps to ${addr}`
      : sp === 'error' ? `System proxy problem${st.systemProxyNote ? ': ' + st.systemProxyNote : ''} · ${addr}`
      : `System proxy off · ${addr}`;
  }
  renderTun();
  if (S.page === 'settings') renderHelper();
  // route card
  const pill = $('#route-pill');
  const shown = on ? st.tier : st.tierPreference || 'auto';
  pill.textContent = tierName(shown);
  pill.className = 'pill ' + shown;
  const measured = st.measurement?.routes?.[shown];
  $('#route-ms').textContent = measured ? routeValue(measured) : '—';
  $('#route-note').textContent = on
    ? (st.tierPreference && st.tierPreference !== 'auto' ? `Pinned to ${tierName(st.tierPreference)}.` : 'Auto: pipe switches routes if one stops working.')
    : 'Pipe picks the best route for you.';
  $('#test-routes').disabled = !on || S.testing;
  $('#test-routes2').disabled = !on || S.testing;
  // mode
  $$('#home-mode button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.mode === st.mode)));
  $('#mode-note').textContent = modeSummary(st.mode, st.via);
  // traffic
  const d = st.downBytesPerSecond || 0, u = st.upBytesPerSecond || 0;
  $('#t-down').textContent = fmtRate(d); $('#t-up').textContent = fmtRate(u);
  $('#t-total').textContent = `This session: ${fmtBytes(st.downBytes || 0)} down · ${fmtBytes(st.upBytes || 0)} up`;
  $('#side-down').textContent = fmtRate(d); $('#side-up').textContent = fmtRate(u);
  $('#side-dot').className = 'dot ' + (on ? 'on' : busy ? 'busy' : err ? 'err' : '');
  $('#side-state').textContent = on ? 'Connected' : busy ? 'Connecting…' : err ? 'Error' : 'Not connected';
  spark.down.push(d); spark.up.push(u);
  if (spark.down.length > 60) { spark.down.shift(); spark.up.shift(); }
  if (S.page === 'home' && document.visibilityState === 'visible') {
    drawSpark();
    renderPath();
  }
  if (S.page === 'routing') { renderRoutingTiles(); $('#rules-paused').hidden = st.mode !== 'direct'; }
  if (S.page === 'profiles') renderTestAge($('#profiles-tested-at'), S.profiles?.lastTestedAt);
  updatePowerEnabled();
}

const PATH_ROUTE_NAMES = { fast: 'Fast · UDP', stealth: 'Stealth · TCP', rescue: 'Rescue · WebSocket', direct: 'Direct' };
function pathLevel(rate, level) {
  if (rate >= (level === 3 ? 384 : 512) * 1024) return 3;
  if (rate >= (level >= 2 ? 32 : 48) * 1024) return 2;
  return rate >= (level >= 1 ? 32 : 128) ? 1 : 0;
}
function renderPath() {
  const st = S.status;
  if (!st || S.page !== 'home' || document.visibilityState !== 'visible') return;
  const card = $('#live-path');
  const on = st.state === 'on';
  const direct = on && (st.mode === 'direct' || st.tier === 'direct');
  const tier = on ? (direct ? 'direct' : st.tier) : '';
  const server = on ? st.server : activeProfile()?.server;
  let middle = 'none', middleLabel = '', middleHost = '', note = '';
  if (st.state === 'error') {
    note = st.lastError || 'Something went wrong while connecting.';
  } else if (on && !direct) {
    if (tier === 'rescue') {
      middle = 'cloud';
      middleLabel = 'Cloudflare';
      if (st.relay) note = 'Relay not used by Rescue';
    } else if (st.relay) {
      middle = st.relayState || 'unused';
      middleLabel = 'Relay';
      middleHost = st.relay;
      if (middle === 'pending') note = 'Trying relay…';
      else if (middle === 'direct') note = 'not reachable';
      else if (middle !== 'via') note = 'Relay not used by this route';
    }
  }
  let label = PATH_ROUTE_NAMES[tier];
  if (!label) {
    label = { on: 'Connected', connecting: 'Connecting…', error: 'Could not connect' }[st.state] || 'Not connected';
  }
  const measured = st.measurement?.routes?.[tier];
  if (on && !direct && measured?.ok) label += ` · ${routeValue(measured)}`;
  const moving = on && !direct && middle !== 'pending';
  const up = moving ? st.proxyUpBytesPerSecond || 0 : 0;
  const down = moving ? st.proxyDownBytesPerSecond || 0 : 0;
  const text = (id, value, title = false) => {
    const el = $(id);
    if (el.textContent === value) return;
    el.textContent = value;
    if (title) el.title = value;
  };
  const data = { state: st.state, tier, middle, up: String(pathLevel(up, +card.dataset.up)), down: String(pathLevel(down, +card.dataset.down)) };
  for (const [key, value] of Object.entries(data)) {
    if (card.dataset[key] !== value) card.dataset[key] = value;
  }
  const node = $('#path-middle');
  const hidden = String(middle === 'none');
  if (node.getAttribute('aria-hidden') !== hidden) node.setAttribute('aria-hidden', hidden);
  text('#path-route', label);
  text('#path-destination-label', direct ? 'Internet' : 'Server');
  text('#path-server', direct ? '' : server || '', true);
  text('#path-middle-label', middleLabel);
  text('#path-middle-host', middleHost, true);
  text('#path-note', note, true);
  text('#path-up', fmtRate(up));
  text('#path-down', fmtRate(down));
}
const helperState = () => (S.status && S.status.helper && S.status.helper.state) || '';
const thisComputer = () => (S.about && S.about.os && S.about.os !== 'darwin' ? 'computer' : 'Mac');
function renderTun() {
  const tun = !!(S.settings && S.settings.tun), un = helperState() === 'unsupported';
  $$('#home-tun button').forEach((b) => {
    b.setAttribute('aria-pressed', String((b.dataset.tun === 'true') === (tun && !un)));
    if (b.dataset.tun === 'true') { b.disabled = un; b.title = un ? 'TUN is not available on this system yet.' : ''; }
  });
  const n = $('#tun-note');
  n.hidden = !un;
  n.textContent = un ? 'TUN is not available on this system yet.' : '';
}
async function setTun(on) {
  if (!S.settings) return;
  if (!on) return saveTun(false);
  if (helperState() !== 'ok') return askHelper();
  return saveTun(true);
}
async function saveTun(on) {
  try {
    S.settings = await api('PUT', '/settings', { ...S.settings, tun: on });
    renderSettings();
    tick();
    return true;
  } catch (e) {
    if (e.code === 'needHelper') { askHelper(); return false; }
    toast(e.message); return false;
  }
}
function askHelper() {
  const outdated = helperState() === 'outdated', pc = thisComputer();
  const text = `${outdated ? 'Pipe Helper needs an update. ' : ''}TUN sends every app on this ${pc} through pipe, including Terminal and games. Your ${pc} asks for your password once to ${outdated ? 'update' : 'install'} Pipe Helper. After that, TUN starts by itself.`;
  sheet('Turn on TUN?', h('p', { class: 'muted' }, text), [
    { label: 'Cancel' },
    { label: 'Install and turn on', kind: 'primary', run: async () => {
      const btn = $('#sheet-actions .primary');
      if (btn) btn.textContent = 'Waiting for your password…';
      try { await api('POST', '/helper/install'); }
      catch (e) { toast(e.code === 'canceled' ? 'Cancelled.' : e.message); refreshHelper(); return false; }
      finally { if (btn) btn.textContent = 'Install and turn on'; }
      await refreshHelper();
      return (await saveTun(true)) ? undefined : false;
    } },
  ]);
}
async function refreshHelper() {
  try { const info = await api('GET', '/helper'); if (S.status) S.status.helper = info; } catch { /* status poll covers it */ }
  renderTun(); renderHelper(); tick();
}
function renderHelper() {
  const hp = (S.status && S.status.helper) || {}, st = hp.state || '';
  const un = st === 'unsupported';
  const label = { missing: 'Not installed', ok: `Running${hp.version ? ' v' + String(hp.version).replace(/^v/, '') : ''}`, outdated: 'Needs update', unsupported: 'Not available on this system', error: 'Problem' }[st] || '-';
  $('#helper-state').textContent = label;
  $('#helper-note').textContent = st === 'error' ? (hp.note || 'Pipe Helper has a problem.')
    : un ? 'This system cannot run TUN from the app yet.' : 'Lets TUN start without asking for your password each time.';
  const inst = $('#helper-install'), rem = $('#helper-remove');
  inst.hidden = !(st === 'missing' || st === 'outdated' || st === 'error');
  inst.textContent = st === 'outdated' ? 'Update' : 'Install';
  rem.hidden = !(st === 'ok' || st === 'outdated');
  $('#cli-box').hidden = !un;
}
async function installHelper(ev) {
  const b = ev.currentTarget, t = b.textContent;
  b.disabled = true; b.textContent = 'Waiting for your password…';
  try { await api('POST', '/helper/install'); toast('Pipe Helper is ready.'); }
  catch (e) { toast(e.code === 'canceled' ? 'Cancelled.' : e.message); }
  b.disabled = false; b.textContent = t;
  refreshHelper();
}
function removeHelper() {
  confirmSheet('Remove Pipe Helper?', `TUN turns off. Your ${thisComputer()} asks for your password.`, 'Remove', async () => {
    try { await api('POST', '/helper/remove'); S.settings = await api('GET', '/settings'); renderSettings(); toast('Pipe Helper removed.'); }
    catch (e) { toast(e.code === 'canceled' ? 'Cancelled.' : e.message); refreshHelper(); return false; }
    refreshHelper();
  });
}
function updatePowerEnabled() {
  const none = S.profiles && S.profiles.profiles.length === 0 && !canDisconnect(S.status);
  $('#home-empty').hidden = !none;
  $('#home-main').hidden = !!none;
}
function drawSpark() {
  const c = $('#spark');
  if (!c.offsetWidth) return;
  const dpr = window.devicePixelRatio || 1, w = c.offsetWidth, hh = 46;
  c.width = w * dpr; c.height = hh * dpr;
  const g = c.getContext('2d'); g.scale(dpr, dpr);
  const cs = getComputedStyle(document.documentElement);
  const max = Math.max(2048, ...spark.down, ...spark.up);
  const line = (arr, col, fill) => {
    if (arr.length < 2) return;
    const step = w / 59, off = (60 - arr.length) * step;
    g.beginPath();
    arr.forEach((v, i) => { const x = off + i * step, y = hh - 3 - (v / max) * (hh - 8); i ? g.lineTo(x, y) : g.moveTo(x, y); });
    g.strokeStyle = col; g.lineWidth = 1.6; g.lineJoin = 'round'; g.stroke();
    if (fill) { g.lineTo(w, hh); g.lineTo(off, hh); g.closePath(); g.globalAlpha = 0.14; g.fillStyle = col; g.fill(); g.globalAlpha = 1; }
  };
  line(spark.down, cs.getPropertyValue('--on').trim() || '#0D9488', true);
  line(spark.up, cs.getPropertyValue('--primary').trim() || '#4F46E5', false);
}

// ---------- actions ----------
async function togglePower() {
  const st = S.status;
  if (!st) return;
  const off = canDisconnect(st);
  const prev = st;
  S.note = '';
  applyStatus({ ...st, state: off ? 'off' : 'connecting', guarded: false, lastError: '' });
  try { applyStatus(await api('POST', off ? '/disconnect' : '/connect', {})); }
  catch (e) {
    applyStatus(prev);
    if (e.code === 'needHelper') { await refreshHelper(); askHelper(); }
    else showBanner(e.message);
  }
}
async function setMode(mode) {
  const prev = S.status;
  if (!prev || prev.mode === mode) return;
  applyStatus({ ...prev, mode });
  try { applyStatus(await api('PUT', '/mode', { mode })); if (S.routing) S.routing.mode = mode; renderRoutingTiles(); }
  catch (e) { applyStatus(prev); toast(e.message); }
}
async function setTier(tier) {
  const prev = S.status;
  if (!prev || prev.tierPreference === tier) return;
  applyStatus({ ...prev, tierPreference: tier });
  try { applyStatus(await api('PUT', '/tier', { tier })); if (S.routing) S.routing.tier = tier; renderRoutingTiles(); }
  catch (e) { applyStatus(prev); toast(e.message); }
}
async function testRoutes() {
  if (S.testing) return;
  S.testing = true;
  $$('#test-routes,#test-routes2').forEach((b) => { b.disabled = true; b.textContent = 'Testing…'; });
  try {
    const r = await api('POST', '/routes/test');
    if (!publishMeasurement(r)) await loadProfiles();
  } catch (e) { toast(e.message); }
  S.testing = false;
  $('#test-routes').textContent = 'Test'; $('#test-routes2').textContent = 'Test routes';
  applyStatus(S.status);
}

// ---------- routing page ----------
function activeProfileRoutes() {
  const p = activeProfile();
  return p ? p.routes : null;
}
function renderRoutingTiles() {
  const st = S.status || {};
  const mt = $('#mode-tiles');
  if (!mt.children.length) {
    for (const k of Object.keys(MODES)) {
      mt.append(h('button', { class: 'tile', role: 'radio', 'data-mode': k, onclick: () => setMode(k) },
        h('span', { class: 't-top' }, h('span', { class: 'ic', html: icon(k) }), h('b', {}, MODES[k][0])), h('p', {}, MODES[k][1])));
    }
  }
  $$('.tile', mt).forEach((t) => {
    t.setAttribute('aria-checked', String(t.dataset.mode === st.mode));
    $('p', t).textContent = modeSummary(t.dataset.mode, st.via);
  });
  renderTestAge($('#route-tested-at'), st.measurement?.completedAt);
  const tt = $('#tier-tiles');
  const routes = activeProfileRoutes();
  const rescueOk = st.rescueAvailable != null ? st.rescueAvailable : routes ? routes.includes('rescue') : true;
  if (!tt.children.length) {
    for (const k of Object.keys(TIERS)) {
      tt.append(h('button', { class: 'tile', role: 'radio', 'data-tier': k, onclick: () => setTier(k) },
        h('span', { class: 't-top' }, h('span', { class: 'ic', html: icon(k) }), h('b', {}, TIERS[k][0]), h('span', { class: 'pill', hidden: true })), h('p', {}, TIERS[k][1])));
    }
  }
  $$('.tile', tt).forEach((t) => {
    const k = t.dataset.tier, lat = st.measurement?.routes?.[k];
    t.setAttribute('aria-checked', String(k === (st.tierPreference || 'auto')));
    const dis = k === 'rescue' && !rescueOk;
    t.disabled = dis;
    $('p', t).textContent = dis ? 'Not available: this profile has no Rescue route.' : TIERS[k][1];
    const pl = $('.pill', t);
    pl.hidden = !lat || k === 'auto';
    if (lat) {
      pl.textContent = routeValue(lat);
      pl.className = 'pill ' + (lat.ok ? 'ok' : 'bad');
      pl.title = lat.ok && !lat.ms ? 'The server returned one valid reply' : lat.via === 'relay' ? 'via relay' : '';
    }
  });
}
const TYPE_LABEL = { domain: 'Domain', suffix: 'Domain suffix', keyword: 'Keyword', ip: 'IP / CIDR', app: 'App' };
const PLACEHOLDER = { domain: 'www.example.com', suffix: 'example.com', keyword: 'example', ip: '203.0.113.0/24', app: 'chrome.exe or Google Chrome' };
function validateRule(type, v) {
  v = v.trim();
  if (!v) return 'Type a value.';
  if (type === 'ip') {
    const m = v.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
    if (m) return m[1].split('.').every((n) => +n <= 255) && (m[2] == null || +m[2] <= 32) ? '' : 'That IP address or prefix is out of range.';
    return /^[0-9a-f:]+(\/\d{1,3})?$/i.test(v) && v.includes(':') ? '' : 'Use an IP like 203.0.113.5 or a range like 203.0.113.0/24.';
  }
  if (type === 'app') return /[\\/]/.test(v) ? 'Use the exact program file name only, like chrome.exe or Google Chrome.' : '';
  if (/\s/.test(v)) return 'No spaces, please.';
  if (type === 'suffix' || type === 'domain') return /^[a-z0-9_.*-]+(\.[a-z0-9_-]+)*$/i.test(v) || /[^\x00-\x7f]/.test(v) ? '' : 'That does not look like a domain.';
  return '';
}
function renderRules(badIndex) {
  const rules = (S.routing && S.routing.rules) || [];
  const body = $('#rules-body');
  body.replaceChildren(...rules.map((r, i) => h('tr', { class: i === badIndex ? 'bad' : '' },
    h('td', { class: 'n' }, String(i + 1)),
    h('td', {}, TYPE_LABEL[r.type] || r.type),
    h('td', { class: 'v' }, r.value),
    h('td', {}, h('span', { class: 'pill ' + r.action }, r.action[0].toUpperCase() + r.action.slice(1))),
    h('td', { class: 'acts' },
      h('button', { class: 'btn small ghost', 'aria-label': `Move rule ${i + 1} up`, disabled: i === 0, onclick: () => moveRule(i, -1) }, '↑'),
      h('button', { class: 'btn small ghost', 'aria-label': `Move rule ${i + 1} down`, disabled: i === rules.length - 1, onclick: () => moveRule(i, 1) }, '↓'),
      h('button', { class: 'btn small ghost', 'aria-label': `Delete rule ${i + 1}`, onclick: () => saveRules(rules.filter((_, j) => j !== i)) }, '✕')))));
  $('#rules-table').hidden = !rules.length;
  $('#rules-empty').hidden = !!rules.length;
  $('#rules-paused').hidden = !(S.status && S.status.mode === 'direct');
}
async function saveRules(rules) {
  const prev = S.routing;
  S.routing = { ...prev, rules };
  renderRules();
  try {
    const r = await api('PUT', '/routing', { mode: prev.mode, tier: prev.tier, rules });
    if (r) S.routing = r;
    renderRules(); toast('Rules applied');
    return true;
  } catch (e) {
    S.routing = prev; renderRules(e.index);
    $('#r-hint').textContent = e.message;
    return false;
  }
}
const moveRule = (i, d) => { const a = [...S.routing.rules]; [a[i], a[i + d]] = [a[i + d], a[i]]; saveRules(a); };
function checkRuleForm() {
  const t = $('#r-type').value, v = $('#r-value').value;
  const msg = v ? validateRule(t, v) : '';
  $('#r-hint').textContent = msg;
  $('#r-add').disabled = !v.trim() || !!msg || ((S.routing && S.routing.rules.length) || 0) >= 500;
}
async function loadRouting() {
  try { S.routing = await api('GET', '/routing'); renderRules(); renderRoutingTiles(); } catch (e) { toast(e.message); }
}

// ---------- profiles ----------
const SECRET_TTL_MS = 30000;

let secretState = null;

function parseSVG(text) {
  const doc = new DOMParser().parseFromString(text, 'image/svg+xml');
  const el = doc.documentElement;
  if (!el || el.tagName.toLowerCase() !== 'svg' || doc.querySelector('parsererror')) return null;
  el.setAttribute('role', 'img');
  el.setAttribute('aria-label', 'Device link QR code');
  return document.importNode(el, true);
}

function hideSecrets() {
  if (!secretState) return;
  const st = secretState;
  secretState = null;
  st.abort.abort();
  clearTimeout(st.timer);
  if (st.data) {
    st.data.link = '';
    st.data.proxy = '';
    st.data.export = '';
    st.data = null;
  }
  const hadFocus = st.box.contains(document.activeElement);
  st.box.replaceChildren();
  st.box.hidden = true;
  st.btn.textContent = 'Show device link';
  st.btn.setAttribute('aria-expanded', 'false');
  if (hadFocus) st.btn.focus({ preventScroll: true });
}

function deviceLinkControls(name) {
  const box = h('div', { id: 'device-link-' + name, class: 'dlink-reveal', hidden: true });
  const toggle = h('button', {
    class: 'btn small', type: 'button', 'aria-expanded': 'false', 'aria-controls': box.id,
    onclick: (event) => {
      const btn = event.currentTarget;
      if (secretState?.btn === btn) hideSecrets();
      else revealSecret(name, box, btn);
    },
  }, 'Show device link');
  return h('div', { class: 'dlink' }, toggle, box);
}

function secretField(label, value, copyValue) {
  return h('div', { class: 'dlink-field' },
    h('span', { class: 'muted small-text' }, label),
    h('div', { class: 'code' },
      h('code', {}, value),
      h('button', { class: 'btn small', type: 'button', onclick: copyValue }, 'Copy')));
}

async function revealSecret(name, box, btn) {
  hideSecrets();
  const state = { box, btn, abort: new AbortController() };
  secretState = state;
  btn.textContent = 'Hide device link';
  btn.setAttribute('aria-expanded', 'true');
  box.hidden = false;
  box.replaceChildren(h('p', { class: 'muted small-text', role: 'status' }, 'Loading…'));
  let res;
  try {
    res = await api('POST', `/profiles/${encodeURIComponent(name)}/secret`, undefined, state.abort.signal);
  } catch (e) {
    if (secretState !== state) return;
    hideSecrets();
    toast(e.message);
    return;
  }
  if (secretState !== state) return;
  if (!box.isConnected || document.visibilityState !== 'visible') {
    hideSecrets();
    return;
  }
  const data = {
    link: (res && res.link) || '',
    proxy: (res && res.proxy) || '',
    export: (res && res.export) || '',
  };
  const rev = res?.rev;
  const qrEl = res && res.qr ? parseSVG(res.qr) : null;
  res = null;

  const qrWrap = h('div', { class: 'dlink-qr' });
  // A phone reads a dense link best when the code is big: click to enlarge.
  // The dialog sits in the card, so hiding the card removes it too.
  let qrBig = null;
  if (qrEl) {
    qrBig = h('dialog', { class: 'qr-zoom', 'aria-label': 'Device link QR code', onclick: () => qrBig.close() }, qrEl.cloneNode(true));
    const zoom = () => { if (!qrBig.open) qrBig.showModal(); };
    qrWrap.classList.add('zoomable');
    qrWrap.setAttribute('role', 'button');
    qrWrap.setAttribute('tabindex', '0');
    qrWrap.setAttribute('title', 'Click to enlarge for scanning');
    qrWrap.addEventListener('click', zoom);
    qrWrap.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); zoom(); } });
    qrWrap.append(qrEl);
  }

  const field = (label, format, message) => secretField(label, data[format], async () => {
    if (secretState !== state || !data[format]) return;
    try {
      const result = await api('POST', `/profiles/${encodeURIComponent(name)}/copy`, { format, rev }, state.abort.signal);
      if (secretState !== state) return;
      if (result?.fallback) await copy(data[format], `${message} (system clipboard)`);
      else toast(message);
    } catch (e) {
      if (secretState === state) toast(e.message);
    }
  });
  const fields = [field('Link', 'link', 'Device link copied')];
  if (data.proxy) {
    fields.push(
      field('HTTPS proxy', 'proxy', 'HTTPS proxy URL copied'),
      field('Terminal command', 'export', 'Terminal command copied'),
    );
  } else {
    fields.push(h('p', { class: 'muted small-text dlink-note' }, 'This link has no HTTPS proxy.'));
  }

  box.replaceChildren(
    h('p', { class: 'muted small-text' }, 'Hides automatically after 30 s.'),
    h('div', { class: 'dlink-body' },
      qrWrap,
      qrBig,
      h('div', { class: 'dlink-fields' }, ...fields)),
  );
  state.data = data;
  state.timer = setTimeout(hideSecrets, SECRET_TTL_MS);
}

let profileLoad = 0;
let profileBatch = null;
const PROFILE_TIERS = ['fast', 'stealth', 'rescue'];

async function loadProfiles() {
  const request = ++profileLoad;
  try {
    const profiles = await api('GET', '/profiles');
    if (request !== profileLoad) return;
    if (S.profiles && S.profiles.active !== profiles.active) hideSecrets();
    for (const previous of S.profiles?.profiles || []) {
      const current = profiles.profiles.find((p) => p.name === previous.name);
      const relayChanged = current?.relay?.host !== previous.relay?.host || current?.relay?.on !== previous.relay?.on;
      if (!current || current.rev !== previous.rev || relayChanged) clearProfileTest(previous.name);
    }
    S.profiles = profiles;
    renderProfiles();
    updatePowerEnabled();
    renderRoutingTiles();
    renderPath();
  } catch (e) { if (request === profileLoad) toast(e.message); }
}

function publishMeasurement(result) {
  if (!result || !S.profiles) return false;
  const profile = S.profiles.profiles.find((p) => p.name === result.profile);
  if (!profile || profile.rev !== result.rev) return false;
  profileLoad++;
  profile.measurement = result;
  renderProfileTest(profile.name);
  if (S.profiles.active === profile.name && S.status) {
    statusRead++;
    S.status = { ...S.status, measurement: result };
    renderRoutingTiles();
  }
  return true;
}

function countryName(code) {
  if (!code) return '';
  try { return new Intl.DisplayNames(undefined, { type: 'region' }).of(code) || code; }
  catch { return code; }
}

function renderTestAge(node, iso) {
  const tested = Date.parse(iso);
  if (!(tested > 0)) {
    node.textContent = 'Never tested';
    node.removeAttribute('datetime');
    node.removeAttribute('title');
    return;
  }
  const min = Math.max(0, Math.floor((Date.now() - tested) / 60000));
  const age = min === 0 ? 'just now' : min < 60 ? min + ' min ago' : min < 1440
    ? Math.floor(min / 60) + ' hr ago' : Math.floor(min / 1440) + ' d ago';
  node.textContent = 'Tested ' + age;
  node.dateTime = iso;
  node.title = new Date(tested).toLocaleString();
}

function routeValue(probe) {
  return !probe.ok ? 'No reply' : probe.ms > 0 ? probe.ms + ' ms' : 'Reachable';
}

function renderMetric(cell, tier, probe, configured, testing, fastest) {
  const name = tierName(tier);
  let meaning = 'untested';
  let nodes = [h('span', { class: 'muted' }, '—')];
  cell.removeAttribute('title');
  if (!configured) {
    meaning = 'unavailable';
    nodes = [h('span', { class: 'muted' }, 'N/A')];
  } else if (probe?.ok && probe.ms > 0) {
    const relay = probe.via === 'relay';
    const quality = probe.ms < 100 ? 'Good' : probe.ms < 250 ? 'OK' : 'Slow';
    meaning = probe.ms + ' milliseconds, ' + quality + (relay ? ', via relay' : '') + (fastest ? ', fastest measured' : '');
    nodes = [relay ? h('span', { class: 'ic rtt-relay', html: icon('chain') }) : null,
      h('span', { class: 'rtt-bars ' + quality.toLowerCase() }, h('i'), h('i'), h('i')),
      h('span', { class: fastest ? 'rtt fastest' : 'rtt' }, String(probe.ms), h('span', { class: 'rtt-unit' }, 'ms'))];
  } else if (probe?.ok) {
    meaning = 'reachable, one reply' + (probe.via === 'relay' ? ', via relay' : '');
    cell.title = 'The server returned one valid reply';
    nodes = ['Reachable'];
  } else if (probe) {
    meaning = 'no reply';
    nodes = [h('span', { class: 'rtt-failed' }, '×'), 'No reply'];
  } else if (testing) {
    meaning = 'testing';
    nodes = [h('span', { class: 'profile-placeholder' })];
  }
  cell.setAttribute('aria-label', name + ', ' + meaning);
  cell.replaceChildren(h('span', { class: 'profile-metric-value', 'aria-hidden': 'true' }, nodes));
}

function renderProfileTest(name) {
  const row = document.getElementById('profile-row-' + name);
  const details = document.getElementById('profile-details-' + name);
  const profile = S.profiles?.profiles.find((p) => p.name === name);
  if (!row || !profile) return;
  const result = profile.measurement;
  const isTesting = profileBatch?.jobs.get(name)?.state === 'testing';
  const country = result?.exitCountry;
  const countryText = countryName(country);
  $('.profile-country', row).replaceChildren(country
    ? h('span', { class: 'profile-exit-chip', role: 'img', 'aria-label': countryText, title: countryText }, country)
    : h('span', { class: 'muted', role: 'img', 'aria-label': 'Exit country unknown' }, '—'));
  $('.profile-exit-detail', details).textContent = countryText || '—';
  const tested = $('.profile-exact-test', details);
  tested.textContent = result ? new Date(result.completedAt).toLocaleString() : '—';
  tested.dateTime = result?.completedAt || '';
  const numbers = PROFILE_TIERS.map((tier) => result?.routes?.[tier]).filter((r) => r?.ok && r.ms > 0);
  const min = numbers.length >= 2 ? Math.min(...numbers.map((r) => r.ms)) : 0;
  const fastest = numbers.filter((r) => r.ms === min).length === 1 ? min : 0;
  const notes = [];
  $$('.profile-metric', row).forEach((cell, i) => {
    const tier = PROFILE_TIERS[i], probe = result?.routes?.[tier];
    renderMetric(cell, tier, probe, profile.routes?.includes(tier), isTesting, fastest > 0 && probe?.ms === fastest);
    if (probe?.ok && (probe.via === 'relay' || !probe.ms)) {
      notes.push(tierName(tier) + (probe.ms ? '' : ' · one valid reply') + (probe.via === 'relay' ? ' · via relay' : ''));
    }
  });
  $('.profile-route-notes', details).textContent = notes.join('  /  ');
}

function updateProfileTestButton() {
  $('#test-profiles').disabled = !!profileBatch || !S.profiles?.profiles.length;
  renderTestAge($('#profiles-tested-at'), S.profiles?.lastTestedAt);
}

function profileProgress(text, error = false) {
  const status = $('#profile-test-progress');
  status.textContent = text;
  status.dataset.error = String(error);
}

function clearProfileTest(name) {
  const job = profileBatch?.jobs.get(name);
  job?.abort?.abort();
  profileBatch?.jobs.delete(name);
  const profile = S.profiles?.profiles.find((p) => p.name === name);
  if (profile) delete profile.measurement;
  renderProfileTest(name);
}

function cancelProfileTests() {
  const batch = profileBatch;
  if (!batch) return;
  profileBatch = null;
  for (const [name, job] of batch.jobs) {
    job.abort?.abort();
    renderProfileTest(name);
  }
  profileProgress('Tests canceled.');
  updateProfileTestButton();
}

async function testAllProfiles() {
  const profiles = S.profiles?.profiles;
  if (profileBatch || !profiles?.length) return;
  const jobs = new Map(profiles.map(({ name }) => [name, { state: 'queued' }]));
  const batch = { jobs, started: 0, completed: 0, error: '' };
  profileBatch = batch;
  const queue = jobs.entries();
  updateProfileTestButton();
  const worker = async () => {
    while (profileBatch === batch) {
      const next = queue.next();
      if (next.done) return;
      const [name, job] = next.value;
      job.abort = new AbortController();
      job.state = 'testing';
      profileProgress('Testing ' + ++batch.started + ' of ' + profiles.length);
      renderProfileTest(name);
      try {
        const result = await api('POST', '/profiles/' + encodeURIComponent(name) + '/test', undefined, job.abort.signal);
        if (profileBatch !== batch || !jobs.has(name)) continue;
        if (!publishMeasurement(result)) {
          await loadProfiles();
          if (profileBatch !== batch || !jobs.has(name)) continue;
          if (!publishMeasurement(result)) throw new Error('The profile changed during the test.');
        }
        batch.completed++;
      } catch (e) {
        if (profileBatch === batch && jobs.has(name)) batch.error = name + ' · ' + e.message;
      }
      jobs.delete(name);
      renderProfileTest(name);
    }
  };
  try {
    await Promise.all([worker(), worker()]);
    if (profileBatch !== batch) return;
    if (batch.completed === profiles.length && !batch.error) {
      const finished = await api('POST', '/profiles/test-complete');
      if (profileBatch === batch && S.profiles) {
        profileLoad++;
        S.profiles.lastTestedAt = finished.lastTestedAt;
      }
    } else {
      batch.error ||= 'The test did not finish for every profile.';
    }
  } catch (e) { batch.error = e.message; }
  finally {
    if (profileBatch === batch) {
      profileBatch = null;
      profileProgress(batch.error, !!batch.error);
      updateProfileTestButton();
    }
  }
}

function relayForm(p) {
  const relay = p.relay || {};
  const code = h('input', { type: 'text', placeholder: 'Relay IP, name or code', value: relay.host || '', spellcheck: 'false', autocapitalize: 'none' });
  const enabled = h('input', { type: 'checkbox', class: 'sw', role: 'switch', checked: !!relay.on });
  const save = h('button', { class: 'btn small', type: 'submit' }, 'Save');
  const error = h('p', { class: 'hint', role: 'alert' });
  return h('form', { class: 'profile-relay', onsubmit: async (event) => {
    event.preventDefault();
    if (save.disabled) return;
    code.disabled = enabled.disabled = save.disabled = true;
    error.textContent = '';
    try {
      const result = await api('PUT', `/profiles/${encodeURIComponent(p.name)}/relay`, { host: code.value, on: enabled.checked });
      if (p.relay?.host !== result.relay.host || p.relay?.on !== result.relay.on) {
        clearProfileTest(p.name);
      }
      p.relay = result.relay;
      code.value = p.relay.host;
      enabled.checked = p.relay.on;
      applyStatus(result.status);
      toast('Relay saved');
    } catch (e) {
      if (e.code === 'needHelper') { await refreshHelper(); askHelper(); }
      error.textContent = e.message;
    } finally {
      code.disabled = enabled.disabled = save.disabled = false;
    }
  } }, h('label', { class: 'relay-host' }, h('b', {}, 'Relay'), code),
    h('label', { class: 'relay-toggle' }, 'Use relay', enabled), save, error);
}

function toggleProfileDetails(button) {
  const opened = $('#profile-list .profile-name[aria-expanded="true"]');
  if (opened) {
    hideSecrets();
    opened.setAttribute('aria-expanded', 'false');
    document.getElementById(opened.getAttribute('aria-controls')).hidden = true;
  }
  if (button !== opened) {
    button.setAttribute('aria-expanded', 'true');
    document.getElementById(button.getAttribute('aria-controls')).hidden = false;
  }
  button.focus({ preventScroll: true });
}

function profileView(p, revision) {
  const nameID = 'profile-name-' + p.name, detailsID = 'profile-details-' + p.name;
  const name = h('button', {
    class: 'profile-name', type: 'button', id: nameID, title: p.name,
    'aria-expanded': 'false', 'aria-controls': detailsID,
    onclick: (event) => toggleProfileDetails(event.currentTarget),
  }, h('span', { class: 'profile-check', 'aria-hidden': 'true' }),
    h('span', { class: 'profile-label' }, p.name));
  const row = h('div', { id: 'profile-row-' + p.name, class: 'profile-grid profile-row' },
    name,
    h('span', { class: 'profile-country' }),
    PROFILE_TIERS.map(() => h('span', { class: 'profile-metric', role: 'img' })),
    h('button', { class: 'btn small ghost profile-use', type: 'button', 'aria-label': 'Use ' + p.name, onclick: () => activate(p.name) }, 'Use'));
  return h('div', { 'data-profile': p.name, 'data-revision': revision }, row,
    h('div', { class: 'profile-details', id: detailsID, hidden: true, role: 'region', 'aria-labelledby': nameID },
      h('dl', { class: 'kv' },
        h('dt', {}, 'Profile'), h('dd', {}, p.name),
        h('dt', {}, 'Server'), h('dd', {}, p.server),
        h('dt', {}, 'Exit'), h('dd', { class: 'profile-exit-detail' }, '—'),
        h('dt', {}, 'Tested'), h('dd', {}, h('time', { class: 'profile-exact-test' }, '—')),
        h('dt', {}, 'Key fingerprint'), h('dd', { class: 'fp' }, p.fingerprint || '—')),
      h('p', { class: 'muted small-text profile-route-notes' }),
      relayForm(p),
      h('div', { class: 'profile-actions' }, deviceLinkControls(p.name),
        h('button', { class: 'btn small', type: 'button', onclick: () => renameSheet(p.name) }, 'Rename'),
        h('button', { class: 'btn small danger', type: 'button', onclick: () => confirmSheet('Delete “' + p.name + '”?', 'The link is removed from this device. You can add it again later with the same link.', 'Delete', () => delProfile(p.name)) }, 'Delete'))));
}

function renderProfiles() {
  const list = $('#profile-list');
  const profiles = S.profiles?.profiles || [];
  list.parentElement.hidden = !profiles.length;
  $('#profiles-empty').hidden = !!profiles.length;
  const views = new Map([...list.children].map((view) => [view.dataset.profile, view]));
  for (const [i, p] of profiles.entries()) {
    const old = views.get(p.name);
    const revision = JSON.stringify([p.rev, p.relay]);
    let view = old;
    if (!view || view.dataset.revision !== revision) {
      const wasOpen = old && !$('.profile-details', old)?.hidden;
      const hadFocus = old && old.contains(document.activeElement);
      if (secretState && old?.contains(secretState.box)) hideSecrets();
      view = profileView(p, revision);
      if (wasOpen) {
        const details = $('.profile-details', view);
        const btn = $('.profile-name', view);
        if (details && btn) { details.hidden = false; btn.setAttribute('aria-expanded', 'true'); }
      }
      if (old) old.replaceWith(view);
      if (hadFocus) $('.profile-name', view)?.focus();
    }
    views.delete(p.name);
    if (list.children[i] !== view) list.insertBefore(view, list.children[i] || null);
    const row = $('.profile-row', view);
    const selected = p.name === S.profiles.active;
    row.dataset.selected = String(selected);
    const name = $('.profile-name', row);
    if (selected) name.setAttribute('aria-current', 'true');
    else name.removeAttribute('aria-current');
    $('.profile-check', name).textContent = selected ? '✓' : '';
    const useBtn = $('.profile-use', row);
    const useFocused = selected && document.activeElement === useBtn;
    useBtn.hidden = selected;
    if (useFocused) name.focus();
    renderProfileTest(p.name);
  }
  for (const view of views.values()) {
    if (secretState && view.contains(secretState.box)) hideSecrets();
    view.remove();
  }
  updateProfileTestButton();
}

async function activate(name) {
  hideSecrets();
  try { const st = await api('POST', `/profiles/${encodeURIComponent(name)}/activate`); await loadProfiles(); applyStatus(st); toast(`Using ${name}`); } catch (e) { toast(e.message); return false; }
}
async function delProfile(name) {
  try {
    await api('DELETE', `/profiles/${encodeURIComponent(name)}`);
    clearProfileTest(name);
    await loadProfiles();
    applyStatus(await api('GET', '/status'));
    toast('Profile deleted');
  } catch (e) { toast(e.message); return false; }
}
function renameSheet(name) {
  const inp = h('input', { type: 'text', value: name, 'aria-label': 'New name', maxlength: 32 });
  const note = h('p', { class: 'muted small-text' }, 'Lowercase letters, numbers, - and _. Up to 32 characters.');
  sheet('Rename profile', h('div', {}, inp, note), [{ label: 'Cancel' }, { label: 'Rename', kind: 'primary', run: async () => {
    try {
      const renamed = await api('PATCH', `/profiles/${encodeURIComponent(name)}`, { name: inp.value.trim().toLowerCase() });
      if (renamed.name !== name) clearProfileTest(name);
      await loadProfiles();
      toast('Renamed');
    }
    catch (e) { note.textContent = e.message; return false; }
  } }]);
}
async function startImport(link, field) {
  try {
    const p = await api('POST', '/profiles/preview', { link: link.trim() });
    const inp = h('input', { type: 'text', value: p.name, 'aria-label': 'Profile name', maxlength: 32 });
    const err = h('p', { class: 'hint' });
    const kv = h('dl', { class: 'kv' },
      h('dt', {}, 'Name'), h('dd', {}, inp),
      h('dt', {}, 'Server'), h('dd', {}, p.server),
      p.fast ? [h('dt', {}, 'Fast'), h('dd', {}, p.fast)] : null,
      p.stealth ? [h('dt', {}, 'Stealth'), h('dd', {}, p.stealth)] : null,
      p.httpsProxy ? [h('dt', {}, 'HTTPS proxy'), h('dd', {}, p.httpsProxy)] : null,
      p.cdn ? [h('dt', {}, 'CDN'), h('dd', {}, p.cdn)] : null,
      h('dt', {}, 'Routes'), h('dd', {}, (p.routes || []).map(tierName).join(', ')),
      h('dt', {}, 'Key'), h('dd', { class: 'fp' }, p.fingerprint || '—'));
    const body = h('div', {}, h('p', { class: 'muted small-text' }, 'Check that this matches your server before saving.'), kv,
      p.exists ? h('p', { class: 'banner warn' }, 'A profile with this name already exists. Saving will replace it.') : null, err);
    sheet('Add this server?', body, [{ label: 'Cancel' }, { label: 'Save', kind: 'primary', run: async () => {
      try {
        const saved = await api('POST', '/profiles', { link: link.trim(), name: inp.value.trim().toLowerCase() });
        clearProfileTest(saved.name);
        field.value = ''; field.dispatchEvent(new Event('input'));
        await loadProfiles(); applyStatus(await api('GET', '/status')); toast('Profile saved');
      } catch (e) { err.textContent = e.message; return false; }
    } }]);
  } catch (e) { toast(e.message); }
}

// ---------- logs ----------
const L = { entries: [], next: 0, level: 2, q: '', paused: false, busy: false };
const LV = { error: 0, warn: 1, info: 2, debug: 3 };
const logRow = (e) => h('div', { class: 'll' }, h('span', { class: 'tm' }, fmtTime(e.time)), h('span', { class: 'lv ' + e.level }, e.level === 'warn' ? 'warn' : e.level), h('span', { class: 'src' }, e.source), h('span', { class: 'msg' }, e.message));
const logMatch = (e) => LV[e.level] <= L.level && (!L.q || (e.message + ' ' + e.source).toLowerCase().includes(L.q));
function renderLogs() {
  const box = $('#logbox');
  const rows = L.entries.filter(logMatch).map(logRow);
  const empty = $('#log-empty');
  empty.hidden = !!rows.length;
  box.replaceChildren(...rows, empty);
  box.scrollTop = box.scrollHeight;
}
async function pollLogs() {
  if (L.paused || L.busy) return;
  L.busy = true;
  try {
    const r = await api('GET', `/logs?after=${L.next}&limit=500`);
    if (r.next < L.next) { L.entries = []; renderLogs(); }
    L.next = r.next;
    if (r.entries && r.entries.length) {
      const box = $('#logbox');
      const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
      L.entries.push(...r.entries);
      if (L.entries.length > 1000) L.entries.splice(0, L.entries.length - 1000);
      for (const e of r.entries) if (logMatch(e)) box.insertBefore(logRow(e), $('#log-empty'));
      while (box.children.length > 1001) box.firstChild.remove();
      $('#log-empty').hidden = L.entries.some(logMatch);
      if (stick) box.scrollTop = box.scrollHeight;
    }
  } catch { /* status poll reports connection problems */ }
  L.busy = false;
}

// ---------- settings ----------
function renderSettings() {
  const s = S.settings;
  if (!s) return;
  $$('#page-settings input.sw[data-k]').forEach((i) => { i.checked = i.dataset.k === 'updateAuto' ? s.updateAuto !== false : !!s[i.dataset.k]; });
  $$('.seg[data-k]').forEach((g) => $$('button', g).forEach((b) => b.setAttribute('aria-pressed', String(s[g.dataset.k] === b.dataset.v))));
  if (document.activeElement !== $('#s-port')) $('#s-port').value = s.listenPort;
  const tun = !!s.tun;
  $('input[data-k=systemProxy]').disabled = tun;
  $('#sp-note').textContent = tun ? 'Not needed in TUN mode' : 'Browsers and most apps then use Pipe automatically.';
  renderTun();
  applyTheme(s.theme);
}
function applyTheme(t) {
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
  if (S.page === 'home' && document.visibilityState === 'visible') drawSpark();
}
async function saveSetting(patch) {
  const prev = S.settings;
  S.settings = { ...prev, ...patch };
  renderSettings();
  try {
    S.settings = await api('PUT', '/settings', S.settings);
    renderSettings();
    if (patch.updateAuto === true) checkAutomatically();
    if (patch.ipv6 !== undefined) await loadProfiles();
  }
  catch (e) { S.settings = prev; renderSettings(); toast(e.message); }
}

let updateState, updateRequest = false, updateTimer;
const updateBusy = () => ['checking', 'downloading'].includes(updateState?.state);

function renderUpdates() {
  const { installed, state, version, error, artifact } = updateState || {};
  $('#update-installed').textContent = installed ? `v${installed.replace(/^v/, '')}` : '—';
  const messages = {
    checking: 'Checking for updates…',
    available: `Version ${version} is available.`,
    current: 'Pipe is up to date.',
    downloading: `Downloading and verifying version ${version}…`,
    ready: `Version ${version} is ready. Open the downloaded file to install it.`,
    error: error || 'Could not update Pipe.',
  };
  const status = $('#update-status');
  const message = messages[state] || '';
  if (status.textContent !== message) status.textContent = message;
  status.parentElement.hidden = !message;
  $('#update-check').disabled = updateRequest || updateBusy();
  $('#update-download').hidden = state !== 'available' && !(state === 'error' && version);
  $('#update-download').disabled = updateRequest;
  $('#update-reveal').hidden = state !== 'ready' || !artifact;
  $('#update-reveal').disabled = updateRequest;
}

async function requestUpdates(action, input) {
  if (!sessionToken || updateRequest) return;
  clearTimeout(updateTimer);
  updateRequest = true;
  renderUpdates();
  try {
    const next = await api(action ? 'POST' : 'GET', action ? '/updates/' + action : '/updates', input);
    if (next) updateState = next;
  } catch (e) {
    if (action) toast(e.message);
  } finally {
    updateRequest = false;
    renderUpdates();
    if (sessionToken && updateBusy() && document.visibilityState === 'visible') {
      updateTimer = setTimeout(requestUpdates, 1000);
    }
  }
}

function checkAutomatically() {
  if (!S.settings || document.visibilityState !== 'visible') return;
  if (S.settings.updateAuto !== false) requestUpdates('check', { automatic: true });
  else if (!updateState || updateBusy()) requestUpdates();
}
async function loadAbout() {
  try {
    S.about = await api('GET', '/about');
    $('#ab-ver').textContent = 'v' + S.about.version;
    $('#ab-os').textContent = `${S.about.os} · ${S.about.arch}`;
    $('#cli-cmd').textContent = S.about.cliCommand || 'pipe run --tun';
    $('#cfg-dir').textContent = S.about.configDir || '';
  } catch { /* optional */ }
}

// ---------- navigation and polling ----------
function go(page) {
  hideSecrets();
  if (page !== S.page) cancelProfileTests();
  S.page = page;
  $$('.page').forEach((p) => { p.hidden = p.id !== 'page-' + page; });
  $$('.nav').forEach((n) => (n.dataset.page === page ? n.setAttribute('aria-current', 'page') : n.removeAttribute('aria-current')));
  if (page === 'routing') loadRouting();
  if (page === 'profiles' || page === 'home') loadProfiles();
  if (page === 'logs') { renderLogs(); pollLogs(); }
  if (page === 'settings') { renderSettings(); loadAbout(); refreshHelper(); requestUpdates(); }
  if (page === 'home' && document.visibilityState === 'visible') { drawSpark(); renderPath(); }
  $('#main').scrollTop = 0;
}
let statusRead = 0, statusPending = false;
async function tick() {
  if (!sessionToken || statusPending || document.visibilityState !== 'visible') return;
  statusPending = true;
  const read = statusRead;
  try {
    const status = await api('GET', '/status');
    if (read !== statusRead) return;
    applyStatus(status);
    if (S.fails >= 3) S.note = '';
    S.fails = 0;
    if (S.page === 'logs') pollLogs();
  } catch (e) {
    if (++S.fails >= 3) { S.note = 'Lost contact with Pipe. Open it again from your apps.'; showBanner(S.note); }
  } finally {
    statusPending = false;
  }
}

function veil(title, text) {
  $('#veil-title').textContent = title; $('#veil-text').textContent = text; $('#veil').hidden = false;
}

function wire() {
  $$('[data-ic]').forEach((e) => { e.innerHTML = icon(e.dataset.ic); });
  $$('.nav').forEach((n) => n.addEventListener('click', () => go(n.dataset.page)));
  $('#power').addEventListener('click', togglePower);
  $$('#home-mode button').forEach((b) => b.addEventListener('click', () => setMode(b.dataset.mode)));
  $$('#home-tun button').forEach((b) => b.addEventListener('click', () => setTun(b.dataset.tun === 'true')));
  $('#helper-install').addEventListener('click', installHelper);
  $('#helper-remove').addEventListener('click', removeHelper);
  $('#test-routes').addEventListener('click', testRoutes);
  $('#test-routes2').addEventListener('click', testRoutes);
  $('#test-profiles').addEventListener('click', testAllProfiles);
  $('#copy-proxy').addEventListener('click', () => {
    const a = (S.status && S.status.listen) || '127.0.0.1:7890';
    copy(`export https_proxy=http://${a} http_proxy=http://${a} all_proxy=socks5://${a}`, 'Copied. Paste it in your terminal.');
  });
  $('#quit').addEventListener('click', () => confirmSheet('Quit Pipe?', 'This disconnects and turns off the system proxy.', 'Quit', async () => {
    try {
      await api('POST', '/quit');
      saveSessionToken('');
      veil('Pipe has quit', 'You can close this window.');
    } catch (e) { toast(e.message); return false; }
  }));
  // import fields
  for (const [ta, btn] of [['#empty-link', '#empty-import'], ['#add-link', '#add-preview']]) {
    const t = $(ta), b = $(btn);
    t.addEventListener('input', () => { b.disabled = !t.value.trim(); });
    b.addEventListener('click', () => startImport(t.value, t));
  }
  // rules
  $('#r-type').addEventListener('change', () => { $('#r-value').placeholder = PLACEHOLDER[$('#r-type').value]; checkRuleForm(); });
  $('#r-value').addEventListener('input', checkRuleForm);
  $('#add-rule').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if ($('#r-add').disabled || !S.routing) return;
    const rule = { type: $('#r-type').value, value: $('#r-value').value.trim(), action: $('#r-action').value };
    if (await saveRules([...S.routing.rules, rule])) { $('#r-value').value = ''; checkRuleForm(); }
  });
  // logs
  const lvl = () => $$('#log-level button').forEach((b) => b.setAttribute('aria-pressed', String(+b.dataset.l === L.level)));
  lvl();
  $$('#log-level button').forEach((b) => b.addEventListener('click', () => { L.level = +b.dataset.l; lvl(); renderLogs(); }));
  $('#log-search').addEventListener('input', (e) => { L.q = e.target.value.trim().toLowerCase(); renderLogs(); });
  $('#log-pause').addEventListener('click', (e) => { L.paused = !L.paused; e.target.textContent = L.paused ? 'Resume' : 'Pause'; if (!L.paused) pollLogs(); });
  $('#log-copy').addEventListener('click', () => copy(L.entries.filter(logMatch).map((e) => `${e.time} ${e.level} ${e.source} ${e.message}`).join('\n'), 'Logs copied'));
  $('#log-clear').addEventListener('click', async () => { try { await api('DELETE', '/logs'); L.entries = []; renderLogs(); } catch (e) { toast(e.message); } });
  // settings
  $$('#page-settings input.sw[data-k]').forEach((i) => i.addEventListener('change', () => saveSetting({ [i.dataset.k]: i.checked })));
  $$('.seg[data-k] button').forEach((b) => b.addEventListener('click', () => saveSetting({ [b.parentElement.dataset.k]: b.dataset.v })));
  $('#update-check').addEventListener('click', () => requestUpdates('check'));
  $('#update-download').addEventListener('click', () => requestUpdates('download'));
  $('#update-reveal').addEventListener('click', () => requestUpdates('reveal', { artifact: updateState.artifact }));
  $('#s-port').addEventListener('change', (e) => {
    const n = +e.target.value;
    if (!Number.isInteger(n) || n < 1024 || n > 65535) { toast('Pick a port between 1024 and 65535.'); e.target.value = S.settings.listenPort; return; }
    saveSetting({ listenPort: n });
  });
  $('#copy-cli').addEventListener('click', () => copy($('#cli-cmd').textContent));
  document.addEventListener('contextmenu', (e) => {
    const el = e.target && e.target.nodeType === 1 ? e.target : e.target && e.target.parentElement;
    if (!el || !el.closest('input, textarea')) e.preventDefault();
  });
  const syncVisibility = () => {
    document.documentElement.toggleAttribute('data-window-hidden', document.visibilityState !== 'visible');
    if (document.visibilityState !== 'visible') hideSecrets();
    else { renderPath(); checkAutomatically(); }
    tick();
  };
  document.documentElement.toggleAttribute('data-window-hidden', document.visibilityState !== 'visible');
  document.addEventListener('visibilitychange', syncVisibility);
  window.addEventListener('pageshow', syncVisibility);
  window.addEventListener('blur', hideSecrets);
  window.addEventListener('pagehide', () => {
    document.documentElement.setAttribute('data-window-hidden', '');
    hideSecrets();
    cancelProfileTests();
  });
  window.addEventListener('resize', () => S.page === 'home' && document.visibilityState === 'visible' && drawSpark());
}

async function boot() {
  wire();
  const m = location.hash.match(/boot=([^&]+)/);
  try {
    if (m) {
      history.replaceState(null, '', '/');
      const redeemed = await api('POST', '/session', { nonce: decodeURIComponent(m[1]) });
      if (!redeemed?.token) throw new Error('Could not open the Pipe session.');
      saveSessionToken(redeemed.token);
    } else {
      sessionToken = restoreSessionToken();
    }
    const st = await api('GET', '/status');
    const [, s] = await Promise.all([loadProfiles(), api('GET', '/settings')]);
    S.settings = s; applyTheme(s.theme);
    applyStatus(st);
    checkAutomatically();
  } catch (e) {
    if (e.status === 401 || e.status === 403 || m) {
      saveSessionToken('');
      veil('Open Pipe again from your apps', 'This window is not connected to Pipe any more.');
    } else veil('Pipe is not responding', 'Open Pipe again from your apps.');
    return;
  }
  setInterval(tick, 1000);
}
boot();
