// Pipe desktop UI. Vanilla JS, no dependencies, no external requests.
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const ICONS = {
  home: '<path d="M3 11l9-7 9 7v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/>',
  routing: '<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="12" r="2"/><path d="M6 7v10M8 5h3a5 5 0 0 1 5 5v0M8 19h3a5 5 0 0 0 5-5v0"/>',
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
  global: ['Global', 'Everything goes through pipe.'],
  direct: ['Direct', 'Pipe is not used. Your normal connection is used.'],
};
const TIERS = {
  auto: ['Auto', 'Recommended. Fast first, switches to Stealth or Rescue if needed.'],
  fast: ['Fast', 'Hysteria2 over UDP, the quickest.'],
  stealth: ['Stealth', 'REALITY over TCP, looks like a normal website.'],
  rescue: ['Rescue', 'Through Cloudflare, works when the others are blocked.'],
};
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
    try { ta.value = text; document.body.append(ta); ta.select(); document.execCommand('copy'); } finally { ta.value = ''; ta.remove(); }
  }
  toast(msg);
}
function showBanner(msg) {
  const b = $('#banner');
  b.textContent = msg || '';
  b.hidden = !msg;
}

// ---------- API ----------
async function api(method, path, body, signal) {
  const o = { method, credentials: 'same-origin', headers: {}, signal };
  if (method !== 'GET') o.headers['X-Pipe-CSRF'] = '1';
  if (body !== undefined) { o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(body); }
  const r = await fetch('/api' + path, o);
  if (r.status === 204) return null;
  let j = null;
  try { j = await r.json(); } catch { /* no body */ }
  if (!r.ok) {
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
function applyStatus(st) {
  if (!st) return;
  S.status = st;
  const on = st.state === 'on', busy = st.state === 'connecting', err = st.state === 'error';
  const key = on ? 'on' : busy ? 'connecting' : err ? 'error' : 'off';
  const p = $('#power');
  p.dataset.s = key;
  p.setAttribute('aria-label', on || busy ? 'Disconnect' : 'Connect');
  p.setAttribute('aria-pressed', String(on));
  $('#hero-title').textContent = on ? 'Connected' : busy ? 'Connecting…' : err ? 'Could not connect' : 'Not connected';
  let sub;
  if (on) {
    const parts = [st.profile, tierName(st.tier)];
    if (st.relayState === 'via') parts.push(`via ${st.relay}`);
    else if (st.relayState === 'direct') parts.push('relay not reachable, direct');
    if (st.latencyMs != null) parts.push(`${st.latencyMs} ms`);
    sub = parts.filter(Boolean).join(' · ');
    if (st.connectedSince) sub += ` · Connected for ${fmtDur(Date.now() - new Date(st.connectedSince))}`;
  } else if (busy) sub = `Reaching ${st.server || st.profile || 'your server'}…`;
  else sub = st.profile ? `${st.profile} · Tap the button to connect` : 'Tap the button to connect';
  $('#hero-sub').textContent = sub;
  showBanner(err ? st.lastError || 'Something went wrong while connecting.' : (S.note || ''));

  const strip = $('#proxy-strip');
  strip.hidden = !on;
  if (on) {
    const sp = st.systemProxy, addr = st.listen || '127.0.0.1:7890';
    $('#proxy-dot').className = 'dot ' + (sp === 'on' ? 'on' : sp === 'error' ? 'err' : '');
    const tunMode = st.via === 'tun' || (S.settings && S.settings.tun);
    $('#tun-badge').hidden = st.via !== 'tun';
    $('#proxy-text').textContent = tunMode ? `Not needed in TUN mode · ${addr}` : sp === 'on' ? `System proxy on · ${addr}`
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
  $('#route-ms').textContent = on && st.latencyMs != null ? `${st.latencyMs} ms` : '—';
  $('#route-note').textContent = on
    ? (st.tierPreference && st.tierPreference !== 'auto' ? `Pinned to ${tierName(st.tierPreference)}.` : 'Auto: pipe switches routes if one stops working.')
    : 'Pipe picks the best route for you.';
  $('#test-routes').disabled = !on || S.testing;
  $('#test-routes2').disabled = !on || S.testing;
  // mode
  $$('#home-mode button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.mode === st.mode)));
  $('#mode-note').textContent = (MODES[st.mode] || [])[1] || '';
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
  if (on && !direct && st.latencyMs != null) label += ` · ${st.latencyMs} ms`;
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
  const none = S.profiles && S.profiles.profiles.length === 0;
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
  const off = st.state === 'on' || st.state === 'connecting';
  const prev = st;
  S.note = '';
  applyStatus({ ...st, state: off ? 'off' : 'connecting', lastError: '' });
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
    S.status = { ...S.status, routes: (r && r.routes) || {} };
    toast('Routes tested');
  } catch (e) { toast(e.status === 409 ? 'Connect first, then test.' : e.message); }
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
  $$('.tile', mt).forEach((t) => t.setAttribute('aria-checked', String(t.dataset.mode === st.mode)));
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
    const k = t.dataset.tier, lat = (st.routes || {})[k];
    t.setAttribute('aria-checked', String(k === (st.tierPreference || 'auto')));
    const dis = k === 'rescue' && !rescueOk;
    t.disabled = dis;
    $('p', t).textContent = dis ? 'Not available: this profile has no Rescue route.' : TIERS[k][1];
    const pl = $('.pill', t);
    pl.hidden = !lat || k === 'auto';
    if (lat) { pl.textContent = lat.ok ? `${lat.ms} ms` : 'No answer'; pl.className = 'pill ' + (lat.ok ? 'ok' : 'bad'); }
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
    st.data.cmd = '';
    st.data = null;
  }
  const hadFocus = st.box.contains(document.activeElement);
  st.box.querySelectorAll('code').forEach((c) => { c.textContent = ''; });
  const show = secretPlaceholder(st.name, st.box);
  st.box.replaceChildren(show);
  if (hadFocus) show.focus({ preventScroll: true });
}

function secretPlaceholder(name, box) {
  return h('button', { class: 'btn small', type: 'button', onclick: (event) => revealSecret(name, box, event.currentTarget) }, 'Show device link');
}

function secretField(label, getValue, toastMsg) {
  return h('div', { class: 'dlink-field' },
    h('span', { class: 'muted small-text' }, label),
    h('div', { class: 'code' },
      h('code', {}, getValue()),
      h('button', { class: 'btn small', type: 'button', onclick: () => { const v = getValue(); if (v) copy(v, toastMsg); } }, 'Copy')));
}

async function revealSecret(name, box, btn) {
  hideSecrets();
  const state = { box, name, abort: new AbortController() };
  secretState = state;
  btn.disabled = true;
  btn.textContent = 'Loading…';
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
    cmd: (res && res.export) || '',
  };
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

  const fields = [secretField('Link', () => data.link, 'Device link copied')];
  if (data.proxy) {
    fields.push(
      secretField('HTTPS proxy', () => data.proxy, 'HTTPS proxy URL copied'),
      secretField('Terminal command', () => data.cmd, 'Terminal command copied'),
    );
  } else {
    fields.push(h('p', { class: 'muted small-text dlink-note' }, 'This link has no HTTPS proxy.'));
  }

  const hideBtn = h('button', { class: 'btn small', type: 'button', onclick: hideSecrets }, 'Hide');
  box.replaceChildren(
    h('div', { class: 'dlink-head' },
      h('span', { class: 'dlink-title' }, h('b', {}, 'Device link'), h('span', { class: 'muted small-text' }, 'Hides automatically after 30 s.')),
      hideBtn),
    h('div', { class: 'dlink-body' },
      qrWrap,
      qrBig,
      h('div', { class: 'dlink-fields' }, ...fields)),
  );
  state.data = data;
  state.timer = setTimeout(hideSecrets, SECRET_TTL_MS);
}

let profileLoad = 0;
async function loadProfiles() {
  const request = ++profileLoad;
  try {
    const profiles = await api('GET', '/profiles');
    if (request !== profileLoad) return;
    for (const previous of S.profiles?.profiles || []) {
      const current = profiles.profiles.find((p) => p.name === previous.name);
      const relayChanged = current?.relay?.host !== previous.relay?.host || current?.relay?.on !== previous.relay?.on;
      if (!current || current.rev !== previous.rev || relayChanged) {
        clearProfileTest(previous.name, relayChanged ? undefined : current?.rev);
      }
    }
    S.profiles = profiles;
    renderProfiles();
    updatePowerEnabled();
    renderRoutingTiles();
    renderPath();
  } catch (e) { if (request === profileLoad) toast(e.message); }
}
const PROFILE_TIERS = ['fast', 'stealth', 'rescue'];
const profileResults = new Map();
let profileBatch = null;

function countryName(code) {
  if (!code) return '';
  try { return new Intl.DisplayNames(undefined, { type: 'region' }).of(code) || code; }
  catch { return code; }
}

function renderProfileTest(name) {
  const row = document.getElementById(`profile-row-${name}`);
  const profile = S.profiles?.profiles.find((p) => p.name === name);
  if (!row || !profile) return;
  const completed = profileResults.get(name);
  const result = completed?.rev === profile.rev ? completed : undefined;
  const job = profileBatch?.get(name);
  const phase = job?.rev === profile.rev ? job?.state : undefined;
  const pending = ({ queued: 'Queued', testing: 'Testing…' })[phase];
  const state = $('.profile-state', row);
  state.textContent = pending || result?.error || '';
  state.title = pending ? '' : result?.error || '';
  const country = $('.profile-country', row);
  country.textContent = country.title = result?.country || '';
  $$('.profile-metric', row).forEach((cell, i) => {
    const tier = PROFILE_TIERS[i], probe = result?.routes?.[tier];
    let value = '—';
    if (probe?.ok) value = `${probe.ms} ms`;
    else if (probe?.ok === false) value = 'No reply';
    else if (!profile.routes?.includes(tier)) value = 'n/a';
    else if (!result && phase === 'testing') value = '…';
    cell.classList.toggle('muted', !probe?.ok);
    cell.replaceChildren(h('span', { class: 'sr' }, tierName(tier) + ' '),
      probe?.ok && probe.via === 'relay' ? h('small', { class: 'muted profile-via' }, 'via relay ') : '', value);
  });
}

function updateProfileTestButton() {
  $('#test-profiles').disabled = !!profileBatch || !S.profiles?.profiles.length;
}

function clearProfileTest(name, keepRevision) {
  const job = profileBatch?.get(name);
  if (job && (!keepRevision || job.rev !== keepRevision)) {
    job.abort?.abort();
    profileBatch.delete(name);
  }
  if (profileResults.delete(name) || job) renderProfileTest(name);
}

function cancelProfileTests() {
  const batch = profileBatch;
  if (!batch) return;
  profileBatch = null;
  for (const [name, job] of batch) {
    job.abort?.abort();
    renderProfileTest(name);
  }
  updateProfileTestButton();
}

async function testAllProfiles() {
  const profiles = S.profiles?.profiles;
  if (profileBatch || !profiles?.length) return;
  const batch = new Map(profiles.map(({ name, rev }) => [name, { rev, state: 'queued' }]));
  profileBatch = batch;
  for (const name of batch.keys()) renderProfileTest(name);
  updateProfileTestButton();
  const queue = batch.entries();
  let refresh;
  const worker = async () => {
    while (profileBatch === batch) {
      const next = queue.next();
      if (next.done) return;
      const [name, job] = next.value;
      job.abort = new AbortController();
      job.state = 'testing';
      renderProfileTest(name);
      let result;
      try {
        const { rev, routes, exitCountry } = await api('POST', `/profiles/${encodeURIComponent(name)}/test`, undefined, job.abort.signal);
        result = { rev, routes, country: countryName(exitCountry) };
      } catch (e) { result = { rev: job.rev, error: e.message }; }
      if (profileBatch !== batch || !batch.has(name)) continue;
      let profile = S.profiles?.profiles.find((p) => p.name === name);
      if (profile && result.rev !== profile.rev) {
        // Keep this reply pending while the list catches up to its revision.
        job.rev = result.rev;
        profileResults.delete(name);
        renderProfileTest(name);
        refresh ||= loadProfiles().finally(() => { refresh = null; });
        await refresh;
        profile = S.profiles?.profiles.find((p) => p.name === name);
      }
      if (profileBatch !== batch || !batch.delete(name)) continue;
      if (profile && result.rev === profile.rev) profileResults.set(name, result);
      renderProfileTest(name);
    }
  };
  try { await Promise.all([worker(), worker()]); }
  finally {
    if (profileBatch === batch) {
      profileBatch = null;
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

function renderProfiles() {
  hideSecrets();
  const list = $('#profile-list');
  const profiles = S.profiles?.profiles || [];
  list.parentElement.hidden = !profiles.length;
  list.replaceChildren(...profiles.map((p) => {
    const active = p.name === S.profiles.active;
    const nameID = `profile-name-${p.name}`, detailsID = `profile-details-${p.name}`;
    const name = h('button', {
      class: 'profile-name', type: 'button', id: nameID, title: p.name,
      'aria-expanded': 'false', 'aria-controls': detailsID, 'aria-current': active ? 'true' : null,
      onclick: (event) => toggleProfileDetails(event.currentTarget),
    }, h('span', { class: 'profile-check', 'aria-hidden': 'true' }, active ? '✓' : ''),
    h('span', { class: 'profile-label' }, p.name));
    const row = h('div', { id: `profile-row-${p.name}`, class: 'profile-grid profile-row' },
      h('div', { class: 'profile-identity' }, name, h('small', { class: 'profile-state muted', role: 'status' })),
      h('small', { class: 'profile-country muted' }), PROFILE_TIERS.map(() => h('span', { class: 'profile-metric' })),
      active ? null : h('button', { class: 'btn small ghost', type: 'button', 'aria-label': `Use ${p.name}`, onclick: () => activate(p.name) }, 'Use'));
    const dlink = h('div', { class: 'dlink' });
    dlink.append(secretPlaceholder(p.name, dlink));
    return h('div', {}, row,
      h('div', { class: 'profile-details', id: detailsID, hidden: true, role: 'region', 'aria-labelledby': nameID },
        h('dl', { class: 'kv' },
          h('dt', {}, 'Server'), h('dd', {}, p.server),
          h('dt', {}, 'Key fingerprint'), h('dd', { class: 'fp' }, p.fingerprint || '—')),
        relayForm(p),
        h('div', { class: 'profile-actions' }, dlink,
          h('button', { class: 'btn small', type: 'button', onclick: () => renameSheet(p.name) }, 'Rename'),
          h('button', { class: 'btn small danger', type: 'button', onclick: () => confirmSheet(`Delete “${p.name}”?`, 'The link is removed from this device. You can add it again later with the same link.', 'Delete', () => delProfile(p.name)) }, 'Delete'))));
  }));
  for (const { name } of profiles) renderProfileTest(name);
  updateProfileTestButton();
}
async function activate(name) {
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
  $$('#page-settings input.sw[data-k]').forEach((i) => { i.checked = !!s[i.dataset.k]; });
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
  try { S.settings = await api('PUT', '/settings', S.settings); renderSettings(); }
  catch (e) { S.settings = prev; renderSettings(); toast(e.message); }
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
  if (page === 'settings') { renderSettings(); loadAbout(); refreshHelper(); }
  if (page === 'home' && document.visibilityState === 'visible') { drawSpark(); renderPath(); }
  $('#main').scrollTop = 0;
}
async function tick() {
  if (document.visibilityState !== 'visible') return;
  try {
    applyStatus(await api('GET', '/status'));
    if (S.fails >= 3) S.note = '';
    S.fails = 0;
    if (S.page === 'logs') pollLogs();
  } catch (e) {
    if (++S.fails >= 3) { S.note = 'Lost contact with Pipe. Open it again from your apps.'; showBanner(S.note); }
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
    try { await api('POST', '/quit'); veil('Pipe has quit', 'You can close this window.'); } catch (e) { toast(e.message); return false; }
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
    else renderPath();
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
      await api('POST', '/session', { nonce: decodeURIComponent(m[1]) });
      history.replaceState(null, '', '/');
    }
    const [st, , s] = await Promise.all([api('GET', '/status'), loadProfiles(), api('GET', '/settings')]);
    S.settings = s; applyTheme(s.theme);
    applyStatus(st);
  } catch (e) {
    if (e.status === 401 || e.status === 403 || m) veil('Open Pipe again from your apps', 'This window is not connected to Pipe any more.');
    else veil('Pipe is not responding', 'Open Pipe again from your apps.');
    return;
  }
  setInterval(tick, 1000);
}
boot();
