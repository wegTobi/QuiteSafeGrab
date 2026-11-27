// QuiteSafeGrab-Oberflaeche. Keine Fremdbibliotheken, keine externen Inhalte.
// Alle Daten werden per textContent eingesetzt (nie als HTML).
'use strict';

const CHECKS = [
  ['vpn', 'VPN-Adapter'],
  ['firewall', 'Netzsperre'],
  ['selftest', 'Selbsttest'],
  ['ipv4', 'IPv4-Ausgang'],
  ['ipv6', 'IPv6'],
  ['dns', 'DNS-Ausgang'],
];
const PHASES = ['checks', 'probe', 'resolve', 'download', 'remux', 'verify'];
const STATUS = { waiting: 'wartet', running: 'läuft', done: 'fertig', failed: 'Fehler', stopped: 'angehalten' };

// ---- Zugriffstoken: kommt einmalig im #-Teil der Adresse (wird nie an den Server geschickt)
let token = '';
try { token = sessionStorage.getItem('qsgrab-token') || ''; } catch (e) { /* privater Modus */ }
const hash = new URLSearchParams(location.hash.slice(1));
if (hash.get('t')) {
  token = hash.get('t');
  try { sessionStorage.setItem('qsgrab-token', token); } catch (e) { /* ok */ }
  history.replaceState(null, '', location.pathname);
}

const $ = (id) => document.getElementById(id);

async function api(path, body) {
  const opts = { headers: { 'X-QSGrab-Token': token }, cache: 'no-store' };
  if (body !== undefined) {
    opts.method = 'POST';
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (e) { /* leer */ }
  if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
  return data;
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}

// Ortszeit vom Server (Mullvad Browser meldet Seiten absichtlich UTC). Anzeige rechnet in UTC + Versatz.
let tzOffset = -new Date().getTimezoneOffset() * 60;
let clockSkew = 0;   // Serverzeit - Browserzeit (Sekunden)
const pad = (n) => String(n).padStart(2, '0');
function serverNow() { return Date.now() / 1000 + clockSkew; }

function clock(t, seconds = true) {
  if (!t) return '–';
  const d = new Date((t + tzOffset) * 1000);
  const today = new Date((serverNow() + tzOffset) * 1000);
  const time = pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + (seconds ? ':' + pad(d.getUTCSeconds()) : '');
  const sameDay = d.getUTCFullYear() === today.getUTCFullYear() && d.getUTCMonth() === today.getUTCMonth() && d.getUTCDate() === today.getUTCDate();
  return sameDay ? time : pad(d.getUTCDate()) + '.' + pad(d.getUTCMonth() + 1) + '.' + d.getUTCFullYear() + ' ' + time;
}

function ago(t) {
  if (!t) return '';
  const s = Math.max(0, Math.round(serverNow() - t));
  if (s < 60) return 'gerade eben';
  if (s < 3600) return 'vor ' + Math.round(s / 60) + ' Min.';
  if (s < 86400) return 'vor ' + Math.round(s / 3600) + ' Std.';
  return 'vor ' + Math.round(s / 86400) + ' Tagen';
}

function bytes(n, decimals = 1) {
  if (n === null || n === undefined) return '';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? decimals : 0).replace('.', ',') + ' ' + u[i];
}

function unit(s) {
  // yt-dlp: "212.40MiB" -> "212,40 MiB"
  return s ? s.replace(/^([\d.]+)/, (m) => m.replace('.', ',') + ' ') : '–';
}

const UNITS = { B: 1, KB: 1e3, MB: 1e6, GB: 1e9, KIB: 1024, MIB: 1024 ** 2, GIB: 1024 ** 3, TIB: 1024 ** 4 };
function parseSize(s) {
  // "6.21MiB/s" oder "212.40MiB" -> Bytes; unbekannt -> null
  const m = /^([\d.]+)\s*([KMGT]?i?B)/i.exec(s || '');
  if (!m) return null;
  const f = UNITS[m[2].toUpperCase()];
  return f ? parseFloat(m[1]) * f : null;
}

function speedText(bytesPerSec) {
  // KiB/s ohne Nachkommastellen, ab 1 MiB/s mit zwei.
  if (bytesPerSec === null || !isFinite(bytesPerSec)) return '–';
  if (bytesPerSec >= 1024 ** 2) return (bytesPerSec / 1024 ** 2).toFixed(2).replace('.', ',') + ' MiB/s';
  if (bytesPerSec >= 1024) return Math.round(bytesPerSec / 1024) + ' KiB/s';
  return Math.round(bytesPerSec) + ' B/s';
}

// Was gerade passiert, solange noch nichts heruntergeladen wird.
const HINTS = {
  checks: 'Sicherheitsprüfung läuft (VPN, Firewall, IP, DNS) – der Download beginnt gleich.',
  probe: 'Kurzer Probe-Download zur Kontrolle der Verbindung – der Download beginnt gleich.',
  resolve: 'Video wird gesucht – der Download beginnt gleich.',
  download: 'Verbindung zum Video wird aufgebaut …',
  remux: 'Video wird fertiggestellt (ohne Qualitätsverlust) …',
  verify: 'Abschlussprüfung der Verbindung …',
};
function hintText(st, cur, hasProgress) {
  if (st.mode === 'check') return 'Sicherheitsprüfung läuft (VPN, Firewall, IP, DNS) …';
  if (st.mode === 'preview') return 'Titel werden gesucht – vorher und zwischendurch wird die Verbindung geprüft. Noch kein Download.';
  if (cur.phase === 'download' && hasProgress) return '';
  return HINTS[cur.phase] || '';
}

function duration(sec) {
  sec = Math.max(0, Math.round(sec));
  const h = Math.floor(sec / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
  return (h ? h + ':' + String(m).padStart(2, '0') : m) + ':' + String(s).padStart(2, '0');
}

// ---- Darstellung
function renderChecks(st) {
  const ul = $('checks');
  ul.replaceChildren();
  for (const [key, label] of CHECKS) {
    const c = st.checks[key];
    const li = el('li', c && c.ok === false ? 'problem' : '');
    const dot = el('span', 'dot');
    if (c) {
      dot.classList.add(c.ok === true ? 'good' : c.ok === false ? 'bad' : 'warn');
      if (c.stale) dot.classList.add('stale');
    }
    li.append(dot, el('span', 'check-name', label),
      el('span', 'check-detail', c ? c.detail : 'noch nicht geprüft'),
      el('span', 'check-time', c ? (c.stale ? 'zuletzt ' : '') + clock(c.time) : ''));
    if (c && c.stale) li.title = 'Ergebnis einer früheren Sitzung – vor dem nächsten Download wird neu geprüft.';
    ul.append(li);
  }
  $('last-check').textContent = st.last_check
    ? 'Letzte vollständige Prüfung: ' + clock(st.last_check) + ' (' + ago(st.last_check) + '). Vor und nach jedem Download wird automatisch erneut geprüft.'
    : 'Noch keine vollständige Prüfung in dieser Ablage. „Jetzt prüfen“ testet alles ohne Download.';

  const pill = $('overall');
  const busy = st.mode !== 'idle';
  pill.className = 'pill ' + (busy ? 'busy' : st.overall);
  pill.textContent = busy ? (st.mode === 'check' ? 'Prüfe …' : st.mode === 'preview' ? 'Suche Titel …' : 'Download läuft')
    : st.overall === 'good' ? 'Geschützt'
    : st.overall === 'bad' ? 'Gesperrt – Problem gefunden'
    : st.overall === 'stale' ? 'Letzte Prüfung OK (' + ago(st.last_check) + ')'
    : 'Nicht geprüft';
}

function renderBanner(st) {
  const b = $('banner');
  if (!st.banner) { b.hidden = true; return; }
  b.hidden = false;
  b.className = 'banner ' + st.banner.level;
  $('banner-text').textContent = st.banner.text;
}

function renderNow(st) {
  const cur = st.current;
  $('now-empty').hidden = !!cur;
  $('now').hidden = !cur;
  $('now-mode').textContent = st.mode === 'download' ? 'Download' : st.mode === 'check' ? 'Sicherheitsprüfung'
    : st.mode === 'preview' ? 'Titelsuche' + (st.start_pending ? ' – Download startet danach' : '') : '';
  if (!cur) return;
  $('now-title').textContent = cur.title || (st.mode === 'check' ? 'Sicherheitsprüfung' : 'Titel wird ermittelt …');
  const idx = PHASES.indexOf(cur.phase);
  $('steps').hidden = st.mode === 'preview';
  for (const li of $('steps').children) {
    const i = PHASES.indexOf(li.dataset.phase);
    li.className = i < idx ? 'done' : i === idx ? 'active' : '';
    li.hidden = st.mode === 'check' && i > 0;
  }
  const bar = $('bar');
  // Prozent nur beim echten Download (nicht bei Titelsuche oder Prüfungen).
  const downloading = st.mode === 'download' && cur.phase === 'download';
  const pct = downloading && typeof cur.percent === 'number' ? cur.percent : null;
  if (pct !== null) {
    bar.classList.remove('indeterminate');
    $('bar-fill').style.width = pct.toFixed(1) + '%';
    bar.setAttribute('aria-valuenow', pct.toFixed(0));
  } else {
    bar.classList.add('indeterminate');
    $('bar-fill').style.width = '';
    bar.removeAttribute('aria-valuenow');
  }
  const hint = hintText(st, cur, pct !== null);
  $('now-hint').hidden = !hint;
  $('now-hint-text').textContent = hint;
  $('st-pct').textContent = pct !== null ? pct.toFixed(1).replace('.', ',') + ' %' : '–';
  $('st-speed').textContent = downloading ? speedText(parseSize(cur.speed)) : '–';
  // Durchschnitt dieses Videos: geladene Bytes / Zeit seit Beginn des Downloads.
  const totalBytes = parseSize(cur.total);
  const since = cur.download_started ? serverNow() - cur.download_started : 0;
  $('st-avg').textContent = downloading && pct !== null && totalBytes && since > 1
    ? speedText(totalBytes * pct / 100 / since) : '–';
  $('st-eta').textContent = cur.phase === 'download' && cur.eta ? cur.eta : '–';
  $('st-total').textContent = cur.total ? unit(cur.total) : '–';
  $('st-elapsed').textContent = cur.started ? duration(serverNow() - cur.started) : '–';
}

// ---- Reihenfolge per Ziehen am Griff (Pointer-Ereignisse: Maus, Stift, Touch; kein HTML5-Drag-and-drop)
let drag = null;   // { li, id } solange gezogen wird; dann wird die Liste nicht neu aufgebaut

function moveTo(id, li) {
  // Neue Position = vor dem naechsten Eintrag (oder ans Ende).
  const next = li.nextElementSibling;
  return act('/api/queue/move', { id, before: next ? next.dataset.id : null });
}

function startDrag(e, li, id) {
  if (e.button !== 0 || drag) return;
  e.preventDefault();
  // Ereignisse am Dokument abhoeren: setPointerCapture geht verloren, sobald der Eintrag im DOM umgesetzt wird.
  const doc = document;
  const pid = e.pointerId;
  const ul = li.parentElement;
  const before = li.nextElementSibling;
  drag = { li, id };
  li.classList.add('dragging');
  const onMove = (ev) => {
    if (ev.pointerId !== pid) return;
    ev.preventDefault();
    const r = ul.getBoundingClientRect();
    if (ev.clientY < r.top + 24) ul.scrollTop -= 12;          // Liste mitscrollen
    else if (ev.clientY > r.bottom - 24) ul.scrollTop += 12;
    for (const other of ul.children) {
      if (other === li) continue;
      const b = other.getBoundingClientRect();
      if (ev.clientY >= b.top && ev.clientY <= b.bottom) {
        if (ev.clientY < b.top + b.height / 2) ul.insertBefore(li, other);
        else ul.insertBefore(li, other.nextElementSibling);
        break;
      }
    }
  };
  const onEnd = (ev) => {
    if (ev.pointerId !== pid) return;
    doc.removeEventListener('pointermove', onMove);
    doc.removeEventListener('pointerup', onEnd);
    doc.removeEventListener('pointercancel', onEnd);
    doc.body.classList.remove('sorting');
    li.classList.remove('dragging');
    drag = null;
    if (ev.type === 'pointercancel') { ul.insertBefore(li, before); return; }
    if (li.nextElementSibling !== before) moveTo(id, li);
  };
  doc.body.classList.add('sorting');
  doc.addEventListener('pointermove', onMove);
  doc.addEventListener('pointerup', onEnd);
  doc.addEventListener('pointercancel', onEnd);
}

function keyMove(e, li, id) {
  // Tastatur: Griff fokussieren, Pfeil hoch/runter verschiebt um eine Stelle.
  const ul = li.parentElement;
  if (e.key === 'ArrowUp' && li.previousElementSibling) ul.insertBefore(li, li.previousElementSibling);
  else if (e.key === 'ArrowDown' && li.nextElementSibling) ul.insertBefore(li, li.nextElementSibling.nextElementSibling);
  else return;
  e.preventDefault();
  e.currentTarget.focus();   // Umsetzen im DOM nimmt den Fokus weg
  moveTo(id, li);
}

function renderQueue(st) {
  if (drag) return;   // waehrend des Ziehens nicht neu zeichnen
  const ul = $('queue');
  // Fokus auf einem Griff ueber das Neuzeichnen retten (Tastaturbedienung)
  const active = document.activeElement;
  const focusId = active && active.classList.contains('grip') && ul.contains(active) ? active.closest('li').dataset.id : null;
  ul.replaceChildren();
  $('queue-empty').hidden = st.queue.length > 0;
  const done = st.queue.filter((x) => x.status === 'done').length;
  $('queue-count').hidden = st.queue.length === 0;
  $('queue-count').textContent = done + ' von ' + st.queue.length + ' fertig';
  for (const item of st.queue) {
    const li = el('li');
    li.dataset.id = item.id;
    const grip = el('button', 'grip', '⋮⋮');
    grip.type = 'button';
    if (item.status === 'running') {
      grip.disabled = true;
      grip.setAttribute('aria-hidden', 'true');
    } else {
      grip.title = 'Ziehen, um die Reihenfolge zu ändern (oder Pfeiltasten)';
      grip.setAttribute('aria-label', 'Verschieben');
      grip.addEventListener('pointerdown', (e) => startDrag(e, li, item.id));
      grip.addEventListener('keydown', (e) => keyMove(e, li, item.id));
    }
    li.append(grip);
    const main = el('div', 'item-main');
    const ts = item.title_state;
    const searching = item.status === 'waiting' && (ts === 'running' || ts === 'queued' || ts === 'pending');
    const shown = item.name || item.title;
    const head = el('div', 'item-title' + (shown ? '' : ' item-searching'),
      shown || (ts === 'running' ? 'Titel wird gesucht …'
        : ts === 'queued' ? 'Wartet auf Titelsuche …'
        : ts === 'pending' ? 'Titel wird gleich gesucht …'
        : 'Titel noch unbekannt'));
    main.append(head);
    if (item.name && item.title && item.title !== item.name) main.append(el('div', 'item-sub', 'Gefundener Titel: ' + item.title));
    // Adresse nur als Text - bewusst nicht anklickbar.
    main.append(el('div', 'item-sub', item.url));
    if (item.error) main.append(el('div', 'item-err', (item.error.ident ? item.error.ident + ': ' : '') + item.error.message));
    const actions = el('div', 'item-actions');
    const label = searching ? 'Titelsuche' : item.status === 'waiting' && ts === 'ok' ? 'bereit' : (STATUS[item.status] || item.status);
    actions.append(el('span', 'tag ' + (searching ? 'searching' : item.status === 'waiting' && ts === 'ok' ? 'ready' : item.status), label));
    if (item.status === 'failed' || item.status === 'stopped') {
      const r = el('button', 'btn ghost small-btn', 'Wiederholen');
      r.type = 'button';
      r.addEventListener('click', () => act('/api/queue/retry', { id: item.id }));
      actions.append(r);
    }
    if (item.status !== 'running') {
      const x = el('button', 'icon-btn', '×');
      x.type = 'button';
      x.setAttribute('aria-label', 'Entfernen');
      x.addEventListener('click', () => act('/api/queue/remove', { id: item.id }));
      actions.append(x);
    }
    li.append(main, actions);
    ul.append(li);
    if (item.id === focusId && !grip.disabled) grip.focus();
  }
}

function renderHistory(st) {
  const ul = $('history');
  ul.replaceChildren();
  $('history-empty').hidden = st.history.length > 0;
  for (const f of st.history) {
    const li = el('li');
    const main = el('div', 'item-main');
    // Fertige Videos bewusst schlicht: kleiner, nicht fett, Uhrzeit ohne Sekunden, Größe ohne Nachkommastelle
    main.append(el('div', 'item-title', f.name), el('div', 'item-sub', clock(f.time, false)));
    li.append(main, el('span', 'tag', bytes(f.size, 0)));
    ul.append(li);
  }
  $('btn-folder').title = st.storage_finished;
}

function renderLog(st) {
  const pre = $('log');
  const atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 30;
  pre.textContent = st.log.map((l) => clock(l.time) + '  ' + l.text).join('\n') || 'Noch keine Ausgabe.';
  if (atBottom) pre.scrollTop = pre.scrollHeight;
}

function renderControls(st) {
  const busy = st.mode !== 'idle';
  const waiting = st.queue.some((x) => x.status === 'waiting');
  const previewing = st.mode === 'preview';
  $('btn-start').disabled = !waiting || (busy && !previewing) || (previewing && st.start_pending);
  $('btn-start').textContent = 'Start';   // waehrend der Titelsuche: Downloads starten automatisch danach
  $('btn-check').disabled = busy;
  $('btn-stop').hidden = !busy;
  $('btn-clear').disabled = !st.queue.some((x) => ['done', 'failed', 'stopped'].includes(x.status));
  $('browser-info').textContent = 'Browser-Einstellung: ' + st.browser;
}

let lastState = null;
function render(st) {
  lastState = st;
  if (typeof st.tz_offset === 'number') tzOffset = st.tz_offset;
  if (typeof st.server_time === 'number') clockSkew = st.server_time - Date.now() / 1000;
  renderChecks(st);
  renderBanner(st);
  renderNow(st);
  renderQueue(st);
  renderHistory(st);
  renderLog(st);
  renderControls(st);
}

// ---- Abfrage im Sekundentakt
let failures = 0;
async function poll() {
  try {
    render(await api('/api/state'));
    failures = 0;
    $('offline').hidden = true;
  } catch (e) {
    failures++;
    if (failures >= 3) $('offline').hidden = false;
  }
  setTimeout(poll, lastState && lastState.mode !== 'idle' ? 700 : 1500);
}

function message(text, cls) {
  const m = $('add-msg');
  m.textContent = text;
  m.className = 'small ' + (cls || '');
}

async function act(path, body) {
  try {
    await api(path, body || {});
    render(await api('/api/state'));
    return true;
  } catch (e) {
    message(e.message, 'bad');
    return false;
  }
}

function setup() {
  if (!token) {
    $('offline').hidden = false;
    $('offline').textContent = 'Kein Zugriffsschlüssel. Bitte Quite Safe Grab über „qsgrab.cmd ui“ starten.';
    return;
  }
  $('btn-add').addEventListener('click', async () => {
    const urls = $('urls').value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    if (!urls.length) { message('Bitte mindestens einen Link eingeben.', 'bad'); return; }
    try {
      const r = await api('/api/queue/add', { urls, name: $('name').value });
      $('urls').value = '';
      $('name').value = '';
      message(r.added + ' Link(s) hinzugefügt.' + (r.invalid.length ? ' Ungültig: ' + r.invalid.length : ''),
        r.invalid.length ? 'bad' : 'good');
      render(await api('/api/state'));
    } catch (e) { message(e.message, 'bad'); }
  });
  $('btn-start').addEventListener('click', () => { message(''); act('/api/start'); });
  $('btn-check').addEventListener('click', () => { message(''); act('/api/check'); });
  $('btn-stop').addEventListener('click', () => act('/api/stop'));
  $('btn-clear').addEventListener('click', () => act('/api/queue/clear'));
  $('btn-folder').addEventListener('click', () => act('/api/open-folder'));
  $('banner-close').addEventListener('click', () => act('/api/dismiss'));
  $('urls').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) $('btn-add').click();
  });
  poll();
}

setup();
