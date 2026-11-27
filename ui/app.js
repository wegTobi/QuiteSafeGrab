// QuiteSafeGrab-Oberflaeche. Keine Fremdbibliotheken, keine externen Inhalte.
// Alle Daten werden per textContent eingesetzt (nie als HTML).
'use strict';

// Prüfpunkte, Phasen, Status-Texte und Grenzen kommen vom Server (st.meta), damit sie nur in ui.py stehen.

// Zeiten und Abfragetakt
const CALCULATING_AFTER_SEC = 12;   // Titelsuche: erst danach „wird berechnet …“ statt „–“
const POLL_BUSY_MS = 700;           // Abfrage, solange ein Vorgang läuft
const POLL_IDLE_MS = 1500;          // Abfrage im Leerlauf

// ---- Zugriffstoken: kommt einmalig im #-Teil der Adresse (der geht nie an den Server); danach nur als Kopfzeile X-QSGrab-Token
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

// Einlesen der yt-dlp-Angaben: KB/MB/GB dezimal (1000), KiB/MiB/... binär (1024).
// Die Anzeige (bytes(), speedText()) rechnet dagegen mit 1024 und schreibt „KB/MB“ – bewusst so belassen.
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
  if (bytesPerSec >= 1024 ** 2) return (bytesPerSec / 1024 ** 2).toFixed(2).replace('.', ',') + ' MB/s';
  if (bytesPerSec >= 1024) return Math.round(bytesPerSec / 1024) + ' KB/s';
  return Math.round(bytesPerSec) + ' B/s';
}

// Was die Sicherheitsprüfung vor Titelsuche/Größenabfrage gerade tut: Hinweis des nächsten Prüfpunkts
// nach dem zuletzt fertigen (unbekannt/noch keiner -> erster Prüfpunkt).
function nextCheckHint(meta, step) {
  const i = meta.checks.findIndex((c) => c.key === step);
  return i === meta.checks.length - 1 ? meta.checks_done_hint : meta.checks[i + 1].hint;
}
// Was gerade passiert, solange noch nichts heruntergeladen wird.
function hintText(st, d) {
  const cur = d.cur;
  if (st.mode === 'preview' && !cur.preview_started) return nextCheckHint(st.meta, cur.check_step || '');
  if (st.mode === 'check') return 'Sicherheitsprüfung läuft (VPN, Firewall, IP, DNS) …';
  if (st.mode === 'preview') return 'Titel werden gesucht – vorher und zwischendurch wird die Verbindung geprüft. Noch kein Download.';
  if (cur.phase === 'download' && d.pct !== null) return '';
  const phase = st.meta.phases.find((p) => p.key === cur.phase);
  return phase ? phase.hint : '';
}

function duration(sec) {
  sec = Math.max(0, Math.round(sec));
  const h = Math.floor(sec / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
  return (h ? h + ':' + pad(m) : m) + ':' + pad(s);
}

// ---- Zustand einmal ableiten, dann zeichnen
// Zuletzt gemessene Durchschnittsgeschwindigkeit (für Gesamt-Restzeit und Knopftext, auch zwischen Downloads).
let lastSpeed = null;
function derive(st) {
  const cur = st.current;
  const d = { cur, previewing: st.mode === 'preview', downloading: false, pct: null, avg: null, totalBytes: null,
    waiting: st.queue.filter((x) => x.status === 'waiting'), running: st.queue.find((x) => x.status === 'running') };
  if (!cur) return d;
  d.downloading = st.mode === 'download' && cur.phase === 'download';
  d.pct = d.downloading && typeof cur.percent === 'number' ? cur.percent : null;
  d.totalBytes = parseSize(cur.total);
  const since = cur.download_started ? serverNow() - cur.download_started : 0;
  d.avg = d.downloading && d.pct !== null && d.totalBytes && since > 1 ? d.totalBytes * d.pct / 100 / since : null;
  if (d.avg) lastSpeed = d.avg;
  return d;
}

// ---- Darstellung
let metaApplied = false;
function applyMeta(meta) {
  // Einmalig: Phasenleiste und Namensgrenze aus den Server-Konstanten.
  if (metaApplied) return;
  metaApplied = true;
  const steps = $('steps');
  for (const p of meta.phases) {
    const li = el('li', '', p.label);
    li.dataset.phase = p.key;
    steps.append(li);
  }
  $('name').maxLength = meta.limits.name;
}

function renderChecks(st) {
  const ul = $('checks');
  ul.replaceChildren();
  for (const { key, label } of st.meta.checks) {
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

function renderNow(st, d) {
  const cur = d.cur;
  $('now-empty').hidden = !!cur;
  $('now').hidden = !cur;
  $('now-mode').textContent = st.mode === 'download' ? 'Download' : st.mode === 'check' ? 'Sicherheitsprüfung'
    : st.mode === 'preview' ? 'Titelsuche' + (st.start_pending ? ' – Download startet danach' : '') : '';
  if (!cur) return;
  $('now-title').textContent = cur.title || (st.mode === 'check' ? 'Sicherheitsprüfung' : 'Titel wird ermittelt …');
  const phases = st.meta.phases.map((p) => p.key);
  const idx = phases.indexOf(cur.phase);
  $('steps').hidden = st.mode === 'preview';
  for (const li of $('steps').children) {
    const i = phases.indexOf(li.dataset.phase);
    li.className = i < idx ? 'done' : i === idx ? 'active' : '';
    li.hidden = st.mode === 'check' && i > 0;
  }
  const bar = $('bar');
  // Titelsuche: kein Balken, nur Restzeit und Laufzeit (das drehende Rädchen zeigt, dass es läuft).
  const previewing = d.previewing;
  bar.hidden = previewing;
  for (const id of ['st-pct', 'st-speed', 'st-avg']) $(id).parentElement.hidden = previewing;
  $('st-elapsed').parentElement.style.order = previewing ? '-1' : '';
  const pct = d.pct;
  if (pct !== null) {
    bar.classList.remove('indeterminate');
    $('bar-fill').style.width = pct.toFixed(1) + '%';
    bar.setAttribute('aria-valuenow', pct.toFixed(0));
  } else {
    bar.classList.add('indeterminate');
    $('bar-fill').style.width = '';
    bar.removeAttribute('aria-valuenow');
  }
  const hint = hintText(st, d);
  $('now-hint').hidden = !hint;
  $('now-hint-text').textContent = hint;
  $('st-pct').textContent = pct !== null ? pct.toFixed(1).replace('.', ',') + ' %' : '–';
  $('st-speed').textContent = d.downloading ? speedText(parseSize(cur.speed)) : '–';
  $('st-avg').textContent = d.avg ? speedText(d.avg) : '–';
  if (previewing) {
    // erst ab dem zweiten fertigen Link berechnet (Server), hier nur heruntergezählt
    const left = typeof cur.eta_seconds === 'number' ? cur.eta_seconds - (serverNow() - cur.eta_at) : null;
    const calculating = typeof cur.preview_started === 'number' && serverNow() - cur.preview_started >= CALCULATING_AFTER_SEC;
    $('st-eta').textContent = left === null ? (calculating ? 'wird berechnet …' : '–')
      : left > 0 ? 'ca. ' + duration(left) : 'gleich fertig';
  } else {
    $('st-eta').textContent = cur.phase === 'download' && cur.eta ? cur.eta : '–';
  }
  $('st-elapsed').textContent = cur.started ? duration(serverNow() - cur.started) : '–';
}

// ---- Reihenfolge per Ziehen am Griff (Pointer-Ereignisse: Maus, Stift, Touch; kein HTML5-Drag-and-drop)
let drag = null;   // { li, id } solange gezogen wird; dann wird die Liste nicht neu aufgebaut

function moveTo(id, li) {
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
    if (ev.clientY < r.top + 24) ul.scrollTop -= 12;
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
  const ul = li.parentElement;
  if (e.key === 'ArrowUp' && li.previousElementSibling) ul.insertBefore(li, li.previousElementSibling);
  else if (e.key === 'ArrowDown' && li.nextElementSibling) ul.insertBefore(li, li.nextElementSibling.nextElementSibling);
  else return;
  e.preventDefault();
  e.currentTarget.focus();   // Umsetzen im DOM nimmt den Fokus weg
  moveTo(id, li);
}

function renderQueue(st) {
  if (drag) return;
  const ul = $('queue');
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
      grip.setAttribute('aria-label', 'Verschieben');
      grip.addEventListener('pointerdown', (e) => startDrag(e, li, item.id));
      grip.addEventListener('keydown', (e) => keyMove(e, li, item.id));
    }
    li.append(grip);
    const main = el('div', 'item-main');
    const ts = item.title_state;
    const searching = item.status === 'waiting' && (ts === 'running' || ts === 'queued' || ts === 'pending');
    const shown = item.display;   // eigener Name oder gefundener Titel (berechnet der Server)
    const head = el('div', 'item-title' + (shown ? '' : ' item-searching'),
      shown || (ts === 'running' ? 'Titel wird gesucht …'
        : ts === 'queued' ? 'Wartet auf Titelsuche …'
        : ts === 'pending' ? 'Titel wird gleich gesucht …'
        : 'Titel noch unbekannt'));
    main.append(head);
    if (item.name && item.title && item.title !== item.name) main.append(el('div', 'item-sub', 'Gefundener Titel: ' + item.title));
    // Adresse nur als Text - bewusst nicht anklickbar.
    const sub = el('div', 'item-sub', item.url);
    // Größe: aus der Größenabfrage, beim laufenden Download notfalls aus dessen Fortschrittsangabe
    const live = item.status === 'running' && st.current && st.current.id === item.id ? parseSize(st.current.total) : null;
    const size = (item.size_state === 'ok' && item.expected_size) || (item.status === 'running' && (item.expected_size || live));
    if (size) sub.append(el('span', 'tag size-tag', bytes(size, size >= 1024 ** 3 ? 1 : 0)));
    main.append(sub);
    if (item.error) main.append(el('div', 'item-err', (item.error.ident ? item.error.ident + ': ' : '') + item.error.message));
    const actions = el('div', 'item-actions');
    const label = searching ? 'Titelsuche' : item.status === 'waiting' && ts === 'ok' ? 'bereit' : (st.meta.status[item.status] || item.status);
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

function renderTotal(st, d) {
  const { waiting, running } = d;
  $('btn-sizes').hidden = st.sizes_enabled || !waiting.length;
  $('btn-sizes').textContent = lastSpeed ? 'Gesamtlaufzeit berechnen' : 'Gesamtgröße ermitteln';
  const out = $('queue-total');
  if (!st.sizes_enabled || (!waiting.length && !running)) { out.hidden = true; return; }
  let total = 0, unknown = 0, pending = 0;
  for (const x of waiting) {
    if (x.size_state === 'ok') total += x.expected_size;
    else if (x.size_state === 'unknown') unknown++;
    else pending++;
  }
  if (running) {
    if (d.downloading && d.totalBytes && d.pct !== null) total += d.totalBytes * (1 - d.pct / 100);
    else if (running.expected_size) total += running.expected_size;
  }
  const speed = (running && d.avg) || lastSpeed;
  out.hidden = false;
  if (pending) {
    // Größenabfrage läuft parallel; Links ohne Titel kommen direkt nach ihrer Titelsuche dran.
    const job = st.size_job;
    out.textContent = job ? 'Größen werden ermittelt (' + job.done + ' von ' + job.total + ') …'
      : waiting.some((x) => x.title_state !== 'ok') ? 'Gesamtzeit: nach der Titelsuche' : 'Größen werden ermittelt …';
    out.title = '';
    return;
  }
  if (!total) {
    out.textContent = 'Größe unbekannt';
    out.title = '';
    return;
  }
  const sec = speed ? total / speed : 0;
  const mins = Math.max(1, Math.round(sec / 60));
  const span = mins >= 60 ? Math.floor(mins / 60) + ':' + pad(mins % 60) + ' h' : mins + ' Min.';
  out.textContent = (speed ? 'Gesamt: ca. ' + span + ' · ' : 'Gesamt: ') + bytes(total)
    + (speed ? '' : ' – Zeit ab Downloadstart') + (unknown ? ' +?' : '');
  out.title = (speed ? 'Geschätzt mit der aktuellen Geschwindigkeit (' + speedText(speed) + ').' : 'Die Zeit erscheint, sobald ein Download läuft.')
    + (unknown ? ' ' + unknown + ' Größe(n) unbekannt, nicht eingerechnet.' : '');
}

function renderControls(st) {
  const busy = st.mode !== 'idle';
  const waiting = st.queue.some((x) => x.status === 'waiting');
  const previewing = st.mode === 'preview';
  // Während der Titelsuche bleibt „Start“ bedienbar: Downloads starten dann automatisch danach.
  $('btn-start').disabled = !waiting || (busy && !previewing) || (previewing && st.start_pending);
  $('btn-check').disabled = busy;
  $('btn-stop').hidden = !busy && !st.size_job;
  $('browser-info').textContent = 'Browser-Einstellung: ' + st.browser;
}

let lastState = null;
function render(st) {
  lastState = st;
  if (typeof st.tz_offset === 'number') tzOffset = st.tz_offset;
  if (typeof st.server_time === 'number') clockSkew = st.server_time - Date.now() / 1000;
  applyMeta(st.meta);
  const d = derive(st);
  renderChecks(st);
  renderBanner(st);
  renderNow(st, d);
  renderQueue(st);
  renderHistory(st);
  renderLog(st);
  renderControls(st);
  renderTotal(st, d);
}

// ---- Abfrage: alle POLL_BUSY_MS, solange ein Vorgang läuft, sonst alle POLL_IDLE_MS
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
  setTimeout(poll, lastState && lastState.mode !== 'idle' ? POLL_BUSY_MS : POLL_IDLE_MS);
}

function message(text, cls) {
  const m = $('add-msg');
  m.textContent = text;
  m.className = 'small ' + (cls || '');
}

// Knopfdruck: Anfrage schicken, bei Erfolg optional done(Antwort), dann sofort neu zeichnen.
async function act(path, body, done) {
  try {
    const data = await api(path, body || {});
    if (done) done(data);
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
  $('btn-add').addEventListener('click', () => {
    const urls = $('urls').value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    if (!urls.length) { message('Bitte mindestens einen Link eingeben.', 'bad'); return; }
    act('/api/queue/add', { urls, name: $('name').value }, (r) => {
      $('urls').value = '';
      $('name').value = '';
      message(r.added + ' Link(s) hinzugefügt.' + (r.invalid.length ? ' Ungültig: ' + r.invalid.length : ''),
        r.invalid.length ? 'bad' : 'good');
    });
  });
  $('btn-start').addEventListener('click', () => { message(''); act('/api/start'); });
  $('btn-check').addEventListener('click', () => { message(''); act('/api/check'); });
  $('btn-stop').addEventListener('click', () => act('/api/stop'));
  $('btn-sizes').addEventListener('click', () => act('/api/sizes'));
  $('btn-folder').addEventListener('click', () => act('/api/open-folder'));
  $('banner-close').addEventListener('click', () => act('/api/dismiss'));
  $('urls').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) $('btn-add').click();
  });
  poll();
}

setup();
