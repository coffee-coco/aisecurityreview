// Shared UI helpers: escaping, icons, toasts, overlays, formatting.

export const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const P = {
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  kanban: '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M8 7v7M12 7v4M16 7v9"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  book: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20V3H6.5A2.5 2.5 0 0 0 4 5.5v14z"/><path d="M8 7h8M8 11h6"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
  sparkles: '<path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3z"/><path d="M19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9L19 15z"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  chevron: '<path d="m6 9 6 6 6-6"/>',
  left: '<path d="M19 12H5M12 19l-7-7 7-7"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
  trash: '<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.64-6.36L21 8"/><path d="M21 3v5h-5"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
  globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  building: '<rect x="4" y="2" width="16" height="20" rx="2"/><path d="M9 22v-4h6v4M8 6h.01M16 6h.01M12 6h.01M12 10h.01M12 14h.01M16 10h.01M16 14h.01M8 10h.01M8 14h.01"/>',
  cpu: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>',
  calendar: '<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/>',
  layers: '<path d="m12 2 10 5-10 5L2 7l10-5z"/><path d="m2 17 10 5 10-5M2 12l10 5 10-5"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  columns: '<rect x="3" y="3" width="7" height="18" rx="1.5"/><rect x="14" y="3" width="7" height="18" rx="1.5"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
  code: '<path d="m16 18 6-6-6-6M8 6l-6 6 6 6"/>',
  fingerprint: '<path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4M14 13.12c0 2.38 0 6.38-1 8.88M17.29 21.02c.12-.6.43-2.3.5-3.02M2 12a10 10 0 0 1 18-6M2 16h.01M21.8 16c.2-2 .131-5.354 0-6M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2M8.65 22c.21-.66.45-1.32.57-2M9 6.8a6 6 0 0 1 9 5.2v2"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
  target: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
  database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
  terminal: '<path d="m4 17 6-6-6-6M12 19h8"/>',
  zap: '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
  message: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/>',
  upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/>',
  image: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/>',
  flag: '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1zM4 22v-7"/>',
  bulb: '<path d="M9 18h6M10 22h4M12 2a7 7 0 0 0-4 12.7c.6.5 1 1.3 1 2.1V17h6v-.2c0-.8.4-1.6 1-2.1A7 7 0 0 0 12 2z"/>',
  wand: '<path d="m15 4-1 1M19 8l1-1M17 3v2M21 7h-2M3 21l12-12M14 6l4 4"/>',
  undo: '<path d="M3 7v6h6"/><path d="M21 17a9 9 0 0 0-15-6.7L3 13"/>',
  filter: '<path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z"/>',
  package: '<path d="m16.5 9.4-9-5.19M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.27 6.96 12 12.01l8.73-5.05M12 22.08V12"/>',
  eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
  next: '<path d="M5 12h14M12 5l7 7-7 7"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  edit: '<path d="M12 20h9M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4z"/>',
};

export const icon = (name, cls = '') =>
  `<svg class="${cls}" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ''}</svg>`;

export const STATUS = {
  new: { label: 'New', color: '#60a5fa' },
  in_progress: { label: 'In progress', color: '#a78bfa' },
  awaiting_info: { label: 'Awaiting info', color: '#fbbf24' },
  approved: { label: 'Approved', color: '#34d399' },
  rejected: { label: 'Rejected', color: '#f43f5e' },
};
export const REQ = {
  open: { label: 'Open', color: '#7d869c' },
  met: { label: 'Met', color: '#34d399' },
  partial: { label: 'Partial', color: '#fbbf24' },
  not_met: { label: 'Not met', color: '#f43f5e' },
  na: { label: 'N/A', color: '#94a3b8' },
};
export const CHECK = {
  applicable: 'To verify', pass: 'Pass', fail: 'Fail', exception: 'Exception', na: 'N/A',
};
export const FN_COLOR = (id) => `var(--${(id || 'GV').slice(0, 2)})`;

export const riskBadge = (r) =>
  r ? `<span class="badge risk-${esc(r)}"><span class="d"></span>${esc(r[0].toUpperCase() + r.slice(1))} risk</span>` : '<span class="badge">Unrated</span>';
export const statusBadge = (s) => `<span class="badge st-${esc(s)}"><span class="d"></span>${esc(STATUS[s]?.label || s)}</span>`;

export function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso.length === 10 ? iso + 'T00:00:00' : iso);
  return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
}
export function timeAgo(iso) {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 86400 * 30) return `${Math.floor(s / 86400)}d ago`;
  return fmtDate(iso);
}
export const isOverdue = (r) => r.due_date && !['approved', 'rejected'].includes(r.status) && r.due_date < new Date().toISOString().slice(0, 10);

export function debounce(fn, ms = 500) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

export function toast(msg, kind = 'ok', ms = 3600) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `${icon(kind === 'ok' ? 'check' : kind === 'warn' ? 'alert' : 'x')}<div>${esc(msg)}</div>`;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 300); }, ms);
}

/** Open a drawer (side='right') or modal. Returns {el, close}. */
export function openOverlay(html, { modal = false, onClose } = {}) {
  const root = document.getElementById('overlay-root');
  const wrap = document.createElement('div');
  wrap.innerHTML = `<div class="overlay"></div><div class="${modal ? 'modal' : 'drawer'}" role="dialog" aria-modal="true">${html}</div>`;
  root.appendChild(wrap);
  const close = () => { wrap.remove(); document.removeEventListener('keydown', onKey); onClose?.(); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  wrap.querySelector('.overlay').addEventListener('click', close);
  wrap.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', close));
  return { el: wrap.querySelector('.drawer, .modal'), close };
}

export function confirmDialog(title, text, okLabel = 'Delete') {
  return new Promise((resolve) => {
    const { el, close } = openOverlay(`
      <div class="drawer-head"><div><h2>${esc(title)}</h2><p class="muted" style="margin:6px 0 0">${esc(text)}</p></div></div>
      <div class="drawer-body row" style="justify-content:flex-end;flex:0">
        <button class="btn" data-close id="confirm-cancel">Cancel</button>
        <button class="btn primary" id="confirm-ok">${esc(okLabel)}</button>
      </div>`, { modal: true, onClose: () => resolve(false) });
    el.style.top = '24vh';
    el.querySelector('#confirm-ok').addEventListener('click', () => { resolve(true); close(); });
  });
}

/** Full-screen animated AI scoping indicator. */
export function scopingOverlay() {
  const el = document.createElement('div');
  el.className = 'scoping';
  el.innerHTML = `<div class="box"><div class="orb"><div class="orb-ic">${icon('sparkles')}</div></div>
    <h3>Scoping your security review</h3><div class="steps" id="scope-step">Reading the initiative description…</div></div>`;
  document.body.appendChild(el);
  const steps = [
    'Reading the initiative description…',
    'Identifying platforms, data and integrations…',
    'Selecting NIST CSF 2.0 requirements…',
    'Mapping SP 800-53 Rev 5 controls…',
    'Linking Checkov technical checks…',
    'Drafting key risks and questions…',
  ];
  let i = 0;
  const t = setInterval(() => {
    i = (i + 1) % steps.length;
    const s = el.querySelector('#scope-step');
    s.style.opacity = 0;
    setTimeout(() => { s.textContent = steps[i]; s.style.opacity = 1; }, 250);
  }, 1600);
  return () => { clearInterval(t); el.remove(); };
}

/** Determinate progress overlay for background jobs. Returns {set(msg, pct), close()}. */
export function progressOverlay(title, first = 'Starting…') {
  const el = document.createElement('div');
  el.className = 'scoping';
  el.innerHTML = `<div class="box"><div class="orb"><div class="orb-ic">${icon('sparkles')}</div></div>
    <h3>${esc(title)}</h3><div class="steps" data-msg>${esc(first)}</div><div class="pbar"><i style="width:2%"></i></div></div>`;
  document.body.appendChild(el);
  return {
    set(msg, pct) {
      if (msg) el.querySelector('[data-msg]').textContent = msg;
      if (pct != null) el.querySelector('.pbar i').style.width = `${Math.max(2, Math.round(pct * 100))}%`;
    },
    close() { el.remove(); },
  };
}

export const CLS = {
  public: { code: 'C1', label: 'Public' },
  internal: { code: 'C2', label: 'Internal' },
  confidential: { code: 'C3', label: 'Confidential' },
  restricted: { code: 'C4', label: 'Restricted' },
};
export const clsBadge = (c, prefix = '') =>
  `<span class="cbadge c-${esc(c)}" title="${esc(prefix)}${esc(CLS[c]?.label || c)}"><b>${esc(CLS[c]?.code || '?')}</b>${esc(CLS[c]?.label || c)}</span>`;
export const cap = (s) => (s ? String(s)[0].toUpperCase() + String(s).slice(1).replace(/_/g, ' ') : '');
export const ratingPill = (r) => (r ? `<span class="pill r-${esc(r)}">${esc(cap(r))}</span>` : '');

export function animateCount(el, to, ms = 700) {
  const start = performance.now();
  const step = (now) => {
    const p = Math.min(1, (now - start) / ms);
    el.textContent = Math.round(to * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
