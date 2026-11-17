import { api, getMeta, setAuthLostHandler, setCsrfToken } from './api.js';
import { esc, icon, toast } from './ui.js';
import { installDevil } from './devil.js';
import { renderAuth } from './views/auth.js';
import * as queue from './views/queue.js';
import * as newReview from './views/new-review.js';
import * as review from './views/review.js';
import * as threatModels from './views/threat-models.js';
import * as threatModel from './views/threat-model.js';
import * as library from './views/library.js';
import * as mappings from './views/mappings.js';
import * as settings from './views/settings.js';
import * as jobsView from './views/jobs.js';

const NAV = [
  { route: 'queue', label: 'Review queue', icon: 'kanban' },
  { route: 'new', label: 'New review', icon: 'plus' },
  { route: 'threat-models', label: 'Threat models', icon: 'target' },
  { route: 'library', label: 'Control library', icon: 'book' },
  { route: 'mappings', label: 'Check mappings', icon: 'link' },
  { route: 'jobs', label: 'Jobs', icon: 'clock' },
  { route: 'settings', label: 'Settings', icon: 'settings' },
];

function renderNav() {
  for (const n of NAV) {
    const el = document.querySelector(`.nav-item[data-route="${n.route}"]`);
    el.innerHTML = `${icon(n.icon)}<span>${n.label}</span>${n.route === 'jobs' ? '<span class="count" id="nav-jobs-count" hidden></span>' : ''}`;
  }
}

export async function refreshSidebar() {
  const meta = await getMeta(true);
  const pill = document.getElementById('ai-pill');
  const p = meta.ai.provider || 'heuristic';
  const offline = p === 'heuristic';
  pill.innerHTML = `<span class="dot ${offline ? 'offline' : ''}"></span>
    <div><small>AI scoping engine</small><strong>${offline ? 'Offline rules' : esc(p[0].toUpperCase() + p.slice(1))}${meta.ai.model && !offline ? ` · ${esc(meta.ai.model)}` : ''}</strong></div>`;
  const c = meta.catalog;
  document.getElementById('catalog-foot').innerHTML =
    `<b>NIST CSF ${esc(c.csf_version)}</b> · ${c.counts.subcategories} outcomes<br>
     <b>SP 800-53 r${esc(c.sp80053_version)}</b> · ${c.counts.controls} controls<br>
     <b>Checkov ${esc(c.checkov_version)}</b> · ${c.counts.checks} checks${c.counts.check_implementations ? ` · ${c.counts.check_implementations} implementations` : ''}${(meta.frameworks || []).filter((f) => f.id !== 'csf').map((f) => `<br><b>${esc(f.short || f.name)}</b> · ${f.count} items`).join('')}`;
}

const ROUTES = [
  { re: /^#?\/?$/, view: queue, nav: 'queue', title: 'Review queue' },
  { re: /^#\/new$/, view: newReview, nav: 'new', title: 'New review' },
  { re: /^#\/review\/(\d+)$/, view: review, nav: 'queue', title: 'Review' },
  { re: /^#\/threat-models$/, view: threatModels, nav: 'threat-models', title: 'Threat models' },
  { re: /^#\/threat-model\/(\d+)$/, view: threatModel, nav: 'threat-models', title: 'Threat model' },
  { re: /^#\/library$/, view: library, nav: 'library', title: 'Control library' },
  { re: /^#\/mappings$/, view: mappings, nav: 'mappings', title: 'Check mappings' },
  { re: /^#\/jobs$/, view: jobsView, nav: 'jobs', title: 'Jobs' },
  { re: /^#\/settings$/, view: settings, nav: 'settings', title: 'Settings' },
];

let cleanup = null;
export const rerender = () => route();

/** Active (queued + running) job count shown on the Jobs nav item. */
export function setJobCount(n) {
  const el = document.getElementById('nav-jobs-count');
  if (!el) return;
  el.hidden = !n;
  el.textContent = n;
  el.classList.toggle('busy', n > 0);
}
const refreshJobCount = () => api.get('/api/jobs?active=true&limit=200')
  .then((d) => setJobCount((d.counts.queued || 0) + (d.counts.running || 0))).catch(() => {});
async function route() {
  const hash = location.hash || '#/';
  const match = ROUTES.find((r) => r.re.test(hash)) || ROUTES[0];
  const params = hash.match(match.re)?.slice(1) || [];
  document.querySelectorAll('.nav-item').forEach((el) => el.classList.toggle('active', el.dataset.route === match.nav));
  document.title = `${match.title} · Sentinel`;
  if (typeof cleanup === 'function') cleanup();
  const view = document.getElementById('view');
  view.scrollTop = 0;
  view.innerHTML = '';
  try {
    cleanup = await match.view.render(view, ...params);
  } catch (e) {
    console.error(e);
    view.innerHTML = `<div class="page"><div class="card empty"><div class="ic">${icon('alert')}</div>
      <h3>Something went wrong</h3><p>${esc(e.message)}</p></div></div>`;
  }
}

// ---------------------------------------------------------------- session
export const session = { me: null };
export const role = () => session.me?.workspace?.role || null;
export const isAdmin = () => role() === 'admin';
export const canWrite = () => ['admin', 'write'].includes(role());

function renderUserBox() {
  const me = session.me;
  const ws = me.workspaces || [];
  document.getElementById('user-box').innerHTML = `
    <label class="label" for="ws-select">Workspace</label>
    <select class="select sm" id="ws-select">${ws.map((w) => `<option value="${w.id}" ${w.id === me.workspace?.id ? 'selected' : ''}>${esc(w.name)}</option>`).join('')}</select>
    <div class="user-line">${icon('user')}<span title="${esc(me.user.email)}">${esc(me.user.name || me.user.email)}</span>
      <span class="badge">${esc(me.workspace?.role || 'no access')}</span>
      <button class="btn ghost sm" id="logout-btn" title="Sign out">Sign out</button></div>`;
  document.getElementById('ws-select').addEventListener('change', async (e) => {
    try {
      await api.post('/api/auth/workspace', { workspace_id: Number(e.target.value) });
      location.hash = '#/';
      location.reload();
    } catch (err) { toast(err.message, 'err'); }
  });
  document.getElementById('logout-btn').addEventListener('click', async () => {
    try { await api.post('/api/auth/logout'); } catch { /* session already gone */ }
    location.hash = '#/';
    location.reload();
  });
}

export async function refreshSession() {
  session.me = await api.get('/api/auth/me');
  setCsrfToken(session.me.csrf_token);
  renderUserBox();
  return session.me;
}

let started = false;
function startApp(me) {
  session.me = me;
  setCsrfToken(me.csrf_token);
  document.getElementById('auth-root').hidden = true;
  document.getElementById('auth-root').innerHTML = '';
  document.getElementById('app').hidden = false;
  renderUserBox();
  if (started) return route();
  started = true;
  installDevil();
  refreshJobCount();
  setInterval(refreshJobCount, 15000);
  renderNav();
  refreshSidebar().catch(console.error);
  window.addEventListener('hashchange', route);
  route();
}

async function showAuth() {
  const config = await api.get('/api/auth/config').catch(() => ({ registration: false, demo: false }));
  document.getElementById('app').hidden = true;
  const root = document.getElementById('auth-root');
  root.hidden = false;
  document.title = 'Sign in · Sentinel';
  renderAuth(root, { config, onSignedIn: (me) => { location.hash = location.hash || '#/'; startApp(me); } });
}

setAuthLostHandler(() => { if (session.me) location.reload(); });
api.get('/api/auth/me').then(startApp).catch(showAuth);
