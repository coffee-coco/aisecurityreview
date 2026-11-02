import { getMeta } from './api.js';
import { esc, icon } from './ui.js';
import * as queue from './views/queue.js';
import * as newReview from './views/new-review.js';
import * as review from './views/review.js';
import * as threatModels from './views/threat-models.js';
import * as threatModel from './views/threat-model.js';
import * as library from './views/library.js';
import * as mappings from './views/mappings.js';
import * as settings from './views/settings.js';

const NAV = [
  { route: 'queue', label: 'Review queue', icon: 'kanban' },
  { route: 'new', label: 'New review', icon: 'plus' },
  { route: 'threat-models', label: 'Threat models', icon: 'target' },
  { route: 'library', label: 'Control library', icon: 'book' },
  { route: 'mappings', label: 'Check mappings', icon: 'link' },
  { route: 'settings', label: 'Settings', icon: 'settings' },
];

function renderNav() {
  for (const n of NAV) {
    const el = document.querySelector(`.nav-item[data-route="${n.route}"]`);
    el.innerHTML = `${icon(n.icon)}<span>${n.label}</span>`;
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
  { re: /^#\/settings$/, view: settings, nav: 'settings', title: 'Settings' },
];

let cleanup = null;
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

renderNav();
refreshSidebar().catch(console.error);
window.addEventListener('hashchange', route);
route();
