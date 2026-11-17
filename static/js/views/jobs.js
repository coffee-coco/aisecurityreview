// Job queue monitor: the workspace's background jobs with progress, AI usage, cancel and purge.
import { api } from '../api.js';
import { confirmDialog, esc, icon, timeAgo, toast } from '../ui.js';
import { canWrite, isAdmin, setJobCount } from '../app.js';

const KIND = {
  design: 'Design analysis', code_review: 'Code review', fix_gen: 'Fixes & tests', threat_all: 'Full threat model',
  threat_dfd: 'Diagram import', devil_devil: "Devil's advocate", devil_review: 'AI review',
};
const kindLabel = (k) => KIND[k] || (k.startsWith('threat_') ? `Threat model · ${k.slice(7).replace(/_/g, ' ')}` : k);
const STATUS = {
  queued: ['Queued', '#94a3b8'], running: ['Running', '#a78bfa'], done: ['Done', '#34d399'],
  error: ['Failed', '#f43f5e'], cancelled: ['Cancelled', '#fbbf24'],
};
const STALL_MS = 5 * 60 * 1000;

const ms = (iso) => (iso ? new Date(iso).getTime() : 0);
function duration(j) {
  const start = ms(j.started_at) || ms(j.created_at);
  const end = ['queued', 'running'].includes(j.status) ? Date.now() : ms(j.updated_at);
  const s = Math.max(0, Math.round((end - start) / 1000));
  return s >= 3600 ? `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m` : s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`;
}
const tokens = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : String(n || 0));
const reviewUrl = (j) => `#/${j.review_ref.startsWith('TM') ? 'threat-model' : 'review'}/${j.review_id}`;

export async function render(root) {
  let activeOnly = false;
  let data = { jobs: [], counts: {}, limits: {} };
  root.innerHTML = `<div class="page">
    <div class="page-head"><div>
      <div class="eyebrow">${icon('clock')} Background work</div>
      <h1>Job queue</h1>
      <p id="jq-sub">Background jobs in this workspace. Cancelling stops a job within a few seconds, including AI calls in flight.</p>
    </div>
    <div class="row wrap">
      <div class="seg" id="jq-filter"><button data-f="all" class="on">All</button><button data-f="active">Active</button></div>
      <button class="btn" id="jq-refresh">${icon('refresh')} Refresh</button>
      ${isAdmin() ? `<button class="btn danger" id="jq-purge">${icon('trash')} Purge active jobs</button>` : ''}
    </div></div>
    <div class="row wrap jq-stats" id="jq-stats"></div>
    <div class="card" style="padding:6px 4px"><div id="jq-table"><div class="loading"><span class="spin"></span>Loading…</div></div></div>
  </div>`;

  const draw = () => {
    const active = (data.counts.queued || 0) + (data.counts.running || 0);
    setJobCount(active);
    const lim = data.limits || {};
    root.querySelector('#jq-sub').innerHTML = `Background jobs in this workspace. Cancelling stops a job within a few seconds, including AI calls in flight.
      Each job may make up to <b>${lim.max_ai_calls || 'unlimited'}</b> AI calls and run for <b>${Math.round((lim.time_limit || 0) / 60)} min</b>.`;
    root.querySelector('#jq-stats').innerHTML = Object.entries(STATUS).map(([k, [l, c]]) =>
      `<span class="badge" style="color:${c}"><span class="d"></span>${l} <b style="margin-left:4px">${data.counts[k] || 0}</b></span>`).join('');
    const purge = root.querySelector('#jq-purge');
    if (purge) { purge.disabled = !active; purge.innerHTML = `${icon('trash')} Purge active jobs${active ? ` (${active})` : ''}`; }
    const rows = data.jobs;
    root.querySelector('#jq-table').innerHTML = rows.length ? `<table class="table plain jq"><thead><tr>
        <th>Job</th><th>Review</th><th>Status</th><th style="min-width:220px">Progress</th><th>AI calls</th><th>Tokens</th><th>Started by</th><th>Started</th><th>Duration</th><th></th></tr></thead><tbody>
      ${rows.map((j) => {
        const [sl, sc] = STATUS[j.status] || [j.status, '#94a3b8'];
        const live = ['queued', 'running'].includes(j.status);
        const stalled = j.status === 'running' && Date.now() - ms(j.updated_at) > STALL_MS;
        const hot = lim.max_ai_calls && j.ai_calls >= lim.max_ai_calls * 0.8;
        return `<tr class="${live ? 'live' : ''}">
          <td><b>${esc(kindLabel(j.kind))}</b><div class="small muted mono">#${j.id}</div></td>
          <td><a href="${reviewUrl(j)}" class="mono" style="color:var(--accent-2)">${esc(j.review_ref)}</a><div class="small muted jq-title">${esc(j.review_title)}</div></td>
          <td><span class="badge" style="color:${sc}">${live ? '<span class="spin" style="width:10px;height:10px"></span>' : '<span class="d"></span>'}${sl}</span>
            ${stalled ? `<div class="small" style="color:#fcd34d;margin-top:4px" title="No progress for over 5 minutes - the worker may have stopped">${icon('alert')} No progress ${timeAgo(j.updated_at)}</div>` : ''}</td>
          <td><div class="progress jq-bar"><i style="width:${Math.round((j.progress || 0) * 100)}%"></i></div>
            <div class="small muted jq-msg" title="${esc(j.error || j.message)}">${esc(j.status === 'error' || j.status === 'cancelled' ? (j.error || j.message) : j.message)}</div></td>
          <td class="mono ${hot ? 'jq-hot' : ''}" title="${hot ? 'Close to the per-job AI call limit' : ''}">${j.ai_calls || 0}${lim.max_ai_calls ? `<span class="muted">/${lim.max_ai_calls}</span>` : ''}</td>
          <td class="mono">${tokens(j.ai_tokens)}</td>
          <td class="small">${esc(j.created_by_email || '—')}</td>
          <td class="small" title="${esc(j.created_at)}">${timeAgo(j.created_at)}</td>
          <td class="small mono">${duration(j)}</td>
          <td>${live && canWrite() ? `<button class="btn sm danger" data-cancel="${j.id}">${icon('x')} Cancel</button>` : ''}</td></tr>`;
      }).join('')}</tbody></table>`
      : `<div class="empty" style="padding:30px"><div class="ic">${icon('check')}</div><h3>${activeOnly ? 'No active jobs' : 'No jobs yet'}</h3>
        <p>Document analysis, code reviews, fix generation, threat models and batch AI reviews show up here.</p></div>`;
  };

  const load = async () => {
    try { data = await api.get(`/api/jobs?limit=200${activeOnly ? '&active=true' : ''}`); draw(); }
    catch (e) { toast(e.message, 'err'); }
  };

  root.querySelector('#jq-filter').addEventListener('click', (e) => {
    const b = e.target.closest('[data-f]');
    if (!b) return;
    activeOnly = b.dataset.f === 'active';
    root.querySelectorAll('#jq-filter button').forEach((x) => x.classList.toggle('on', x === b));
    load();
  });
  root.querySelector('#jq-refresh').addEventListener('click', load);
  root.querySelector('#jq-purge')?.addEventListener('click', async () => {
    const n = (data.counts.queued || 0) + (data.counts.running || 0);
    if (!(await confirmDialog(`Purge ${n} active job${n === 1 ? '' : 's'}?`,
      'Every queued and running job in this workspace is cancelled. Running jobs stop within a few seconds; work already saved (e.g. fixes generated so far) is kept.', 'Purge'))) return;
    try {
      const res = await api.post('/api/jobs/purge');
      toast(`Cancelled ${res.cancelled.length} job${res.cancelled.length === 1 ? '' : 's'}`);
      load();
    } catch (e) { toast(e.message, 'err'); }
  });
  root.querySelector('#jq-table').addEventListener('click', async (e) => {
    const b = e.target.closest('[data-cancel]');
    if (!b) return;
    b.disabled = true;
    try { await api.post(`/api/jobs/${b.dataset.cancel}/cancel`); toast('Job cancelled - it stops within a few seconds'); load(); }
    catch (err) { toast(err.message, 'err'); b.disabled = false; }
  });

  await load();
  const timer = setInterval(load, 3000);
  return () => clearInterval(timer);
}
