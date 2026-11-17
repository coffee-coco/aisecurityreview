// Fixes & tests tab (threat model page): for each code-review finding, generate a patch, a Python test that
// proves the vulnerability existed, and a markdown explanation - one at a time or all at once - then download
// everything as a zip.
import { api } from '../api.js';
import { cap, confirmDialog, esc, icon, toast } from '../ui.js';
import { devil } from '../devil.js';

const SEV_COLOR = { critical: '#f43f5e', high: '#fb923c', medium: '#fbbf24', low: '#34d399' };
const SEVS = Object.keys(SEV_COLOR);
const SECTIONS = [
  { id: 'patch', label: 'Patch', icon: 'edit' },
  { id: 'test', label: 'Test', icon: 'check' },
  { id: 'explanation', label: 'Explanation', icon: 'file' },
];
const STATUS_UI = {
  none: ['badge', 'Not generated'],
  busy: ['badge st-in_progress', '<span class="spin" style="width:9px;height:9px;border-width:2px;margin-right:5px"></span>Generating…'],
  ready: ['badge st-approved', `${icon('check')} Ready`],
  error: ['badge st-rejected', `${icon('alert')} Failed`],
};

function state(ctx) {
  return (ctx.ui.fixes ||= { open: new Set(), section: {}, sev: '', onlyMissing: true, fixes: null, busy: new Set() });
}

export function render(el, ctx) {
  const S = state(ctx);
  draw(el, ctx);
  if (S.fixes === null) load(el, ctx);
  if (ctx.runningJob('fix_gen') || (ctx.r.jobs || []).some((j) => j.kind === 'fix_gen')) watch(el, ctx);
}

const snapshot = (fixes) => JSON.stringify(Object.values(fixes || {}).map((f) => [f.finding_id, f.status, f.updated_at]).sort());

async function load(el, ctx) {
  const S = state(ctx);
  const before = snapshot(S.fixes);
  try { S.fixes = await api.get(`/api/reviews/${ctx.r.id}/fixes`); } catch (e) { toast(e.message, 'err'); S.fixes ||= {}; }
  if (ctx.ui.tab === 'fixes' && (before !== snapshot(S.fixes) || !el.querySelector('#fx-list'))) draw(el, ctx);
}

// While a "Generate all" job runs, poll so finished fixes (and the ZIP count) appear as they complete.
function watch(el, ctx) {
  const S = state(ctx);
  if (S.timer) return;
  S.timer = setInterval(async () => {
    const running = ctx.runningJob('fix_gen');
    await load(el, ctx);
    if (!running) { clearInterval(S.timer); S.timer = null; if (ctx.ui.tab === 'fixes') draw(el, ctx); }
  }, 4000);
  ctx.onCleanup(() => { clearInterval(S.timer); S.timer = null; });
}

function copyText(text) {
  navigator.clipboard?.writeText(text || '').then(() => toast('Copied to clipboard'))
    .catch(() => toast('Copy failed — select the text manually', 'warn'));
}

function draw(el, ctx) {
  const S = state(ctx);
  const findings = ctx.r.code_review?.findings || [];
  if (!findings.length) {
    el.innerHTML = `<div class="empty" style="padding:34px 20px"><div class="ic">${icon('wand')}</div><h3>No findings yet</h3>
      <p>Run a code review on the <b>Code &amp; repository</b> tab first — fixes are generated from its findings.</p></div>`;
    return;
  }
  if (S.fixes === null) { el.innerHTML = '<div class="loading"><span class="spin"></span>Loading…</div>'; return; }
  const running = ctx.runningJob('fix_gen');
  const bySev = Object.fromEntries(SEVS.map((s) => [s, findings.filter((x) => x.severity === s).length]));
  const shown = findings.filter((x) => !S.sev || x.severity === S.sev);
  const readyCount = Object.values(S.fixes).filter((f) => f.status === 'ready').length;
  const missing = findings.filter((f) => S.fixes[f.id]?.status !== 'ready').length;

  el.innerHTML = `
    <section class="card" style="padding:18px;margin-bottom:14px">
      <div class="head" style="margin-bottom:10px"><span class="spark">${icon('wand')}</span>
        <div style="flex:1;min-width:0"><h2 class="section-title" style="margin:0">Fixes &amp; tests</h2>
        <div class="small muted">For each finding: a patch, a Python test proving the vulnerability, and a markdown explanation.</div></div></div>
      <div class="row wrap" style="gap:10px">
        <label class="row small" style="gap:8px;cursor:pointer"><span class="switch"><input type="checkbox" id="fx-missing" ${S.onlyMissing ? 'checked' : ''} /><span></span></span>Only findings without a fix (${missing})</label>
        <span class="spacer"></span>
        <button class="btn" id="fx-all" ${running ? 'disabled' : ''}>${running ? '<span class="spin"></span> Generating…' : `${icon('sparkles')} Generate all`}</button>
        <a class="btn ghost" id="fx-zip" href="/api/reviews/${ctx.r.id}/fixes/download.zip" ${readyCount ? '' : 'style="pointer-events:none;opacity:.5" aria-disabled="true"'}>${icon('download')} Download ZIP (${readyCount})</a>
      </div>
    </section>
    <div class="sev-row" style="margin-bottom:12px">${SEVS.map((s) => `<div class="sev-box ${S.sev === s ? 'on' : ''}" data-sev="${s}" style="--c:${SEV_COLOR[s]}"><b>${bySev[s]}</b><span>${s}</span></div>`).join('')}</div>
    <div class="row wrap" style="margin-bottom:10px"><span class="small muted">${shown.length} of ${findings.length} finding${findings.length === 1 ? '' : 's'}</span></div>
    <div id="fx-list">${shown.map((f) => findingHTML(S, f, S.fixes[f.id], running)).join('')}</div>`;

  el.querySelector('#fx-missing').addEventListener('change', (e) => { S.onlyMissing = e.target.checked; draw(el, ctx); });
  el.querySelector('#fx-all').addEventListener('click', () => generateAll(el, ctx));
  el.querySelectorAll('[data-sev]').forEach((b) => b.addEventListener('click', () => { S.sev = S.sev === b.dataset.sev ? '' : b.dataset.sev; draw(el, ctx); }));
  wireList(el, ctx);
}

function findingHTML(S, f, fx, running) {
  const open = S.open.has(f.id);
  const status = S.busy.has(f.id) ? 'busy' : fx?.status || 'none';
  const [cls, label] = STATUS_UI[status];
  const files = [...new Set((f.evidence || []).map((e) => e.file).filter(Boolean))];
  const sec = S.section[f.id] || 'patch';
  return `<div class="finding sev-${f.severity} ${open ? 'open' : ''}" data-fid="${esc(f.id)}">
    <div class="finding-head"><span class="sev">${esc(f.severity)}</span>
      <div class="t">${esc(f.title)}<small>${esc(cap(f.category || ''))}${files.length ? ` · ${files.length} file${files.length === 1 ? '' : 's'}` : ' · no file evidence'}</small></div>
      <span class="${cls}">${label}</span>
      ${devil({ type: 'finding', ref: f.id })}
      <button class="btn sm ghost icon" data-gen="${esc(f.id)}" ${status === 'busy' || running ? 'disabled' : ''} title="${fx ? 'Regenerate' : 'Generate'}">${icon(fx ? 'refresh' : 'sparkles')}</button>
      ${icon('chevron', 'chev')}</div>
    ${open ? `<div class="finding-body">
      <p style="margin:0 0 8px">${esc(f.description || '')}</p>
      ${files.length ? `<div class="chips" style="margin-bottom:10px">${files.map((p) => `<span class="chip" style="font-family:var(--mono);font-size:11px">${esc(p)}</span>`).join('')}</div>` : ''}
      ${status === 'error' ? `<div class="warning">${icon('alert')}<div>${esc(fx.error || 'Generation failed')}</div></div>` : ''}
      ${status === 'ready' ? `<div class="fn-tabs" style="margin-bottom:10px">
        ${SECTIONS.map((s) => `<button class="fn-tab ${sec === s.id ? 'on' : ''}" data-sec="${s.id}">${icon(s.icon)}${s.label}</button>`).join('')}
        <span class="spacer"></span><button class="btn sm ghost" data-copy="1">${icon('edit')} Copy</button></div>
        ${renderSection(fx, sec)}` : ''}
    </div>` : ''}
  </div>`;
}

function renderSection(fx, sec) {
  if (sec === 'patch') return fx.patch ? `<pre class="code-block">${diffHTML(fx.patch)}</pre>`
    : '<p class="small muted">No file patch for this finding — see the Explanation for guidance.</p>';
  if (sec === 'test') return fx.test_code ? `<pre class="code-block">${esc(fx.test_code)}</pre>`
    : '<p class="small muted">No test generated.</p>';
  return `<pre class="code-block">${esc(fx.explanation || '')}</pre>`;
}

function diffHTML(patch) {
  return patch.split('\n').map((l) => {
    const cls = /^\+(?!\+\+)/.test(l) ? 'add' : /^-(?!--)/.test(l) ? 'del' : l.startsWith('@@') ? 'hunk' : '';
    return `<span class="${cls}">${esc(l) || ' '}</span>`;
  }).join('\n');
}

function sectionText(fx, sec) {
  return sec === 'patch' ? fx.patch : sec === 'test' ? fx.test_code : fx.explanation;
}

function wireList(el, ctx) {
  const S = state(ctx);
  el.querySelector('#fx-list').addEventListener('click', (e) => {
    const card = e.target.closest('.finding'); if (!card) return;
    const fid = card.dataset.fid;
    if (e.target.closest('[data-gen]')) return generateOne(el, ctx, fid);
    const secBtn = e.target.closest('[data-sec]');
    if (secBtn) { S.section[fid] = secBtn.dataset.sec; return draw(el, ctx); }
    if (e.target.closest('[data-copy]')) return copyText(sectionText(S.fixes[fid], S.section[fid] || 'patch'));
    if (e.target.closest('.finding-head')) {
      S.open.has(fid) ? S.open.delete(fid) : S.open.add(fid);
      draw(el, ctx);
    }
  });
}

async function generateOne(el, ctx, fid) {
  const S = state(ctx);
  if (S.busy.has(fid)) return;
  S.busy.add(fid); draw(el, ctx);
  try {
    S.fixes[fid] = await api.post(`/api/reviews/${ctx.r.id}/fixes/${encodeURIComponent(fid)}`);
    S.open.add(fid);
    toast('Fix generated');
  } catch (e) {
    toast(e.message, 'err', 7000);
    try { S.fixes[fid] = await api.get(`/api/reviews/${ctx.r.id}/fixes/${encodeURIComponent(fid)}`); } catch { /* ignore */ }
  } finally { S.busy.delete(fid); draw(el, ctx); }
}

async function generateAll(el, ctx) {
  const S = state(ctx);
  const n = (ctx.r.code_review?.findings || []).filter((f) => (!S.sev || f.severity === S.sev)
    && (!S.onlyMissing || S.fixes?.[f.id]?.status !== 'ready')).length;
  if (n > 10 && !(await confirmDialog(`Generate fixes for ${n} findings?`,
    `This makes at least ${n} AI calls with this workspace's provider and can take a long time. You can cancel it from the job banner or the Jobs page.`, `Generate ${n} fixes`))) return;
  try {
    const { job_id } = await api.post(`/api/reviews/${ctx.r.id}/fixes/generate-all`,
      { severities: S.sev ? [S.sev] : [], only_missing: S.onlyMissing });
    ctx.trackJob({ id: job_id, kind: 'fix_gen', message: 'Queued…', progress: 0 }, {
      onDone: async () => {
        try { S.fixes = await api.get(`/api/reviews/${ctx.r.id}/fixes`); } catch (e) { toast(e.message, 'err'); }
        if (ctx.ui.tab === 'fixes') draw(el, ctx);
      },
    });
    draw(el, ctx);
    watch(el, ctx);
  } catch (e) { toast(e.message, 'err', 7000); }
}
