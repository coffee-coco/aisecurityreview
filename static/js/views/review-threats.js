// Threat model tab (threat model page): AI-generated threat model, attack tree, data flow diagram, mitigations,
// DREAD scoring and Gherkin test cases — editable by hand. Linked security reviews promote them to risks and controls.
import { api, pollJob, upload } from '../api.js';
import { renderMermaid } from '../mermaid.js';
import { cap, confirmDialog, debounce, esc, icon, ratingPill, timeAgo, toast } from '../ui.js';
import { dropzone, wireDrop } from './upload.js';

const VIEWS = [
  { id: 'threat_model', label: 'Threat Model', icon: 'shield', needs: '', title: 'No threat model yet',
    about: 'Threats to this system in six categories — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service and Elevation of Privilege — mapped to OWASP, MITRE and NIST CSF. Built from the review profile, design documents and the linked source code (git repository or upload), so threats can cite real files.' },
  { id: 'attack_tree', label: 'Attack Tree', icon: 'target', needs: 'threat_model', title: 'No attack tree yet',
    about: 'How an attacker could reach their goal, broken down into AND / OR steps that link back to the threats.' },
  { id: 'dfd', label: 'Data Flow Diagram', icon: 'layers', needs: '', title: 'No data flow diagram yet',
    about: 'External entities, processes, data stores and the flows between them, grouped by trust boundary. Generate it from the design, import an existing diagram, or build it by hand.' },
  { id: 'mitigations', label: 'Mitigations', icon: 'lock', needs: 'threat_model', title: 'No mitigations yet',
    about: 'Controls that address each threat, mapped to NIST SP 800-53 and the control library. Linked security reviews can adopt them as controls.' },
  { id: 'dread', label: 'DREAD', icon: 'zap', needs: 'threat_model', title: 'No DREAD scoring yet',
    about: 'Each threat scored 0–10 for Damage, Reproducibility, Exploitability, Affected users and Discoverability to prioritise the work.' },
  { id: 'test_cases', label: 'Test Cases', icon: 'check', needs: 'threat_model', title: 'No test cases yet',
    about: 'Gherkin security test scenarios that verify each threat is mitigated.' },
];
const VIEW = Object.fromEntries(VIEWS.map((v) => [v.id, v]));
const CATEGORIES = [
  { id: 'Spoofing', color: '#60a5fa' },
  { id: 'Tampering', color: '#fbbf24' },
  { id: 'Repudiation', color: '#a78bfa' },
  { id: 'Information Disclosure', color: '#22d3ee' },
  { id: 'Denial of Service', color: '#fb923c' },
  { id: 'Elevation of Privilege', color: '#f43f5e' },
];
const FRAMEWORKS = [
  ['owasp_top10', 'OWASP Top 10'], ['owasp_llm', 'OWASP LLM'], ['owasp_asi', 'OWASP Agentic'],
  ['mitre_attack', 'ATT&CK'], ['mitre_atlas', 'ATLAS'], ['csf', 'CSF'],
];
const FACTORS = [
  ['damage', 'Damage'], ['reproducibility', 'Reproducibility'], ['exploitability', 'Exploitability'],
  ['affected_users', 'Affected users'], ['discoverability', 'Discoverability'],
];
const DREAD_RATINGS = [[8, 'critical'], [6, 'high'], [4, 'medium'], [0, 'low']];
const RATING_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };
const PRIORITY_ORDER = { high: 3, medium: 2, low: 1 };
const NODE_TYPES = { external_entity: 'External entity', process: 'Process', data_store: 'Data store' };
const TREE_TYPES = { goal: 'Goal', and: 'AND', or: 'OR', leaf: 'Leaf' };
const APP_TYPES = { web: 'Web application', genai: 'Generative AI application', agentic: 'Agentic AI application' };
const DFD_ACCEPT = '.png,.jpg,.jpeg,.webp,.gif,.drawio,.xml';
const ACTIVE = ['queued', 'running'];
const GHERKIN_KW = /^(\s*)(Feature|Background|Scenario Outline|Scenario Template|Scenario|Examples|Rule|Given|When|Then|And|But)(:?)/;

// Per-review UI state survives tab re-renders (ctx.set re-renders every tab).
const STATE = new Map();
const cleaned = new WeakSet();

function st(ctx) {
  const rid = ctx.r.id;
  if (!STATE.has(rid)) {
    STATE.set(rid, {
      rid, view: 'threat_model', data: null, err: '', jobs: {}, watching: new Set(),
      cat: '', q: '', edit: null, editVals: {}, focus: null,
      sort: { key: 'score', dir: -1 }, zoom: {}, refine: {}, dfdDraft: null,
    });
  }
  return STATE.get(rid);
}

// ------------------------------------------------------------------ helpers
const list = (x) => (Array.isArray(x) ? x : x ? [x] : []).filter((v) => v !== '' && v != null);
const art = (S, k) => S.data?.artifacts?.[k] || null;
const dat = (S, k) => art(S, k)?.data || null;
const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z]/g, '');
const catOf = (c) => CATEGORIES.find((x) => norm(x.id) === norm(c));
const clone = (o) => JSON.parse(JSON.stringify(o ?? null));
const busy = (S) => Object.keys(S.jobs).length > 0;
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const slug = (s) => String(s ?? '').replace(/[^a-zA-Z0-9_-]/g, '_');
const clampFactor = (v) => Math.max(0, Math.min(10, Math.round(Number(v) || 0)));
const dreadRating = (score) => DREAD_RATINGS.find(([min]) => score >= min)[1];
const dreadScore = (a) => Math.round((FACTORS.reduce((s, [k]) => s + clampFactor(a[k]), 0) / FACTORS.length) * 10) / 10;
const heat = (v) => `hsla(${Math.round(140 - clampFactor(v) * 14)}, 75%, 50%, ${(0.1 + clampFactor(v) * 0.03).toFixed(2)})`;
const threatMap = (S) => Object.fromEntries(list(dat(S, 'threat_model')?.threats).map((t) => [String(t.id), t]));
const dreadMap = (S) => Object.fromEntries(list(dat(S, 'dread')?.assessments).map((a) => [String(a.threat_id), a]));

function nextId(prefix, rows) {
  const used = new Set(rows.map((x) => String(x.id)));
  let n = rows.length + 1;
  while (used.has(`${prefix}${n}`)) n += 1;
  return `${prefix}${n}`;
}

function count(S, k) {
  const d = dat(S, k);
  if (!d) return 0;
  return list({ threat_model: d.threats, attack_tree: d.nodes, dfd: d.nodes, mitigations: d.mitigations, dread: d.assessments, test_cases: d.test_cases }[k]).length;
}

async function copyText(text, msg = 'Copied to clipboard') {
  try { await navigator.clipboard.writeText(text); toast(msg); } catch { toast('Copy failed — select the text manually', 'warn'); }
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const fileBase = (S) => S.ctx?.r?.ref || `review-${S.rid}`;

// ------------------------------------------------------------------ lifecycle
export function render(el, ctx) {
  const S = st(ctx);
  S.el = el; S.ctx = ctx;
  if (!cleaned.has(ctx)) {
    cleaned.add(ctx);
    ctx.onCleanup(() => { if (S.ctx === ctx) { S.ctx = null; S.el = null; } });
  }
  if (S.data) draw(S);
  else el.innerHTML = '<div class="loading"><span class="spin"></span>Loading threat model…</div>';
  reload(S);
}

/** Open the Threat Model view and highlight one threat. */
export function jumpTo(ctx, threatId) {
  const S = st(ctx);
  Object.assign(S, { view: 'threat_model', cat: '', q: '', focus: String(threatId) });
  if (ctx.ui.tab !== 'threats') ctx.switchTab('threats'); else draw(S);
}

const snapshot = (d) => JSON.stringify({ ...d, jobs: null });

async function reload(S) {
  try {
    const fresh = await api.get(`/api/reviews/${S.rid}/threats`);
    const changed = !S.data || snapshot(fresh) !== snapshot(S.data);
    S.data = { ...fresh, artifacts: fresh?.artifacts || {} };
    S.err = '';
    list(fresh?.jobs).filter((j) => ACTIVE.includes(j.status)).forEach((j) => track(S, j));
    if (changed) draw(S);
  } catch (e) {
    S.err = e.message;
    if (!S.data) draw(S); else toast(e.message, 'err');
  }
}

// ------------------------------------------------------------------ jobs
function jobLabel(j) {
  if (j.for === 'all') return 'Generating full threat model';
  if (j.for === 'dfd_import') return 'Importing diagram';
  if (VIEW[j.for]) return `Generating ${VIEW[j.for].label}`;
  const kind = String(j.kind || '');
  if (kind.includes('import')) return 'Importing diagram';
  const v = VIEWS.find((x) => kind.includes(x.id));
  return v ? `Generating ${v.label}` : 'Threat modelling';
}

function drawJobs(S) {
  const box = S.el?.querySelector('#tm-jobs');
  if (!box) return;
  box.innerHTML = Object.values(S.jobs).map((j) => `<div class="job-banner" id="tm-job-${slug(j.id)}"><span class="spin"></span>
    <div style="flex:1;min-width:0"><b>${esc(jobLabel(j))}</b> <span class="muted">· ${esc(j.message || 'Working…')}</span></div>
    <div class="progress"><i style="width:${Math.round((j.progress || 0) * 100)}%"></i></div></div>`).join('');
}

function track(S, job) {
  const jid = job?.id;
  if (!jid || S.watching.has(jid)) return;
  S.watching.add(jid);
  S.jobs[jid] = { progress: 0, message: 'Queued…', ...job };
  draw(S);
  const finish = () => {
    const j = S.jobs[jid];
    delete S.jobs[jid]; S.watching.delete(jid);
    if (['all', 'dfd', 'dfd_import'].includes(j?.for)) S.dfdDraft = null;
    return j;
  };
  pollJob(jid, (j) => { if (S.jobs[jid]) { S.jobs[jid] = { ...S.jobs[jid], ...j, for: S.jobs[jid].for }; drawJobs(S); } })
    .then(async (j) => {
      const mine = finish();
      if (!S.ctx) return;
      const label = jobLabel(mine || j);
      toast(label === 'Importing diagram' ? 'Diagram imported' : label === 'Threat modelling' ? 'Threat model updated' : cap(`${label.replace(/^Generating /, '')} ready`));
      if (j.result?.warning) toast(j.result.warning, 'warn', 8000);
      await reload(S);
      draw(S);
    })
    .catch((e) => { finish(); if (S.ctx) { toast(e.message, 'err', 8000); draw(S); } });
}

// ------------------------------------------------------------------ actions
async function generate(S, kind, instructions = '', refine = false) {
  const any = VIEWS.some((v) => art(S, v.id));
  if (kind === 'all' && any && !(await confirmDialog('Regenerate the full threat model?', 'Every view is replaced with a fresh AI generation, including manual edits. Security reviews that link this threat model keep any risks and controls they already promoted.', 'Generate'))) return;
  if (kind !== 'all' && !refine && art(S, kind)?.source === 'manual' && !(await confirmDialog(`Replace the ${VIEW[kind].label}?`, 'It has manual edits that a fresh AI generation will overwrite. Use “Refine with instructions” to keep them.', 'Regenerate'))) return;
  if ((kind === 'all' || kind === 'threat_model') && !refine && S.data?.inputs?.level === 'thin' && !(await confirmDialog('Generate from very little input?', 'No source code or documents are linked, so the threats will be generic and may miss real weaknesses. Link a git repository or upload code first for a threat model grounded in the implementation.', 'Generate anyway'))) return;
  try {
    const { job_id } = await api.post(`/api/reviews/${S.rid}/threats/${kind}/generate`, { instructions, refine });
    S.refine[kind] = '';
    track(S, { id: job_id, for: kind, message: 'Queued…', progress: 0 });
  } catch (e) { toast(e.message, 'err', 6000); }
}

/** Save a whole artifact (manual edit). onOk runs before the re-render. */
async function save(S, kind, data, msg = 'Saved', onOk) {
  try {
    const a = await api.put(`/api/reviews/${S.rid}/threats/${kind}`, { data });
    S.data.artifacts = { ...S.data.artifacts, [kind]: a?.data ? a : { data, source: 'manual', model: '', updated_at: new Date().toISOString() } };
    onOk?.();
    toast(msg);
    draw(S);
    return true;
  } catch (e) { toast(e.message, 'err'); return false; }
}

async function removeArtifact(S, kind) {
  if (!(await confirmDialog(`Delete the ${VIEW[kind].label}?`, 'The generated content and any manual edits are removed. Security reviews that link this threat model keep any risks and controls they already promoted.'))) return;
  try {
    await api.del(`/api/reviews/${S.rid}/threats/${kind}`);
    S.data.artifacts = { ...S.data.artifacts, [kind]: null };
    if (kind === 'dfd') S.dfdDraft = null;
    toast(`${VIEW[kind].label} deleted`);
    draw(S);
  } catch (e) { toast(e.message, 'err'); }
}

function focusThreat(S, id) {
  Object.assign(S, { view: 'threat_model', cat: '', q: '', focus: String(id) });
  draw(S);
}

// ------------------------------------------------------------------ inputs
const INPUT_LEVELS = {
  good: { color: '#34d399', label: 'Grounded in code', tip: 'Source code is linked, so threats can cite real files' },
  limited: { color: '#fbbf24', label: 'Limited input', tip: 'Little or no source code is linked' },
  thin: { color: '#f87171', label: 'Thin input', tip: 'No code or documents - threats are inferred from the description alone' },
};

/** What the threat model is based on, with a prompt to add code or documents when the evidence is thin. */
function inputsBanner(S) {
  const inp = S.data.inputs;
  if (!inp) return '';
  const s = inp.sources;
  const lv = INPUT_LEVELS[inp.level] || INPUT_LEVELS.limited;
  const last = dat(S, 'threat_model')?.inputs?.source;
  const chip = (on, text, tip) => `<span class="tag ${on ? 't-stack' : ''}" title="${esc(tip)}" style="${on ? '' : 'opacity:.6'}">${text}</span>`;
  const needCode = !s.code_sources;
  return `<div class="tm-inputs" style="margin-top:12px">
    <div class="row wrap" style="gap:6px;align-items:center">
      <span class="badge" title="${esc(lv.tip)}" style="color:${lv.color};border-color:${lv.color}">${icon(inp.level === 'good' ? 'check' : 'alert')} ${lv.label}</span>
      ${chip(s.code_files, `${icon('code')} ${s.code_files} source file${s.code_files === 1 ? '' : 's'}${s.git_repos ? ` · ${s.git_repos} git repo${s.git_repos === 1 ? '' : 's'}` : ''}`, 'Linked code and repositories')}
      ${chip(s.documents, `${icon('file')} ${s.documents} document${s.documents === 1 ? '' : 's'}`, 'Uploaded architecture / design documents')}
      ${chip(s.design_analysis, `${icon('layers')} Design analysis`, 'AI design understanding')}
      ${chip(s.data_flow_diagram, `${icon('layers')} Data flow diagram`, 'A data flow diagram exists')}
      ${last ? `<span class="small muted" title="Files included in the AI prompt on the last run">Last run read ${last.files_included} of ${last.files_total} files</span>` : ''}
      <span class="spacer"></span>
      <button class="btn sm ${needCode ? 'primary' : ''}" data-goto-tab="code" title="Link a git repository or upload code">${icon('code')} ${needCode ? 'Link repo / upload code' : 'Manage code'}</button>
      ${s.documents ? '' : `<button class="btn sm" data-goto-tab="docs" title="Upload architecture documents">${icon('file')} Add documents</button>`}
    </div>
    ${list(inp.warnings).length ? `<ul class="small muted" style="margin:8px 0 0 18px;padding:0">${inp.warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}
    ${last && last.files_included < last.files_total ? `<div class="small muted" style="margin-top:6px">${last.files_included} of ${last.files_total} files fit the AI model's context on the last run; the highest-value files were chosen.</div>` : ''}
  </div>`;
}

// ------------------------------------------------------------------ shell
function draw(S) {
  const el = S.el;
  if (!el || !el.isConnected || !S.ctx) return;
  if (!S.data) {
    el.innerHTML = `<div class="empty"><div class="ic">${icon('alert')}</div><h3>Threat model unavailable</h3>
      <p>${esc(S.err || 'Could not load the threat model.')}</p><button class="btn" id="tm-retry" title="Try loading again">${icon('refresh')} Retry</button></div>`;
    el.querySelector('#tm-retry').addEventListener('click', () => reload(S));
    return;
  }
  const d = S.data;
  const ai = d.ai_enabled !== false;
  const working = busy(S);
  el.innerHTML = `<div class="tm">
    <section class="card tm-head">
      <div class="row wrap">
        <div style="flex:1;min-width:0">
          <h2 class="section-title" style="margin:0 0 8px">${icon('shield')} Threat model</h2>
          <div class="row wrap" style="gap:6px">
            ${d.app_type ? `<span class="badge" title="Application type — selects the threat references used">${icon('layers')} ${esc(APP_TYPES[d.app_type] || cap(d.app_type))}</span>` : ''}
            ${list(d.cards).map((c) => `<span class="tag t-stack" title="Reference card used for this model">${icon('book')} ${esc(c)}</span>`).join('')}
          </div>
        </div>
        <a class="btn" id="tm-export" href="/api/reviews/${S.rid}/threats/export.md" download title="Download the threat model as Markdown">${icon('download')} Export .md</a>
        <button class="btn primary" id="tm-all" ${ai && !working ? '' : 'disabled'} title="${ai ? 'Generate every view: threat model, attack tree, data flow diagram, mitigations, DREAD and test cases' : 'Configure AI in Settings to generate'}">${working ? '<span class="spin"></span> Working…' : `${icon('sparkles')} Generate full threat model`}</button>
      </div>
      ${ai ? '' : `<div class="warning" style="margin:12px 0 0">${icon('alert')}<div>AI is not configured, so threat models cannot be generated. <a href="#/settings">Configure an AI provider in Settings</a>. You can still add and edit content by hand.</div></div>`}
      ${inputsBanner(S)}
    </section>
    <div id="tm-jobs"></div>
    <nav class="tm-nav" role="tablist" aria-label="Threat model views">${VIEWS.map((v) => `<button class="filt tm-pill ${S.view === v.id ? 'on' : ''}" role="tab" aria-selected="${S.view === v.id}" data-view="${v.id}" id="tm-v-${v.id}" title="${v.label}">${icon(v.icon)}${v.label}<span class="n">${count(S, v.id)}</span></button>`).join('')}</nav>
    <section class="card tm-body" id="tm-body" role="tabpanel" aria-labelledby="tm-v-${S.view}"></section>
  </div>`;
  drawJobs(S);
  el.querySelectorAll('[data-goto-tab]').forEach((b) => b.addEventListener('click', () => S.ctx.switchTab(b.dataset.gotoTab)));
  el.querySelector('#tm-all').addEventListener('click', () => generate(S, 'all'));
  el.querySelector('.tm-nav').addEventListener('click', (e) => {
    const b = e.target.closest('[data-view]');
    if (b && b.dataset.view !== S.view) { S.view = b.dataset.view; S.edit = null; draw(S); }
  });
  drawBody(S);
}

function drawBody(S) {
  const box = S.el.querySelector('#tm-body');
  const v = VIEW[S.view] || VIEWS[0];
  const a = art(S, v.id);
  const ai = S.data.ai_enabled !== false;
  const blocked = !!v.needs && !art(S, v.needs);
  const canGen = ai && !busy(S) && !blocked;
  const why = !ai ? 'Configure AI in Settings to generate' : blocked ? `Generate the ${VIEW[v.needs].label} first` : busy(S) ? 'A threat model job is already running' : '';
  box.innerHTML = `
    <div class="tm-bar">
      <div style="flex:1;min-width:0"><h2 class="section-title" style="margin:0">${icon(v.icon)} ${v.label}</h2>
        ${a ? `<div class="small muted">${a.source === 'manual' ? 'Edited manually' : `AI generated${a.model ? ` · <span class="mono">${esc(a.model)}</span>` : ''}`}${a.updated_at ? ` · ${timeAgo(a.updated_at)}` : ''}</div>` : ''}</div>
      ${a ? `<button class="btn sm ghost icon danger" id="tm-del" title="Delete the ${v.label}">${icon('trash')}</button>` : ''}
      <button class="btn sm ${a ? '' : 'primary'}" id="tm-gen" ${canGen ? '' : 'disabled'} title="${esc(why || (a ? `Replace the ${v.label} with a fresh AI generation` : `Generate the ${v.label} with AI`))}">${icon(a ? 'refresh' : 'sparkles')} ${a ? 'Regenerate' : 'Generate'}</button>
    </div>
    <details class="ex tm-refine" ${S.refine[v.id] ? 'open' : ''}><summary>${icon('wand')} ${a ? 'Refine with instructions' : 'Generate with instructions'}</summary>
      <div class="row" style="margin-top:8px;align-items:flex-end">
        <textarea class="textarea" id="tm-refine-text" rows="2" aria-label="Instructions for the AI" placeholder="${a ? 'e.g. Add threats for the admin API; the reporting service is internal-only…' : 'e.g. Focus on the payment flow and third-party webhooks…'}">${esc(S.refine[v.id] || '')}</textarea>
        <button class="btn sm" id="tm-refine-go" ${canGen ? '' : 'disabled'} title="${esc(why || (a ? `Update the existing ${v.label} using these instructions` : `Generate the ${v.label} using these instructions`))}">${icon('sparkles')} ${a ? 'Refine' : 'Generate'}</button>
      </div></details>
    <div id="tm-view"></div>`;
  box.querySelector('#tm-gen').addEventListener('click', () => generate(S, v.id));
  box.querySelector('#tm-del')?.addEventListener('click', () => removeArtifact(S, v.id));
  const ta = box.querySelector('#tm-refine-text');
  ta.addEventListener('input', () => { S.refine[v.id] = ta.value; });
  box.querySelector('#tm-refine-go').addEventListener('click', () => {
    if (a && !ta.value.trim()) { toast('Write some instructions first', 'warn'); ta.focus(); return; }
    generate(S, v.id, ta.value.trim(), !!a);
  });
  const view = box.querySelector('#tm-view');
  const manual = (v.id === 'threat_model' && S.edit === 'new') || v.id === 'dfd';
  if (!a && !manual) { drawEmpty(S, view, v, { blocked, ai, canGen }); return; }
  RENDERERS[v.id](S, view);
}

function drawEmpty(S, view, v, { blocked, ai, canGen }) {
  view.innerHTML = `<div class="empty tm-empty"><div class="ic">${icon(v.icon)}</div><h3>${v.title}</h3><p>${v.about}</p>
    ${blocked ? `<p class="small">Requires the <b>${VIEW[v.needs].label}</b> first.</p>` : ''}
    ${!ai ? `<p class="small">AI is not configured — <a href="#/settings">set up a provider in Settings</a>.</p>` : ''}
    <div class="row wrap" style="justify-content:center;margin-top:14px">
      ${blocked ? `<button class="btn sm" data-goto="${v.needs}" title="Open the ${VIEW[v.needs].label}">${icon('next')} Go to ${VIEW[v.needs].label}</button>` : ''}
      ${canGen ? `<button class="btn sm primary" data-gen title="Generate the ${v.label} with AI">${icon('sparkles')} Generate ${v.label}</button>` : ''}
      ${v.id === 'threat_model' ? `<button class="btn sm" data-add-manual title="Add a threat by hand">${icon('plus')} Add a threat manually</button>` : ''}
    </div></div>`;
  view.querySelector('[data-goto]')?.addEventListener('click', (e) => { S.view = e.currentTarget.dataset.goto; draw(S); });
  view.querySelector('[data-gen]')?.addEventListener('click', () => generate(S, v.id));
  view.querySelector('[data-add-manual]')?.addEventListener('click', () => { S.edit = 'new'; S.editVals = {}; drawBody(S); });
}

const threatChip = (id, tmap) => `<button class="chip ctrl" data-threat="${esc(id)}" title="${esc(tmap[String(id)]?.title || 'Show threat')}">${esc(id)}</button>`;

function wireThreatLinks(S, box) {
  box.addEventListener('click', (e) => {
    const b = e.target.closest('[data-threat]');
    if (b) { e.preventDefault(); focusThreat(S, b.dataset.threat); }
  });
}

// ------------------------------------------------------------------ threat model
function viewThreats(S, box) {
  const d = dat(S, 'threat_model') || {};
  const all = list(d.threats);
  const byCat = Object.fromEntries(CATEGORIES.map((c) => [c.id, all.filter((t) => catOf(t.category)?.id === c.id).length]));
  const assumptions = list(d.assumptions);
  const suggestions = list(d.improvement_suggestions);
  const qrows = (rows, ic) => rows.map((x) => `<div class="q-row">${icon(ic)}<div class="x">${esc(x)}</div></div>`).join('');
  box.innerHTML = `
    ${d.summary ? `<p class="tm-summary">${esc(d.summary)}</p>` : ''}
    <div class="row wrap tm-tools">
      <div class="filters" id="tm-cats"><button class="filt ${!S.cat ? 'on' : ''}" data-cat="" title="Show all threats">All<span class="n">${all.length}</span></button>
        ${CATEGORIES.map((c) => `<button class="filt ${S.cat === c.id ? 'on' : ''}" data-cat="${esc(c.id)}" style="--c:${c.color}" title="Show ${c.id} threats"><i></i>${c.id}<span class="n">${byCat[c.id]}</span></button>`).join('')}</div>
      <span class="spacer"></span>
      <div class="search tm-search">${icon('search')}<input class="input sm" id="tm-q" placeholder="Search threats…" value="${esc(S.q)}" aria-label="Search threats" /></div>
    </div>
    <div class="row wrap tm-bulk">
      <span class="small muted" id="tm-shown"></span><span class="spacer"></span>
      <button class="btn sm" id="tm-add" title="Add a threat by hand">${icon('plus')} Add threat</button>
    </div>
    <div id="tm-list"></div>
    ${assumptions.length || suggestions.length ? `<div class="grid-2 tm-panels">
      <div class="tm-panel"><h3 class="label">${icon('info')} Assumptions</h3>${qrows(assumptions, 'check') || '<p class="small muted">None recorded.</p>'}</div>
      <div class="tm-panel"><h3 class="label">${icon('bulb')} Information that would improve this model</h3>${qrows(suggestions, 'message') || '<p class="small muted">None recorded.</p>'}</div>
    </div>` : ''}`;

  box.querySelector('#tm-cats').addEventListener('click', (e) => {
    const b = e.target.closest('[data-cat]');
    if (!b) return;
    S.cat = b.dataset.cat;
    box.querySelectorAll('#tm-cats [data-cat]').forEach((x) => x.classList.toggle('on', x === b));
    drawThreatList(S, box);
  });
  box.querySelector('#tm-q').addEventListener('input', (e) => { S.q = e.target.value; drawThreatList(S, box); });
  box.querySelector('#tm-add').addEventListener('click', () => { S.edit = 'new'; S.editVals = {}; drawThreatList(S, box); box.querySelector('#tf-title')?.focus(); });
  wireThreatList(S, box);
  drawThreatList(S, box);
}

function shownThreats(S) {
  const q = S.q.trim().toLowerCase();
  return list(dat(S, 'threat_model')?.threats).filter((t) => (!S.cat || catOf(t.category)?.id === S.cat)
    && (!q || [t.id, t.title, t.component, t.scenario, t.impact, t.category, ...FRAMEWORKS.flatMap(([k]) => list(t[k]))].join(' ').toLowerCase().includes(q)));
}

function drawThreatList(S, box) {
  const all = list(dat(S, 'threat_model')?.threats);
  const shown = shownThreats(S);
  const dr = dreadMap(S);
  box.querySelector('#tm-list').innerHTML = (S.edit === 'new' ? threatForm(S, {}) : '')
    + (shown.map((t) => (S.edit === String(t.id) ? threatForm(S, t) : threatRow(t, dr[String(t.id)]))).join('')
      || (S.edit === 'new' ? '' : `<div class="empty" style="padding:24px"><p>${all.length ? 'No threats match this filter.' : 'No threats yet.'}</p></div>`));
  box.querySelector('#tm-shown').textContent = `${shown.length} of ${plural(all.length, 'threat')}`;
  if (S.focus) {
    const row = box.querySelector(`#tm-t-${slug(S.focus)}`);
    S.focus = null;
    if (row) {
      row.scrollIntoView({ behavior: 'smooth', block: 'center' });
      row.classList.add('tm-flash');
      setTimeout(() => row.classList.remove('tm-flash'), 1800);
    }
  }
}

function threatRow(t, dr) {
  const c = catOf(t.category);
  const tags = FRAMEWORKS.flatMap(([k, l]) => list(t[k]).map((x) => `<span class="tag tm-fw" title="${esc(l)}"><b>${esc(l)}</b>${esc(x)}</span>`)).join('');
  return `<article class="tm-threat" id="tm-t-${slug(t.id)}" data-tid="${esc(t.id)}" style="--c:${c?.color || 'var(--muted)'}">
    <div class="tm-main">
      <div class="row wrap" style="gap:6px">
        <span class="tm-cat">${esc(c?.id || t.category || 'Uncategorised')}</span>
        <span class="mono muted">${esc(t.id)}</span>
        ${dr?.rating ? `${ratingPill(dr.rating)}<span class="small muted" title="DREAD score">DREAD ${esc(dr.score)}</span>` : ''}
        ${t.likelihood_hint ? `<span class="tag" title="Likelihood">${esc(t.likelihood_hint)}</span>` : ''}
      </div>
      <h3 class="tm-title">${esc(t.title || 'Untitled threat')}</h3>
      ${t.component ? `<div class="small muted tm-comp">${icon('cpu')} ${esc(t.component)}</div>` : ''}
      ${t.scenario ? `<p class="tm-text"><b>Scenario</b>${esc(t.scenario)}</p>` : ''}
      ${t.impact ? `<p class="tm-text"><b>Impact</b>${esc(t.impact)}</p>` : ''}
      ${tags ? `<div class="tm-tags">${tags}</div>` : ''}
      ${list(t.evidence).length ? `<div class="tm-tags" title="Code references that support this threat">${list(t.evidence).map((e) => `<span class="tag mono">${icon('code')} ${esc(e)}</span>`).join('')}</div>` : ''}
    </div>
    <div class="tm-actions">
      <div class="row" style="gap:4px;justify-content:flex-end">
        <button class="btn sm ghost icon" data-edit title="Edit threat">${icon('edit')}</button>
        <button class="btn sm ghost icon danger" data-del title="Delete threat">${icon('trash')}</button>
      </div>
    </div>
  </article>`;
}

function threatForm(S, t) {
  const v = { ...t, ...S.editVals };
  const cat = catOf(v.category)?.id || CATEGORIES[0].id;
  return `<article class="tm-threat editing" id="tm-t-${slug(t.id ?? 'new')}" data-tid="${esc(t.id ?? '')}">
    <div class="tm-form">
      <div class="field"><label for="tf-title">Title</label><input class="input sm" id="tf-title" data-f="title" value="${esc(v.title)}" placeholder="What could go wrong" /></div>
      <div class="grid-2" style="gap:10px">
        <div class="field"><label for="tf-cat">Category</label><select class="select sm" id="tf-cat" data-f="category">${CATEGORIES.map((c) => `<option value="${esc(c.id)}" ${c.id === cat ? 'selected' : ''}>${c.id}</option>`).join('')}</select></div>
        <div class="field"><label for="tf-comp">Component</label><input class="input sm" id="tf-comp" data-f="component" value="${esc(v.component)}" placeholder="e.g. Public API" /></div>
      </div>
      <div class="field"><label for="tf-scn">Scenario</label><textarea class="textarea" id="tf-scn" data-f="scenario" rows="3" placeholder="How the attack happens">${esc(v.scenario)}</textarea></div>
      <div class="field"><label for="tf-imp">Impact</label><textarea class="textarea" id="tf-imp" data-f="impact" rows="2" placeholder="What the attacker gains or the business loses">${esc(v.impact)}</textarea></div>
      <div class="row"><span class="spacer"></span>
        <button class="btn sm" data-cancel title="Discard changes">Cancel</button>
        <button class="btn sm primary" data-save title="Save threat">${icon('check')} Save</button></div>
    </div>
  </article>`;
}

function wireThreatList(S, box) {
  const listEl = box.querySelector('#tm-list');
  wireThreatLinks(S, listEl);
  listEl.addEventListener('input', (e) => { const f = e.target.dataset.f; if (f) S.editVals[f] = e.target.value; });
  listEl.addEventListener('click', async (e) => {
    const row = e.target.closest('[data-tid]');
    if (!row) return;
    const tid = row.dataset.tid;
    const base = dat(S, 'threat_model') || { summary: '', app_type: S.data.app_type || '', assumptions: [], improvement_suggestions: [], threats: [] };
    if (e.target.closest('[data-edit]')) { S.edit = tid; S.editVals = {}; drawThreatList(S, box); row.parentElement.querySelector('#tf-title')?.focus(); return; }
    if (e.target.closest('[data-cancel]')) {
      S.edit = null; S.editVals = {};
      if (art(S, 'threat_model')) drawThreatList(S, box); else drawBody(S);
      return;
    }
    if (e.target.closest('[data-del]')) {
      if (!(await confirmDialog(`Delete threat ${tid}?`, 'The threat is removed from the model. Security reviews that link this threat model keep any risks they already promoted.'))) return;
      const next = clone(base);
      next.threats = list(next.threats).filter((x) => String(x.id) !== tid);
      save(S, 'threat_model', next, 'Threat deleted');
      return;
    }
    if (e.target.closest('[data-save]')) {
      const val = (f) => row.querySelector(`[data-f="${f}"]`).value.trim();
      const fields = { title: val('title'), category: val('category'), component: val('component'), scenario: val('scenario'), impact: val('impact') };
      if (!fields.title) { toast('Give the threat a title', 'warn'); row.querySelector('#tf-title').focus(); return; }
      const next = clone(base);
      next.threats = list(next.threats);
      if (S.edit === 'new') {
        next.threats.unshift({ id: nextId('T', next.threats), ...fields, likelihood_hint: '', owasp_top10: [], owasp_llm: [], owasp_asi: [], mitre_attack: [], mitre_atlas: [], csf: [] });
      } else {
        next.threats = next.threats.map((x) => (String(x.id) === tid ? { ...x, ...fields } : x));
      }
      const added = S.edit === 'new';
      save(S, 'threat_model', next, added ? 'Threat added' : 'Threat updated', () => { S.edit = null; S.editVals = {}; });
    }
  });
}

// ------------------------------------------------------------------ diagrams
const mId = (id) => `n_${String(id ?? '').replace(/[^A-Za-z0-9_]/g, '_')}`;
const mLabel = (s) => String(s ?? '').replace(/[\r\n]+/g, ' ').replace(/"/g, '#quot;').replace(/[<>]/g, ' ');
const mEdge = (s) => String(s ?? '').replace(/[|"<>[\]{}()\r\n]+/g, ' ').trim();

function treeMermaid(d) {
  const nodes = list(d?.nodes);
  if (!nodes.length) return '';
  const out = ['flowchart TD'];
  nodes.forEach((n) => {
    const l = mLabel(['and', 'or'].includes(n.type) ? `${n.type.toUpperCase()}: ${n.label || ''}` : n.label || n.id);
    out.push(`  ${mId(n.id)}${n.type === 'goal' ? `(["${l}"])` : n.type === 'leaf' ? `("${l}")` : `["${l}"]`}`);
  });
  nodes.forEach((n) => list(n.children).forEach((c) => out.push(`  ${mId(n.id)} --> ${mId(c)}`)));
  return out.join('\n');
}

function dfdMermaid(d) {
  const nodes = list(d?.nodes);
  if (!nodes.length) return '';
  const shape = (n) => {
    const l = mLabel(n.label || n.id);
    return n.type === 'process' ? `(("${l}"))` : n.type === 'data_store' ? `[("${l}")]` : `["${l}"]`;
  };
  const placed = new Set();
  const out = ['flowchart LR'];
  list(d.trust_boundaries).forEach((b, k) => {
    const ids = list(b.node_ids).map(String);
    const members = nodes.filter((n) => ids.includes(String(n.id)) && !placed.has(String(n.id)));
    if (!members.length) return;
    out.push(`  subgraph ${mId(`tb_${b.id ?? k}`)}["${mLabel(b.name || 'Trust boundary')}"]`);
    members.forEach((n) => { placed.add(String(n.id)); out.push(`    ${mId(n.id)}${shape(n)}`); });
    out.push('  end');
  });
  nodes.filter((n) => !placed.has(String(n.id))).forEach((n) => out.push(`  ${mId(n.id)}${shape(n)}`));
  list(d.edges).forEach((e) => {
    const l = mEdge([e.label, e.protocol].filter(Boolean).join(' · '));
    out.push(`  ${mId(e.from)} -->${l ? `|${l}|` : ''} ${mId(e.to)}`);
  });
  return out.join('\n');
}

const diagramHTML = () => `<div class="tm-diagram" id="tm-dg">
    <div class="tm-dg-bar">
      <button class="btn sm ghost icon" data-zoom="out" title="Zoom out" aria-label="Zoom out">−</button>
      <button class="btn sm ghost icon" data-zoom="in" title="Zoom in" aria-label="Zoom in">${icon('plus')}</button>
      <button class="btn sm ghost" data-zoom="fit" title="Fit to width">Fit</button>
      <span class="small muted" data-zoom-label></span>
      <span class="spacer"></span>
      <button class="btn sm ghost" data-copy-mmd title="Copy the Mermaid source">${icon('code')} Copy mermaid</button>
      <button class="btn sm ghost" data-svg title="Download the diagram as SVG" disabled>${icon('download')} SVG</button>
    </div>
    <div class="tm-canvas" tabindex="0" aria-label="Diagram"><div class="loading"><span class="spin"></span>Rendering diagram…</div></div>
  </div>`;

function applyZoom(S, kind, wrap) {
  const svg = wrap.querySelector('.tm-canvas svg');
  if (!svg) return;
  const z = S.zoom[kind] ?? 'fit';
  const w = svg.viewBox?.baseVal?.width || svg.getBoundingClientRect().width || 800;
  svg.removeAttribute('width'); svg.removeAttribute('height');
  svg.style.height = 'auto';
  svg.style.maxWidth = z === 'fit' ? `${Math.max(w, 320)}px` : 'none';
  svg.style.width = z === 'fit' ? '100%' : `${Math.round(w * z)}px`;
  wrap.querySelector('[data-zoom-label]').textContent = z === 'fit' ? 'Fit' : `${Math.round(z * 100)}%`;
}

async function mountDiagram(S, box, kind, source) {
  const src = typeof source === 'string' ? source : '';
  const wrap = box.querySelector('#tm-dg');
  const canvas = wrap.querySelector('.tm-canvas');
  wrap.querySelector('[data-copy-mmd]').addEventListener('click', () => (src ? copyText(src, 'Mermaid source copied') : toast('Nothing to copy yet', 'warn')));
  wrap.querySelectorAll('[data-zoom]').forEach((b) => b.addEventListener('click', () => {
    const cur = S.zoom[kind] ?? 'fit';
    const base = cur === 'fit' ? 1 : cur;
    S.zoom[kind] = b.dataset.zoom === 'fit' ? 'fit' : Math.min(4, Math.max(0.25, b.dataset.zoom === 'in' ? base * 1.25 : base / 1.25));
    applyZoom(S, kind, wrap);
  }));
  wrap.querySelector('[data-svg]').addEventListener('click', () => {
    const svg = canvas.querySelector('svg');
    if (!svg) return;
    const copy = svg.cloneNode(true);
    copy.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    copy.style.background = '#0b1020';
    download(`${fileBase(S)}-${kind.replace(/_/g, '-')}.svg`, new XMLSerializer().serializeToString(copy), 'image/svg+xml');
  });
  if (!src.trim()) { canvas.innerHTML = '<p class="small muted" style="margin:0">Nothing to draw yet — add elements below.</p>'; return; }
  try {
    const svg = await renderMermaid(src);
    if (!canvas.isConnected) return;
    canvas.innerHTML = svg;
    wrap.querySelector('[data-svg]').disabled = false;
    applyZoom(S, kind, wrap);
  } catch (e) {
    if (!canvas.isConnected) return;
    canvas.innerHTML = `<div class="warning">${icon('alert')}<div>The diagram could not be rendered${e?.message ? ` (${esc(e.message.split('\n')[0])})` : ''}. Paste the Mermaid source below into any Mermaid editor.</div></div>
      <div class="tm-src-wrap"><button class="btn sm ghost" data-copy-src title="Copy the Mermaid source">${icon('code')} Copy</button><pre class="code-view tm-src">${esc(src)}</pre></div>`;
    canvas.querySelector('[data-copy-src]').addEventListener('click', () => copyText(src, 'Mermaid source copied'));
  }
}

// ------------------------------------------------------------------ attack tree
function viewTree(S, box) {
  const d = dat(S, 'attack_tree') || {};
  const nodes = list(d.nodes);
  const tmap = threatMap(S);
  box.innerHTML = `
    ${d.goal ? `<div class="tm-goal">${icon('target')}<div><div class="label">Attacker goal</div><div>${esc(d.goal)}</div></div></div>` : ''}
    ${diagramHTML()}
    ${nodes.length ? `<details class="tm-outline" open><summary>${icon('list')} Outline <span class="muted">· ${plural(nodes.length, 'node')}</span></summary>
      <div class="tm-tree">${outline(nodes, tmap)}</div></details>` : ''}`;
  wireThreatLinks(S, box);
  mountDiagram(S, box, 'attack_tree', d.mermaid || treeMermaid(d));
}

function outline(nodes, tmap) {
  const index = new Map(nodes.map((n) => [String(n.id), n]));
  const childIds = new Set(nodes.flatMap((n) => list(n.children).map(String)));
  const roots = nodes.filter((n) => !childIds.has(String(n.id)));
  const seen = new Set();
  const node = (n) => {
    if (seen.has(String(n.id))) return '';
    seen.add(String(n.id));
    const type = TREE_TYPES[n.type] ? n.type : 'leaf';
    const head = `<span class="tm-nt t-${type}">${TREE_TYPES[type]}</span><span class="tm-nl">${esc(n.label || n.id)}</span>${list(n.threat_ids).map((id) => threatChip(id, tmap)).join('')}`;
    const inner = list(n.children).map((id) => index.get(String(id))).filter(Boolean).map(node).join('');
    return inner ? `<details open class="tm-node"><summary>${head}</summary><div class="tm-kids">${inner}</div></details>` : `<div class="tm-node leaf">${head}</div>`;
  };
  const html = (roots.length ? roots : nodes.slice(0, 1)).map(node).join('');
  return html + nodes.filter((n) => !seen.has(String(n.id))).map(node).join('');
}

// ------------------------------------------------------------------ data flow diagram
const normDfd = (g) => ({
  ...(g || {}),
  nodes: list(g?.nodes),
  edges: list(g?.edges),
  trust_boundaries: list(g?.trust_boundaries).map((b) => ({ ...b, node_ids: list(b.node_ids) })),
});

function viewDfd(S, box) {
  const d = dat(S, 'dfd');
  const v = VIEW.dfd;
  const canGen = S.data.ai_enabled !== false && !busy(S);
  const drop = dropzone({ id: 'tm-dfd-drop', accept: DFD_ACCEPT, title: 'Import an existing diagram', sub: 'PNG · JPG · WebP · GIF (read by a vision-capable AI provider) or draw.io / XML — replaces the current diagram', iconName: 'image', sm: true, multiple: false });
  box.innerHTML = d || S.dfdDraft ? `
    ${d ? diagramHTML() : ''}
    <div id="tm-dfd-edit"></div>
    <div class="tm-import">${drop}</div>` : `
    <div class="empty tm-empty"><div class="ic">${icon(v.icon)}</div><h3>${v.title}</h3><p>${v.about}</p>
      <div class="row wrap" style="justify-content:center;margin-top:14px">
        ${canGen ? `<button class="btn sm primary" id="tm-dfd-gen" title="Generate the data flow diagram with AI">${icon('sparkles')} Generate ${v.label}</button>` : ''}
        <button class="btn sm" id="tm-dfd-manual" title="Start an empty diagram and add elements by hand">${icon('edit')} Build by hand</button></div></div>
    <div class="tm-import">${drop}</div>`;
  wireDrop(box.querySelector('#tm-dfd-drop'), (files) => importDfd(S, box, files));
  box.querySelector('#tm-dfd-gen')?.addEventListener('click', () => generate(S, 'dfd'));
  box.querySelector('#tm-dfd-manual')?.addEventListener('click', () => { S.dfdDraft = normDfd({ mermaid: '' }); drawBody(S); });
  if (d) mountDiagram(S, box, 'dfd', d.mermaid || dfdMermaid(d));
  if (d || S.dfdDraft) drawDfdEditor(S, box);
}

async function importDfd(S, box, files) {
  const f = files[0];
  if (!f) return;
  if (S.dfdDraft && !(await confirmDialog('Discard unsaved diagram edits?', 'Importing a diagram replaces the current one.', 'Import'))) return;
  const pills = box.querySelector('#tm-dfd-drop [data-pills]');
  if (pills) pills.innerHTML = `<span class="chip"><span class="spin" style="width:10px;height:10px;border-width:2px"></span>${esc(f.name)}</span>`;
  const fd = new FormData();
  fd.append('file', f);
  try {
    const { job_id } = await upload(`/api/reviews/${S.rid}/threats/dfd/import`, fd);
    track(S, { id: job_id, for: 'dfd_import', message: `Reading ${f.name}…`, progress: 0 });
  } catch (e) { toast(e.message, 'err', 6000); if (pills) pills.innerHTML = ''; }
}

function drawDfdEditor(S, box) {
  const host = box.querySelector('#tm-dfd-edit');
  const g = normDfd(S.dfdDraft || dat(S, 'dfd'));
  const { nodes, edges, trust_boundaries: bounds } = g;
  const dirty = !!S.dfdDraft;
  const nodeOpts = (sel) => nodes.map((n) => `<option value="${esc(n.id)}" ${String(n.id) === String(sel) ? 'selected' : ''}>${esc(n.label || n.id)}</option>`).join('');
  const del = (what, k, label) => `<button class="btn sm ghost icon danger" data-act="del-${what}" data-k="${k}" title="Remove ${label}" aria-label="Remove ${label}">${icon('x')}</button>`;
  const none = (cols, text) => `<tr><td colspan="${cols}" class="muted small">${text}</td></tr>`;
  host.innerHTML = `<div class="tm-dfd-edit">
    <div class="row wrap tm-bulk">
      <h3 class="label" style="margin:0">${icon('edit')} Diagram elements</h3>
      <span class="small muted">${plural(nodes.length, 'node')} · ${plural(edges.length, 'flow')} · ${bounds.length} trust boundar${bounds.length === 1 ? 'y' : 'ies'}</span>
      <span class="spacer"></span>
      <span class="small tm-dirty" ${dirty ? '' : 'hidden'}>Unsaved changes</span>
      <button class="btn sm" data-act="discard" ${dirty ? '' : 'disabled'} title="Discard unsaved changes">Discard</button>
      <button class="btn sm primary" data-act="save" ${dirty ? '' : 'disabled'} title="Save the diagram and redraw it">${icon('check')} Save diagram</button>
    </div>
    <div class="grid-2 tm-dfd-grid">
      <div>
        <div class="row tm-sub"><b class="small">Nodes</b><span class="spacer"></span><button class="btn sm ghost" data-act="add-node" title="Add a node">${icon('plus')} Node</button></div>
        <table class="flows tm-table tm-compact"><thead><tr><th>Label</th><th>Type</th><th></th></tr></thead><tbody>
          ${nodes.map((n, k) => `<tr data-n="${k}"><td><input class="input sm" data-nf="label" value="${esc(n.label)}" aria-label="Node label" /></td>
            <td><select class="select sm" data-nf="type" aria-label="Node type">${Object.entries(NODE_TYPES).map(([id, l]) => `<option value="${id}" ${n.type === id ? 'selected' : ''}>${l}</option>`).join('')}</select></td>
            <td>${del('node', k, 'node')}</td></tr>`).join('') || none(3, 'No nodes yet.')}
        </tbody></table>
      </div>
      <div>
        <div class="row tm-sub"><b class="small">Trust boundaries</b><span class="spacer"></span><button class="btn sm ghost" data-act="add-boundary" title="Add a trust boundary">${icon('plus')} Boundary</button></div>
        <table class="flows tm-table tm-compact"><thead><tr><th>Name</th><th>Contains</th><th></th></tr></thead><tbody>
          ${bounds.map((b, k) => {
            const ids = b.node_ids.map(String);
            return `<tr data-b="${k}"><td><input class="input sm" data-bf="name" value="${esc(b.name)}" aria-label="Trust boundary name" /></td>
              <td><div class="chips">${nodes.map((n) => `<button type="button" class="chip tog ${ids.includes(String(n.id)) ? 'on' : ''}" data-bnode="${esc(n.id)}" aria-pressed="${ids.includes(String(n.id))}" title="Toggle ${esc(n.label || n.id)} inside this boundary">${esc(n.label || n.id)}</button>`).join('') || '<span class="small muted">Add nodes first</span>'}</div></td>
              <td>${del('boundary', k, 'trust boundary')}</td></tr>`;
          }).join('') || none(3, 'No trust boundaries yet.')}
        </tbody></table>
      </div>
    </div>
    <div class="row tm-sub"><b class="small">Data flows</b><span class="spacer"></span><button class="btn sm ghost" data-act="add-edge" ${nodes.length ? '' : 'disabled'} title="Add a data flow">${icon('plus')} Flow</button></div>
    <div class="tm-table-wrap"><table class="flows tm-table tm-compact"><thead><tr><th>From</th><th></th><th>To</th><th>Data / label</th><th>Protocol</th><th></th></tr></thead><tbody>
      ${edges.map((e, k) => `<tr data-e="${k}"><td><select class="select sm" data-ef="from" aria-label="Flow source">${nodeOpts(e.from)}</select></td><td class="arrow">→</td>
        <td><select class="select sm" data-ef="to" aria-label="Flow destination">${nodeOpts(e.to)}</select></td>
        <td><input class="input sm" data-ef="label" value="${esc(e.label)}" aria-label="Flow label" /></td>
        <td><input class="input sm" data-ef="protocol" value="${esc(e.protocol)}" aria-label="Flow protocol" /></td>
        <td>${del('edge', k, 'flow')}</td></tr>`).join('') || none(6, 'No data flows yet.')}
    </tbody></table></div>
  </div>`;

  const ed = host.firstElementChild;
  const draft = () => (S.dfdDraft ||= normDfd(clone(dat(S, 'dfd'))));
  const touched = () => {
    ed.querySelectorAll('[data-act="save"], [data-act="discard"]').forEach((b) => { b.disabled = false; });
    ed.querySelector('.tm-dirty').hidden = false;
  };
  ed.addEventListener('input', (e) => {
    const t = e.target;
    const g2 = draft();
    const n = t.closest('[data-n]'); const b = t.closest('[data-b]'); const r = t.closest('[data-e]');
    if (t.dataset.nf && n) g2.nodes[+n.dataset.n][t.dataset.nf] = t.value;
    else if (t.dataset.bf && b) g2.trust_boundaries[+b.dataset.b][t.dataset.bf] = t.value;
    else if (t.dataset.ef && r) g2.edges[+r.dataset.e][t.dataset.ef] = t.value;
    else return;
    if (t.dataset.nf === 'label') {
      const id = CSS.escape(String(g2.nodes[+n.dataset.n].id));
      ed.querySelectorAll(`option[value="${id}"], [data-bnode="${id}"]`).forEach((o) => { o.textContent = t.value || g2.nodes[+n.dataset.n].id; });
    }
    touched();
  });
  ed.addEventListener('click', (e) => {
    const bn = e.target.closest('[data-bnode]');
    if (bn) {
      const b = draft().trust_boundaries[+bn.closest('[data-b]').dataset.b];
      const id = bn.dataset.bnode;
      const ids = b.node_ids.map(String);
      b.node_ids = ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id];
      drawDfdEditor(S, box);
      return;
    }
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    const act = btn.dataset.act;
    const k = +btn.dataset.k;
    if (act === 'save') {
      const g2 = draft();
      save(S, 'dfd', { ...g2, mermaid: dfdMermaid(g2) }, 'Data flow diagram saved', () => { S.dfdDraft = null; });
      return;
    }
    if (act === 'discard') { S.dfdDraft = null; drawBody(S); return; }
    const g2 = draft();
    if (act === 'add-node') g2.nodes.push({ id: nextId('N', g2.nodes), label: 'New node', type: 'process' });
    else if (act === 'del-node') {
      const id = String(g2.nodes[k].id);
      g2.nodes.splice(k, 1);
      g2.edges = g2.edges.filter((x) => String(x.from) !== id && String(x.to) !== id);
      g2.trust_boundaries.forEach((b) => { b.node_ids = b.node_ids.filter((x) => String(x) !== id); });
    } else if (act === 'add-edge') g2.edges.push({ from: g2.nodes[0]?.id ?? '', to: (g2.nodes[1] || g2.nodes[0])?.id ?? '', label: '', protocol: '' });
    else if (act === 'del-edge') g2.edges.splice(k, 1);
    else if (act === 'add-boundary') g2.trust_boundaries.push({ id: nextId('TB', g2.trust_boundaries), name: 'New trust boundary', node_ids: [] });
    else if (act === 'del-boundary') g2.trust_boundaries.splice(k, 1);
    drawDfdEditor(S, box);
  });
}

/** Replace a view's content with a fresh element so re-renders do not stack listeners. */
function fresh(box) {
  box.innerHTML = '<div></div>';
  return box.firstElementChild;
}

// ------------------------------------------------------------------ mitigations
function viewMitigations(S, box) {
  const el = fresh(box);
  const ms = list(dat(S, 'mitigations')?.mitigations).slice().sort((a, b) => (PRIORITY_ORDER[b.priority] || 0) - (PRIORITY_ORDER[a.priority] || 0));
  const tmap = threatMap(S);
  el.innerHTML = `
    <div class="row wrap tm-bulk"><span class="small muted">${plural(ms.length, 'mitigation')}</span></div>
    <div class="tm-table-wrap"><table class="flows tm-table"><thead><tr><th>Mitigation</th><th>Threats</th><th>NIST SP 800-53</th><th>Priority</th></tr></thead><tbody>
      ${ms.map((m) => `<tr id="tm-m-${slug(m.id)}" data-mid="${esc(m.id)}">
          <td class="tm-mt"><b>${esc(m.title || m.id)}</b>${m.description ? `<div class="small muted">${esc(m.description)}</div>` : ''}
            ${m.library_ref ? `<span class="tag strong" title="Control library reference">${icon('book')} ${esc(m.library_ref)}</span>` : ''}</td>
          <td><div class="chips">${list(m.threat_ids).map((id) => threatChip(id, tmap)).join('') || '<span class="muted">—</span>'}</div></td>
          <td><div class="chips">${list(m.nist).map((n) => `<span class="chip tm-nist">${esc(n)}</span>`).join('') || '<span class="muted">—</span>'}</div></td>
          <td>${ratingPill(m.priority) || '<span class="muted">—</span>'}</td>
        </tr>`).join('') || '<tr><td colspan="4" class="muted">No mitigations.</td></tr>'}
    </tbody></table></div>`;
  wireThreatLinks(S, el);
}

// ------------------------------------------------------------------ DREAD
const saveDread = debounce(async (S, data, msg) => {
  try {
    const a = await api.put(`/api/reviews/${S.rid}/threats/dread`, { data });
    S.data.artifacts = { ...S.data.artifacts, dread: a?.data ? a : { ...art(S, 'dread'), data, source: 'manual' } };
    toast(msg);
  } catch (e) { toast(e.message, 'err'); reload(S); }
}, 700);

function viewDread(S, box) {
  const el = fresh(box);
  const d = dat(S, 'dread') || {};
  if (!Array.isArray(d.assessments)) d.assessments = list(d.assessments);
  const tmap = threatMap(S);
  const { key, dir } = S.sort;
  const val = (r) => (key === 'threat' ? String(tmap[String(r.a.threat_id)]?.title || r.a.threat_id || '')
    : key === 'rating' ? RATING_ORDER[r.a.rating] || 0 : key === 'score' ? Number(r.a.score ?? dreadScore(r.a)) || 0 : Number(r.a[key]) || 0);
  const rows = d.assessments.map((a, i) => ({ a, i }))
    .sort((x, y) => { const p = val(x); const q = val(y); return (typeof p === 'string' ? p.localeCompare(q) : p - q) * dir; });
  const th = (k, l) => `<th><button class="tm-sort ${key === k ? 'on' : ''}" data-sort="${k}" title="Sort by ${l}">${l}${key === k ? (dir < 0 ? ' ↓' : ' ↑') : ''}</button></th>`;
  el.innerHTML = `
    <p class="small muted tm-legend">Each factor is scored 0–10; the score is their average. Rating: ${DREAD_RATINGS.map(([min, r], k) => `${ratingPill(r)} ${k === DREAD_RATINGS.length - 1 ? `&lt; ${DREAD_RATINGS[k - 1][0]}` : `≥ ${min}`}`).join(' · ')}</p>
    <div class="tm-table-wrap"><table class="flows tm-table tm-dread"><thead><tr>
      ${th('threat', 'Threat')}${FACTORS.map(([k, l]) => th(k, l)).join('')}${th('score', 'Score')}${th('rating', 'Rating')}<th>Rationale</th>
    </tr></thead><tbody>
      ${rows.map(({ a, i }) => `<tr data-i="${i}">
        <td class="tm-dt">${a.threat_id ? threatChip(a.threat_id, tmap) : ''} <span>${esc(tmap[String(a.threat_id)]?.title || '')}</span></td>
        ${FACTORS.map(([k, l]) => `<td><input type="number" min="0" max="10" step="1" class="input sm tm-num" data-k="${k}" value="${esc(clampFactor(a[k]))}" style="background:${heat(a[k])}" aria-label="${l} for ${esc(a.threat_id)}" /></td>`).join('')}
        <td class="tm-score">${esc(a.score ?? dreadScore(a))}</td>
        <td class="tm-rating">${ratingPill(a.rating || dreadRating(dreadScore(a)))}</td>
        <td class="small tm-rat">${esc(a.rationale || '')}</td>
      </tr>`).join('') || '<tr><td colspan="9" class="muted">No assessments.</td></tr>'}
    </tbody></table></div>`;
  wireThreatLinks(S, el);
  el.querySelector('thead').addEventListener('click', (e) => {
    const b = e.target.closest('[data-sort]');
    if (!b) return;
    S.sort = { key: b.dataset.sort, dir: S.sort.key === b.dataset.sort ? -S.sort.dir : b.dataset.sort === 'threat' ? 1 : -1 };
    viewDread(S, box);
  });
  el.querySelector('tbody').addEventListener('input', (e) => {
    if (e.target.matches('.tm-num')) e.target.style.background = heat(e.target.value);
  });
  el.querySelector('tbody').addEventListener('change', (e) => {
    if (!e.target.matches('.tm-num')) return;
    const row = e.target.closest('[data-i]');
    const a = d.assessments[+row.dataset.i];
    a[e.target.dataset.k] = clampFactor(e.target.value);
    a.score = dreadScore(a);
    a.rating = dreadRating(a.score);
    e.target.value = a[e.target.dataset.k];
    e.target.style.background = heat(a[e.target.dataset.k]);
    row.querySelector('.tm-score').textContent = a.score;
    row.querySelector('.tm-rating').innerHTML = ratingPill(a.rating);
    saveDread(S, clone(d), `DREAD for ${a.threat_id || 'threat'} → ${a.score} (${a.rating})`);
  });
}

// ------------------------------------------------------------------ test cases
function gherkinHTML(src) {
  return String(src || '').split('\n').map((line) => {
    const m = line.match(GHERKIN_KW);
    if (m) return `${m[1]}<span class="tm-kw">${esc(m[2])}${m[3]}</span>${esc(line.slice(m[0].length)).replace(/&quot;(.*?)&quot;/g, '<span class="tm-str">&quot;$1&quot;</span>')}`;
    if (/^\s*#/.test(line)) return `<span class="tm-cm">${esc(line)}</span>`;
    if (/^\s*@/.test(line)) return `<span class="tm-tg">${esc(line)}</span>`;
    return esc(line);
  }).join('\n');
}

function featureFile(S, cases) {
  const oneLine = (s) => String(s || '').replace(/[\r\n]+/g, ' ');
  const body = cases.map((c) => [`  # ${oneLine(c.id)}${c.threat_id ? ` · threat ${oneLine(c.threat_id)}` : ''}${c.title ? ` · ${oneLine(c.title)}` : ''}`,
    ...String(c.gherkin || '').split('\n').filter((l) => !/^\s*Feature:/.test(l)).map((l) => (l.trim() ? `  ${l.trimEnd()}` : ''))].join('\n'));
  return `Feature: Security tests — ${oneLine(S.ctx?.r?.title || 'threat model')}\n\n${body.join('\n\n')}\n`;
}

function viewTests(S, box) {
  const cases = list(dat(S, 'test_cases')?.test_cases);
  const tmap = threatMap(S);
  const order = Object.keys(tmap);
  const groups = new Map();
  cases.forEach((c) => { const k = String(c.threat_id ?? ''); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(c); });
  const keys = [...groups.keys()].sort((a, b) => {
    const ia = order.indexOf(a); const ib = order.indexOf(b);
    return (ia < 0 ? 1e9 : ia) - (ib < 0 ? 1e9 : ib);
  });
  box.innerHTML = `
    <div class="row wrap tm-bulk"><span class="small muted">${plural(cases.length, 'test case')} across ${plural(keys.filter(Boolean).length, 'threat')}</span><span class="spacer"></span>
      <button class="btn sm" id="tm-copy-all" ${cases.length ? '' : 'disabled'} title="Copy every test case as one .feature file">${icon('file')} Copy all</button>
      <button class="btn sm" id="tm-dl-feature" ${cases.length ? '' : 'disabled'} title="Download every test case as a .feature file">${icon('download')} Download .feature</button></div>
    ${keys.map((k) => `<section class="tm-group">
      <h3 class="tm-group-h">${k ? threatChip(k, tmap) : ''}<span>${esc(tmap[k]?.title || (k ? 'Threat not in the model' : 'Not linked to a threat'))}</span></h3>
      ${groups.get(k).map((c) => `<div class="tm-case" id="tm-c-${slug(c.id)}">
        <div class="row"><b>${esc(c.title || c.id)}</b><span class="mono muted">${esc(c.id)}</span><span class="spacer"></span>
          <button class="btn sm ghost" data-copy="${esc(c.id)}" title="Copy this scenario">${icon('file')} Copy</button></div>
        <pre class="tm-gherkin">${gherkinHTML(c.gherkin)}</pre></div>`).join('')}
    </section>`).join('')}`;
  wireThreatLinks(S, box);
  box.querySelector('#tm-copy-all').addEventListener('click', () => copyText(featureFile(S, cases), 'All test cases copied'));
  box.querySelector('#tm-dl-feature').addEventListener('click', () => download(`${fileBase(S)}-threat-tests.feature`, featureFile(S, cases), 'text/plain'));
  box.addEventListener('click', (e) => {
    const b = e.target.closest('[data-copy]');
    if (b) copyText(String(cases.find((c) => String(c.id) === b.dataset.copy)?.gherkin || ''), 'Scenario copied');
  });
}

const RENDERERS = {
  threat_model: viewThreats,
  attack_tree: viewTree,
  dfd: viewDfd,
  mitigations: viewMitigations,
  dread: viewDread,
  test_cases: viewTests,
};
