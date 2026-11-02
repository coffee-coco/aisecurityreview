// Documents & design tab: upload architecture documents / diagrams, let AI work out what is being
// reviewed (AI agent? website? data platform?), then apply that understanding to the profile.
import { api, upload } from '../api.js';
import { CLS, cap, clsBadge, confirmDialog, esc, icon, openOverlay, scopingOverlay, timeAgo, toast } from '../ui.js';
import { DOC_ACCEPT, dropzone, fmtSize, wireDrop } from './upload.js';

const APPLY = [
  ['system_types', 'System type'], ['data_types', 'Data types'], ['exposure', 'Exposure'],
  ['data_classification', 'Classification'], ['technologies', 'Platforms'], ['services', 'Services'],
  ['flags', 'AI / third-party flags'], ['description', 'Description (if empty)'],
];
const COMP_ICON = { frontend: 'globe', api: 'zap', service: 'cpu', database: 'database', queue: 'layers', storage: 'database', llm: 'sparkles', agent: 'sparkles', tool: 'terminal', identity: 'fingerprint', external: 'building', network: 'globe' };

export function render(el, ctx) {
  const r = ctx.r;
  const docs = (r.documents || []).filter((d) => d.kind !== 'code');
  const linkedTms = r.linked_threat_models || [];
  const running = ctx.runningJob('design');
  const vision = docs.filter((d) => d.meta?.needs_vision).length;
  el.innerHTML = `
    <section class="card" style="padding:18px;margin-bottom:14px">
      <div class="row wrap" style="margin-bottom:14px">
        <h2 class="section-title" style="margin:0">${icon('file')} Architecture documents</h2>
        <span class="muted small">Designs, diagrams, PDFs, Word, slides, text or markdown</span>
        <span class="spacer"></span>
        <button class="btn primary" id="dz-analyse" ${(docs.length || linkedTms.length) && !running ? '' : 'disabled'}>${running ? '<span class="spin"></span> Analysing…' : `${icon('sparkles')} ${r.design?.analyzed_at ? 'Re-analyse design' : 'Analyse design'}`}</button>
      </div>
      ${linkedTms.length ? `<p class="small muted" style="margin:0 0 12px">${icon('target')} Linked threat models (threats, data flow diagram, mitigations and code review) are included in the design analysis.</p>` : ''}
      ${dropzone({ id: 'doc-drop', accept: DOC_ACCEPT, title: 'Drop architecture documents or diagrams', sub: 'PDF · Word · PowerPoint · Visio · draw.io · images · text · markdown — AI reads them to understand the design', sm: !!docs.length })}
      ${docs.length ? `<div class="doc-grid" style="margin-top:14px">${docs.map((d) => docCard(r, d)).join('')}</div>` : ''}
      ${vision ? `<p class="small muted" style="margin:12px 0 0">${icon('image')} ${vision} file${vision === 1 ? '' : 's'} need${vision === 1 ? 's' : ''} a vision-capable AI provider (Gemini) to be read — diagrams are sent as images.</p>` : ''}
    </section>
    <section class="card design-panel glow" style="padding:18px" id="design-panel">${designHTML(ctx)}</section>`;

  wireDrop(el.querySelector('#doc-drop'), (files) => doUpload(el, ctx, files));
  el.querySelector('#dz-analyse').addEventListener('click', () => analyse(ctx));
  el.querySelectorAll('[data-doc-del]').forEach((b) => b.addEventListener('click', async (e) => {
    e.stopPropagation();
    const d = docs.find((x) => x.id === +b.dataset.docDel);
    if (!(await confirmDialog(`Remove ${d.filename}?`, 'The file is deleted. Re-analyse the design afterwards to update the understanding.', 'Remove'))) return;
    try { ctx.set(await api.del(`/api/reviews/${r.id}/documents/${d.id}`)); } catch (err) { toast(err.message, 'err'); }
  }));
  el.querySelectorAll('[data-doc-view]').forEach((b) => b.addEventListener('click', () => viewDoc(r, docs.find((x) => x.id === +b.dataset.docView))));
  wireDesign(el, ctx);
}

function docCard(r, d) {
  const img = d.kind === 'image';
  const ext = (d.filename.split('.').pop() || '').toUpperCase();
  const thumb = img ? `<img src="/api/reviews/${r.id}/documents/${d.id}/raw" alt="${esc(d.filename)}" loading="lazy" />`
    : d.meta?.preview ? `<div class="txt">${esc(d.meta.preview.slice(0, 420))}</div>`
      : `<div class="big">${icon(d.meta?.needs_vision ? 'image' : 'file')}</div>`;
  const facts = [fmtSize(d.size), ext];
  if (d.meta?.pages) facts.push(`${d.meta.pages} pages`);
  if (d.meta?.words) facts.push(`${d.meta.words.toLocaleString()} words`);
  if (d.meta?.needs_vision) facts.push('vision');
  if (d.meta?.error) facts.push('⚠ unreadable');
  return `<div class="doc-card" id="doc-${d.id}"><div class="thumb" data-doc-view="${d.id}" title="Preview">${thumb}</div>
    <div class="info"><div class="n"><b title="${esc(d.filename)}">${esc(d.filename)}</b><small>${esc(facts.join(' · '))}</small></div>
      <button class="btn sm ghost icon" data-doc-view="${d.id}" title="Preview">${icon('eye')}</button>
      <button class="btn sm ghost icon danger" data-doc-del="${d.id}" title="Remove" id="docdel-${d.id}">${icon('trash')}</button></div></div>`;
}

async function doUpload(el, ctx, files) {
  const zone = el.querySelector('#doc-drop');
  zone.querySelector('[data-pills]').innerHTML = files.map((f) => `<span class="chip"><span class="spin" style="width:10px;height:10px;border-width:2px"></span>${esc(f.name)}</span>`).join('');
  const fd = new FormData();
  files.forEach((f) => fd.append('files', f));
  try {
    const res = await upload(`/api/reviews/${ctx.r.id}/documents`, fd);
    res.rejected.forEach((m) => toast(m, 'warn', 6000));
    ctx.set(res.review);
    if (res.added.length) {
      toast(`${res.added.length} document${res.added.length === 1 ? '' : 's'} uploaded — analysing design…`);
      analyse(ctx);
    }
  } catch (e) { toast(e.message, 'err'); zone.querySelector('[data-pills]').innerHTML = ''; }
}

async function analyse(ctx) {
  try {
    const { job_id } = await api.post(`/api/reviews/${ctx.r.id}/design/analyze`);
    ctx.trackJob({ id: job_id, kind: 'design', message: 'Queued…', progress: 0 });
    const b = ctx.root.querySelector('#dz-analyse');
    if (b) { b.disabled = true; b.innerHTML = '<span class="spin"></span> Analysing…'; }
  } catch (e) { toast(e.message, 'err'); }
}

async function viewDoc(r, d) {
  const img = d.kind === 'image';
  const { el } = openOverlay(`<div class="drawer-head"><div style="flex:1;min-width:0"><div class="eyebrow">${icon('file')} ${esc(d.kind)}</div><h2 style="overflow:hidden;text-overflow:ellipsis">${esc(d.filename)}</h2></div>
    <a class="btn sm" href="/api/reviews/${r.id}/documents/${d.id}/raw" target="_blank" rel="noopener">${icon('download')} Original</a>
    <button class="btn ghost icon" data-close>${icon('x')}</button></div>
    <div class="drawer-body">${img ? `<img src="/api/reviews/${r.id}/documents/${d.id}/raw" alt="" style="width:100%;border-radius:12px;border:1px solid var(--border)" />` : '<div class="loading"><span class="spin"></span>Loading extracted text…</div>'}</div>`);
  el.style.width = 'min(880px, 96vw)';
  if (!img) {
    const t = await fetch(`/api/reviews/${r.id}/documents/${d.id}/text`).then((x) => x.text()).catch(() => '');
    el.querySelector('.drawer-body').innerHTML = t
      ? `<p class="small muted" style="margin-top:0">Text extracted for AI analysis (${t.length.toLocaleString()} characters)</p><pre class="code-view" style="padding:14px;white-space:pre-wrap;margin:0">${esc(t.slice(0, 200000))}</pre>`
      : `<div class="empty" style="padding:30px"><div class="ic">${icon('image')}</div><h3>No extractable text</h3><p>This file is a diagram or scan. With Gemini configured, it is sent to the model as an image.</p></div>`;
  }
}

// ------------------------------------------------------------------ design understanding
function designHTML(ctx) {
  const r = ctx.r;
  const d = r.design || {};
  const v = ctx.meta.profile;
  if (!d.analyzed_at) {
    return `<div class="empty" style="padding:34px 20px"><div class="ic">${icon('sparkles')}</div><h3>No design understanding yet</h3>
      <p>Upload architecture documents and run “Analyse design”. AI identifies what the system is — an AI agent, a public website, an integration —<br>its components, data flows, trust boundaries and the data it handles, then suggests the review profile.</p></div>`;
  }
  const isTm = r.kind === 'threat_model';
  const st = (d.system_types || []).map((s) => v.system_types.find((x) => x.id === s)?.label || s);
  const dt = (d.data_types || []).map((s) => v.data_types.find((x) => x.id === s)?.label || s);
  const exp = v.exposures.find((x) => x.id === d.exposure);
  const customTitles = new Set(r.items.filter((i) => !i.subcategory_id).map((i) => (i.title || '').trim().toLowerCase()));
  const list = (arr, ic) => `<div class="stack" style="gap:6px">${arr.map((x) => `<div class="q-row" style="padding:4px 2px">${icon(ic)}<div class="x">${esc(x)}</div></div>`).join('')}</div>`;
  return `
    <div class="head" style="margin-bottom:12px"><span class="spark">${icon('sparkles')}</span>
      <div style="flex:1"><h2 class="section-title" style="margin:0">Design understanding</h2>
      <div class="small muted">${d.source === 'ai' ? 'AI analysis by' : 'Offline detection ·'} <span class="mono">${esc(d.provider || 'heuristic')}</span> · ${timeAgo(d.analyzed_at)}</div></div>
      ${d.uses_ai ? `<span class="badge ai">${icon('cpu')} Uses AI</span>` : ''}${d.third_party ? `<span class="badge">${icon('building')} Third party</span>` : ''}</div>
    ${d.warning ? `<div class="warning">${icon('alert')}<div>${esc(d.warning)}</div></div>` : ''}
    <p class="summary">${esc(d.summary || '')}</p>
    <div class="dz-grid">
      <div class="dz"><div class="k">${icon('layers')} What it is</div><div class="v">${esc(st.join(' · ') || 'Unclear')}</div></div>
      <div class="dz"><div class="k">${icon('globe')} Exposure</div><div class="v">${esc(exp?.label || cap(d.exposure) || '—')}</div></div>
      <div class="dz"><div class="k">${icon('lock')} Suggested classification</div><div class="v">${d.suggested_classification ? clsBadge(d.suggested_classification) : '—'}</div></div>
    </div>
    <div class="kv" style="margin-bottom:16px">
      <span>Data handled</span><div class="chips">${dt.map((x) => `<span class="chip">${esc(x)}</span>`).join('') || '<span class="muted">—</span>'}</div>
      ${(d.technologies || []).length ? `<span>Platforms</span><div class="chips">${d.technologies.map((x) => `<span class="chip">${esc(x)}</span>`).join('')}</div>` : ''}
      ${(d.services || []).length ? `<span>Services</span><div class="chips">${d.services.map((x) => `<span class="chip">${esc(x)}</span>`).join('')}</div>` : ''}
      ${(d.integrations || []).length ? `<span>Integrations</span><div class="chips">${d.integrations.map((x) => `<span class="chip">${esc(typeof x === 'string' ? x : x.name || JSON.stringify(x))}</span>`).join('')}</div>` : ''}
    </div>
    ${(d.components || []).length ? `<h3 class="label" style="margin:0 0 8px">Components</h3><div class="comp-grid" style="margin-bottom:16px">${d.components.map((c) => `
      <div class="comp"><b>${icon(COMP_ICON[c.type] || 'cpu')} ${esc(c.name)}</b><span class="ty">${esc(c.type || '')}</span><small>${esc(c.description || '')}</small></div>`).join('')}</div>` : ''}
    ${(d.data_flows || []).length ? `<h3 class="label" style="margin:0 0 8px">Data flows</h3><div style="overflow-x:auto;margin-bottom:16px"><table class="flows"><thead><tr><th>From</th><th></th><th>To</th><th>Data</th><th>Protocol</th><th></th></tr></thead><tbody>
      ${d.data_flows.map((f) => `<tr><td>${esc(f.from)}</td><td class="arrow">→</td><td>${esc(f.to)}</td><td>${esc(f.data || '')}</td><td class="mono">${esc(f.protocol || '')}</td><td>${f.crosses_boundary ? '<span class="cross">crosses trust boundary</span>' : ''}</td></tr>`).join('')}</tbody></table></div>` : ''}
    <div class="grid-2" style="margin-bottom:6px">
      ${(d.trust_boundaries || []).length ? `<div><h3 class="label" style="margin:0 0 6px">Trust boundaries</h3>${list(d.trust_boundaries, 'lock')}</div>` : ''}
      ${(d.notable_concerns || []).length ? `<div><h3 class="label" style="margin:0 0 6px;color:#fda4af">Notable concerns</h3>${list(d.notable_concerns, 'alert')}</div>` : ''}
    </div>
    ${(d.open_questions || []).length ? `<h3 class="label" style="margin:12px 0 6px">Open questions for the team</h3><div>${d.open_questions.map((q, k) => {
      const added = customTitles.has(q.trim().toLowerCase());
      return `<div class="q-row ${added ? 'added' : ''}">${icon('message')}<div class="x">${esc(q)}</div>${isTm ? '' : added ? '<span class="small muted">added</span>' : `<button class="btn sm" data-addq="${k}" id="addq-${k}">${icon('plus')} Add as question</button>`}</div>`;
    }).join('')}</div>` : ''}
    <div class="apply-box">
      <div class="row wrap"><b>${icon('target')} Apply to the ${isTm ? 'threat model' : 'review'} profile</b><span class="small muted">merges with what is already set</span></div>
      <div class="opts" id="apply-opts">${APPLY.map(([k, l]) => `<span class="chip tog on" data-k="${k}" id="ap-${k}">${l}${preview(ctx, k)}</span>`).join('')}</div>
      <div class="row wrap">${isTm ? '' : '<label class="row small" style="gap:8px;cursor:pointer"><span class="switch"><input type="checkbox" id="apply-rescope" checked /><span></span></span>Re-run scoping afterwards</label>'}
        <span class="spacer"></span><button class="btn primary" id="apply-design">${icon('check')} Apply</button></div>
    </div>`;
}

function preview(ctx, k) {
  const d = ctx.r.design || {};
  if (k === 'exposure' && d.exposure && d.exposure !== ctx.r.exposure) return ` <span class="muted">→ ${esc(cap(d.exposure))}</span>`;
  if (k === 'data_classification' && d.suggested_classification && d.suggested_classification !== ctx.r.data_classification) return ` <span class="muted">→ ${esc(CLS[d.suggested_classification]?.code || '')}</span>`;
  if (['system_types', 'data_types', 'technologies', 'services'].includes(k)) {
    const add = (d[k] || []).filter((x) => !(ctx.r[k] || []).includes(x)).length;
    return add ? ` <span class="muted">+${add}</span>` : '';
  }
  return '';
}

function wireDesign(el, ctx) {
  const panel = el.querySelector('#design-panel');
  panel.querySelector('#apply-opts')?.addEventListener('click', (e) => { const c = e.target.closest('[data-k]'); if (c) c.classList.toggle('on'); });
  panel.querySelectorAll('[data-addq]').forEach((b) => b.addEventListener('click', async () => {
    const q = ctx.r.design.open_questions[+b.dataset.addq];
    try {
      const res = await api.post(`/api/reviews/${ctx.r.id}/items`, { kind: 'question', title: q, source: 'document', rationale: 'Open question from the design documents', priority: 'medium' });
      ctx.set(res.review);
      toast('Question added to line items');
    } catch (err) { toast(err.message, 'err'); }
  }));
  panel.querySelector('#apply-design')?.addEventListener('click', async () => {
    const fields = [...panel.querySelectorAll('#apply-opts .on')].map((c) => c.dataset.k);
    const rescope = ctx.r.kind !== 'threat_model' && panel.querySelector('#apply-rescope').checked;
    const stop = rescope ? scopingOverlay() : null;
    try {
      const fresh = await api.post(`/api/reviews/${ctx.r.id}/design/apply`, { fields, rescope, source: 'design' });
      stop?.();
      ctx.set(fresh);
      toast(rescope ? `Profile updated and re-scoped · ${fresh.requirements.length} NIST questions` : 'Profile updated from the design');
    } catch (err) { stop?.(); toast(err.message, 'err'); }
  });
}
