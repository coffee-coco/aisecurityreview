// Threat model tab (security review): link threat models built on the Threat models page and promote their
// threats, mitigations and code findings into this review's risk register and control register.
import { api } from '../api.js';
import { renderMermaid } from '../mermaid.js';
import { cap, confirmDialog, esc, icon, ratingPill, timeAgo, toast } from '../ui.js';

const ARTIFACTS = [
  ['threat_model', 'Threat Model'], ['attack_tree', 'Attack Tree'], ['dfd', 'Data Flow Diagram'],
  ['mitigations', 'Mitigations'], ['dread', 'DREAD'], ['test_cases', 'Test Cases'],
];
const CATEGORIES = [
  { id: 'Spoofing', color: '#60a5fa' },
  { id: 'Tampering', color: '#fbbf24' },
  { id: 'Repudiation', color: '#a78bfa' },
  { id: 'Information Disclosure', color: '#22d3ee' },
  { id: 'Denial of Service', color: '#fb923c' },
  { id: 'Elevation of Privilege', color: '#f43f5e' },
];
const SUBS = [
  { id: 'threats', label: 'Threats', icon: 'shield' },
  { id: 'mitigations', label: 'Mitigations', icon: 'lock' },
  { id: 'findings', label: 'Code findings', icon: 'code' },
  { id: 'dfd', label: 'Data flow diagram', icon: 'layers' },
];
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };
const PRIORITY_ORDER = { high: 3, medium: 2, low: 1 };
const SRC_ICON = { git: 'package', archive: 'package', files: 'file', snippet: 'code' };

// Per-review UI state survives tab re-renders (ctx.set re-renders the active tab).
const STATE = new Map();
const cleaned = new WeakSet();
const svgCache = new Map();

function st(ctx) {
  const rid = ctx.r.id;
  if (!STATE.has(rid)) STATE.set(rid, { rid, data: null, err: '', skip: false, seq: 0, sub: {}, cat: {} });
  return STATE.get(rid);
}

// ------------------------------------------------------------------ helpers
const list = (x) => (Array.isArray(x) ? x : []);
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const num = (x) => (Array.isArray(x) ? x.length : Number(x) || 0);
const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z]/g, '');
const catOf = (c) => CATEGORIES.find((x) => norm(x.id) === norm(c));
const dat = (tm, k) => tm.artifacts?.[k]?.data || null;
const threatsOf = (tm) => list(dat(tm, 'threat_model')?.threats);
const mitsOf = (tm) => list(dat(tm, 'mitigations')?.mitigations).slice().sort((a, b) => (PRIORITY_ORDER[b.priority] || 0) - (PRIORITY_ORDER[a.priority] || 0));
const findingsOf = (tm) => list(tm.findings).slice().sort((a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0));
const hotFindings = (tm) => findingsOf(tm).filter((f) => ['critical', 'high'].includes(f.severity) && !f.item_id);
const dfdSrc = (tm) => String(dat(tm, 'dfd')?.mermaid || '');
const shownThreats = (S, tm) => threatsOf(tm).filter((t) => !S.cat[tm.id] || catOf(t.category)?.id === S.cat[tm.id]);
const tmUrl = (tm) => `#/threat-model/${tm.id}`;
const refHTML = (ref) => `<span class="mono small" style="color:var(--accent-2)">${esc(ref)}</span>`;

// ------------------------------------------------------------------ lifecycle
export function render(el, ctx) {
  const S = st(ctx);
  S.el = el; S.ctx = ctx;
  if (!cleaned.has(ctx)) {
    cleaned.add(ctx);
    ctx.onCleanup(() => { if (S.ctx === ctx) { S.ctx = null; S.el = null; } });
  }
  if (S.skip) { S.skip = false; draw(S); return; }
  if (S.data) draw(S);
  else el.innerHTML = '<div class="loading"><span class="spin"></span>Loading linked threat models…</div>';
  reload(S);
}

async function reload(S) {
  const seq = S.seq;
  try {
    const fresh = await api.get(`/api/reviews/${S.rid}/threat-models`);
    if (seq !== S.seq) return;
    const changed = JSON.stringify(fresh) !== JSON.stringify(S.data);
    S.data = fresh; S.err = '';
    if (changed) draw(S);
  } catch (e) {
    if (seq !== S.seq) return;
    S.err = e.message;
    if (!S.data) draw(S); else toast(e.message, 'err');
  }
}

/** Keep the mutation payload, then let the shell re-render every panel with the fresh review. */
function apply(S, res, msg) {
  S.seq += 1;
  S.data = { linked: list(res.linked), available: list(res.available) };
  S.err = '';
  if (S.ctx) { S.skip = S.ctx.ui.tab === 'threats'; S.ctx.set(res.review); }
  if (msg) toast(msg);
}

async function act(btn, fn) {
  const label = btn.innerHTML;
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Working…';
  try { await fn(); } catch (e) {
    toast(e.message, 'err', 6000);
    if (btn.isConnected) { btn.disabled = false; btn.innerHTML = label; }
  }
}

// ------------------------------------------------------------------ shell
function draw(S) {
  const el = S.el;
  if (!el || !el.isConnected || !S.ctx || S.ctx.ui.tab !== 'threats') return;
  if (!S.data) {
    el.innerHTML = `<div class="empty"><div class="ic">${icon('alert')}</div><h3>Threat models unavailable</h3>
      <p>${esc(S.err || 'Could not load the linked threat models.')}</p><button class="btn" id="tml-retry">${icon('refresh')} Retry</button></div>`;
    el.querySelector('#tml-retry').addEventListener('click', () => reload(S));
    return;
  }
  const linked = list(S.data.linked);
  const available = list(S.data.available);
  el.innerHTML = `<div class="tml">${linked.length ? linkedHTML(S, linked, available) : emptyHTML(available)}</div>`;
  const root = el.firstElementChild;
  root.addEventListener('click', (e) => onClick(S, e));
  root.querySelectorAll('[data-dfd]').forEach((box) => mountDfd(box, linked.find((t) => t.id === +box.dataset.dfd)));
}

function sourceChips(t) {
  return list(t.sources).map((s) => `<span class="tag" title="${esc(s.url || cap(s.type))}">${icon(SRC_ICON[s.type] || 'file')} ${esc(s.name)}${s.type === 'git'
    ? `${s.ref ? ` · ${esc(s.ref)}` : ''}${s.commit ? ` @ ${esc(String(s.commit).slice(0, 8))}` : ''}` : ''}${s.files != null ? ` · ${plural(num(s.files), 'file')}` : ''}</span>`).join('');
}

function countChips(t) {
  return ARTIFACTS.map(([k, l]) => {
    const n = t.counts?.[k] || 0;
    return `<span class="tag ${n ? 't-stack' : ''}" style="${n ? '' : 'opacity:.6'}" title="${l}">${l} <b>${n}</b></span>`;
  }).join('');
}

function findingsChip(t) {
  const cr = t.code_review || {};
  return cr.ran_at
    ? `<span class="tag t-stack" title="Code review ran ${esc(timeAgo(cr.ran_at))}">${icon('code')} ${plural(num(t.findings ?? cr.findings), 'code finding')}</span>`
    : `<span class="tag" style="opacity:.6">${icon('code')} Code review not run</span>`;
}

function emptyHTML(available) {
  return `<section class="card" style="padding:18px">
    <div class="empty tm-empty"><div class="ic">${icon('target')}</div><h3>No threat model linked</h3>
      <p>Build the threat model on the Threat models page from a git repository or uploaded code, then link it here to promote its threats, mitigations and code findings into this review.</p>
      <div class="row wrap" style="justify-content:center;margin-top:14px"><a class="btn sm ${available.length ? '' : 'primary'}" href="#/threat-models">${icon('plus')} Create a threat model</a></div></div>
    ${available.length ? `<h2 class="section-title">${icon('link')} Available threat models <span class="badge">${available.length}</span></h2>
      <div class="stack" style="gap:8px">${available.map(availableHTML).join('')}</div>` : ''}
  </section>`;
}

function availableHTML(t) {
  const reviews = list(t.linked_reviews);
  return `<article class="tm-case" data-avail="${t.id}">
    <div class="row">${refHTML(t.ref)}<b>${esc(t.title)}</b><span class="spacer"></span>
      <button class="btn sm primary" data-link="${t.id}">${icon('link')} Link</button></div>
    ${t.description ? `<div class="small muted">${esc(t.description)}</div>` : ''}
    <div class="tm-tags">${sourceChips(t)}${countChips(t)}${findingsChip(t)}
      <span class="tag" title="${esc(reviews.map((r) => r.ref).join(', '))}">${icon('link')} ${plural(reviews.length, 'linked review')}</span></div>
  </article>`;
}

function linkedHTML(S, linked, available) {
  return `${available.length ? `<div class="row wrap tm-bulk" style="justify-content:flex-end">
      <label class="small muted" for="tml-pick">Link another threat model</label>
      <select class="select sm" id="tml-pick" style="width:auto;max-width:340px">${available.map((t) => `<option value="${t.id}">${esc(t.ref)} · ${esc(t.title)}</option>`).join('')}</select>
      <button class="btn sm" data-link-pick>${icon('link')} Link</button></div>` : ''}
    ${linked.map((tm) => cardHTML(S, tm)).join('')}`;
}

function cardHTML(S, tm) {
  const sub = S.sub[tm.id] || 'threats';
  const counts = { threats: threatsOf(tm).length, mitigations: mitsOf(tm).length, findings: list(tm.findings).length, dfd: list(dat(tm, 'dfd')?.nodes).length };
  const body = { threats: threatsBody, mitigations: mitigationsBody, findings: findingsBody, dfd: dfdBody }[sub] || threatsBody;
  return `<section class="card tm-head" data-tm="${tm.id}">
    <div class="row wrap" style="align-items:flex-start">
      <div style="flex:1;min-width:0">
        ${refHTML(tm.ref)}
        <h2 class="section-title" style="margin:2px 0 6px">${icon('target')} ${esc(tm.title)}</h2>
        ${tm.description ? `<p class="small muted" style="margin:0 0 6px">${esc(tm.description)}</p>` : ''}
        <div class="tm-tags">${sourceChips(tm) || `<span class="tag" style="opacity:.6">${icon('code')} No code linked</span>`}</div>
        <div class="tm-tags">${countChips(tm)}${findingsChip(tm)}</div>
      </div>
      <div class="row wrap">
        <a class="btn sm" href="${tmUrl(tm)}">${icon('next')} Open threat model</a>
        <button class="btn sm ghost danger" data-unlink title="Unlink from this review">${icon('x')} Unlink</button>
      </div>
    </div>
    <nav class="tm-nav" role="tablist" style="margin:14px 0 12px">${SUBS.map((v) => `<button class="filt tm-pill ${sub === v.id ? 'on' : ''}" role="tab" aria-selected="${sub === v.id}" data-sub="${v.id}">${icon(v.icon)}${v.label}<span class="n">${counts[v.id]}</span></button>`).join('')}</nav>
    <div role="tabpanel">${body(S, tm)}</div>
  </section>`;
}

function emptySub(tm, ic, title, text) {
  return `<div class="empty tm-empty"><div class="ic">${icon(ic)}</div><h3>${title}</h3><p>${text}</p>
    <div class="row wrap" style="justify-content:center;margin-top:14px"><a class="btn sm primary" href="${tmUrl(tm)}">${icon('next')} Open threat model</a></div></div>`;
}

// ------------------------------------------------------------------ threats
function threatsBody(S, tm) {
  const all = threatsOf(tm);
  if (!all.length) return emptySub(tm, 'shield', 'No threats yet', 'Generate the Threat Model on the threat model page, then promote its threats to risks here.');
  const cat = S.cat[tm.id] || '';
  const dread = Object.fromEntries(list(dat(tm, 'dread')?.assessments).map((a) => [String(a.threat_id), a]));
  const byCat = Object.fromEntries(CATEGORIES.map((c) => [c.id, all.filter((t) => catOf(t.category)?.id === c.id).length]));
  const shown = shownThreats(S, tm);
  const todo = shown.filter((t) => !t.item_id).length;
  return `<div class="row wrap tm-tools">
      <div class="filters"><button class="filt ${!cat ? 'on' : ''}" data-cat="">All<span class="n">${all.length}</span></button>
        ${CATEGORIES.filter((c) => byCat[c.id] || cat === c.id).map((c) => `<button class="filt ${cat === c.id ? 'on' : ''}" data-cat="${esc(c.id)}" style="--c:${c.color}"><i></i>${c.id}<span class="n">${byCat[c.id]}</span></button>`).join('')}</div>
      <span class="spacer"></span>
      <span class="small muted">${all.filter((t) => t.item_id).length} of ${plural(all.length, 'threat')} promoted</span>
      ${todo ? `<button class="btn sm primary" data-promote-all>${icon('flag')} Promote all (${todo})</button>` : ''}
    </div>
    ${shown.map((t) => threatRow(t, dread[String(t.id)])).join('') || '<div class="empty" style="padding:24px"><p>No threats in this category.</p></div>'}`;
}

function threatRow(t, dr) {
  const c = catOf(t.category);
  return `<article class="tm-threat" data-tid="${esc(t.id)}" style="--c:${c?.color || 'var(--muted)'}">
    <div class="tm-main">
      <div class="row wrap" style="gap:6px">
        <span class="tm-cat">${esc(c?.id || t.category || 'Uncategorised')}</span>
        <span class="mono muted">${esc(t.id)}</span>
        ${dr?.rating ? `${ratingPill(dr.rating)}<span class="small muted" title="DREAD score">DREAD ${esc(dr.score)}</span>` : ''}
      </div>
      <h3 class="tm-title">${esc(t.title || 'Untitled threat')}</h3>
      ${t.component ? `<div class="small muted tm-comp">${icon('cpu')} ${esc(t.component)}</div>` : ''}
      ${t.scenario ? `<p class="tm-text"><b>Scenario</b>${esc(t.scenario)}</p>` : ''}
      ${t.impact ? `<p class="tm-text"><b>Impact</b>${esc(t.impact)}</p>` : ''}
      ${list(t.evidence).length ? `<div class="tm-tags" title="Code references that support this threat">${t.evidence.map((e) => `<span class="tag mono">${icon('code')} ${esc(e)}</span>`).join('')}</div>` : ''}
    </div>
    <div class="tm-actions">${t.item_id
      ? `<span class="small" style="color:var(--ok)">${icon('check')} Promoted</span><button class="btn sm" data-open-risk="${t.item_id}">${icon('flag')} Open risk</button>`
      : `<button class="btn sm primary" data-promote>${icon('flag')} Promote to risk</button>`}</div>
  </article>`;
}

// ------------------------------------------------------------------ mitigations
function mitigationsBody(S, tm) {
  const ms = mitsOf(tm);
  if (!ms.length) return emptySub(tm, 'lock', 'No mitigations yet', 'Generate Mitigations on the threat model page, then add them to this review’s control register.');
  const titles = Object.fromEntries(threatsOf(tm).map((t) => [String(t.id), t.title]));
  const todo = ms.filter((m) => !m.mitigation_id).length;
  return `<div class="row wrap tm-bulk"><span class="small muted">${ms.length - todo} of ${plural(ms.length, 'mitigation')} in the control register · adding one also promotes the threats it addresses</span>
      <span class="spacer"></span>${todo ? `<button class="btn sm primary" data-mit-all>${icon('shield')} Add all (${todo})</button>` : ''}</div>
    <div class="tm-table-wrap"><table class="flows tm-table"><thead><tr><th>Mitigation</th><th>Threats</th><th>NIST SP 800-53</th><th>Priority</th><th></th></tr></thead><tbody>
      ${ms.map((m) => `<tr data-mid="${esc(m.id)}">
        <td class="tm-mt"><b>${esc(m.title || m.id)}</b>${m.description ? `<div class="small muted">${esc(m.description)}</div>` : ''}</td>
        <td><div class="chips">${list(m.threat_ids).map((id) => `<span class="chip mono" title="${esc(titles[String(id)] || '')}">${esc(id)}</span>`).join('') || '<span class="muted">—</span>'}</div></td>
        <td><div class="chips">${list(m.nist).map((n) => `<span class="chip tm-nist">${esc(n)}</span>`).join('') || '<span class="muted">—</span>'}</div></td>
        <td>${ratingPill(m.priority) || '<span class="muted">—</span>'}</td>
        <td class="tm-act">${m.mitigation_id
          ? `<button class="btn sm" data-open-ctl="${m.mitigation_id}">${icon('shield')} Open control</button>`
          : `<button class="btn sm primary" data-mit>${icon('plus')} Add to control register</button>`}</td>
      </tr>`).join('')}
    </tbody></table></div>`;
}

// ------------------------------------------------------------------ code findings
function findingsBody(S, tm) {
  const fs = findingsOf(tm);
  const cr = tm.code_review || {};
  if (!fs.length) {
    return cr.ran_at
      ? emptySub(tm, 'code', 'No code findings', `The code review ran ${esc(timeAgo(cr.ran_at))} and found no issues.`)
      : emptySub(tm, 'code', 'Code review not run', 'Link a git repository or upload code on the threat model page and run the code review, then add its findings here as risks.');
  }
  const hot = hotFindings(tm).length;
  return `<div class="row wrap tm-bulk"><span class="small muted">${fs.filter((f) => f.item_id).length} of ${plural(fs.length, 'finding')} added as risks${cr.ran_at ? ` · reviewed ${esc(timeAgo(cr.ran_at))}` : ''}</span>
      <span class="spacer"></span>${hot ? `<button class="btn sm primary" data-find-hot>${icon('flag')} Add critical/high as risks (${hot})</button>` : ''}</div>
    ${fs.map(findingRow).join('')}`;
}

function findingRow(f) {
  const files = [...new Set(list(f.evidence).filter((e) => e.file).map((e) => `${e.file}${e.line ? `:${e.line}` : ''}`))];
  return `<div class="finding sev-${esc(f.severity)} open" data-fid="${esc(f.id)}">
    <div class="finding-head" style="cursor:default">${ratingPill(f.severity)}
      <div class="t">${esc(f.title)}<small>${esc(cap(f.category || ''))}${f.source ? ` · ${esc(cap(f.source))}` : ''}</small></div>
      ${f.item_id ? `<button class="btn sm" data-open-risk="${f.item_id}">${icon('flag')} Open risk</button>` : `<button class="btn sm primary" data-find>${icon('flag')} Add as risk</button>`}
    </div>
    <div class="finding-body">
      ${f.description ? `<p style="margin:0 0 8px">${esc(f.description)}</p>` : ''}
      ${files.length ? `<div class="tm-tags" style="margin:0 0 8px">${files.slice(0, 8).map((x) => `<span class="tag mono">${icon('code')} ${esc(x)}</span>`).join('')}${files.length > 8 ? `<span class="small muted">+${files.length - 8} more</span>` : ''}</div>` : ''}
      ${f.recommendation ? `<div class="apply-row" style="margin:0">${icon('bulb')}<div class="x"><b>Fix:</b> ${esc(f.recommendation)}</div></div>` : ''}
    </div>
  </div>`;
}

// ------------------------------------------------------------------ data flow diagram
function dfdBody(S, tm) {
  const src = dfdSrc(tm);
  if (!src.trim()) return emptySub(tm, 'layers', 'No data flow diagram yet', 'Generate or import a Data Flow Diagram on the threat model page to see it here.');
  return `<div class="tm-diagram" style="margin:0"><div class="tm-canvas" data-dfd="${tm.id}">${svgCache.get(src) || '<div class="loading"><span class="spin"></span>Rendering diagram…</div>'}</div></div>`;
}

async function mountDfd(box, tm) {
  const src = tm ? dfdSrc(tm) : '';
  if (!src.trim() || svgCache.has(src)) return;
  try {
    const svg = await renderMermaid(src);
    svgCache.set(src, svg);
    if (box.isConnected) box.innerHTML = svg;
  } catch (e) {
    if (!box.isConnected) return;
    box.innerHTML = `<div class="warning">${icon('alert')}<div>The diagram could not be rendered${e?.message ? ` (${esc(e.message.split('\n')[0])})` : ''}. Mermaid source:</div></div>
      <pre class="code-view tm-src">${esc(src)}</pre>`;
  }
}

// ------------------------------------------------------------------ actions
async function link(S, btn, id) {
  const ref = list(S.data.available).find((t) => t.id === id)?.ref || 'Threat model';
  await act(btn, async () => apply(S, await api.post(`/api/reviews/${S.rid}/threat-models`, { threat_model_id: id }), `${ref} linked`));
}

async function onClick(S, e) {
  const b = e.target.closest('button');
  if (!b || b.disabled) return;
  if (b.dataset.link) { link(S, b, +b.dataset.link); return; }
  if ('linkPick' in b.dataset) { link(S, b, +S.el.querySelector('#tml-pick').value); return; }
  const tm = list(S.data.linked).find((t) => t.id === +b.closest('[data-tm]')?.dataset.tm);
  if (!tm) return;
  const base = `/api/reviews/${S.rid}/threat-models/${tm.id}`;
  if (b.dataset.sub) { S.sub[tm.id] = b.dataset.sub; draw(S); return; }
  if ('cat' in b.dataset) { S.cat[tm.id] = b.dataset.cat; draw(S); return; }
  if (b.dataset.openRisk) { S.ctx.jumpToItem(+b.dataset.openRisk); return; }
  if (b.dataset.openCtl) { S.ctx.jumpToControl(+b.dataset.openCtl); return; }
  if ('unlink' in b.dataset) {
    if (!(await confirmDialog(`Unlink ${tm.ref}?`, `${tm.title} stays on the Threat models page. Risks and controls already promoted from it stay in this review.`, 'Unlink'))) return;
    act(b, async () => apply(S, await api.del(base), `${tm.ref} unlinked`));
    return;
  }
  const promote = (ids) => act(b, async () => {
    const res = await api.post(`${base}/promote`, { threat_ids: ids });
    const n = list(res.created).length;
    apply(S, res, n ? `${plural(n, 'risk')} added to Line items` : 'Already in Line items');
  });
  if ('promote' in b.dataset) { const tid = b.closest('[data-tid]').dataset.tid; promote(threatsOf(tm).filter((t) => String(t.id) === tid).map((t) => t.id)); return; }
  if ('promoteAll' in b.dataset) { promote(shownThreats(S, tm).filter((t) => !t.item_id).map((t) => t.id)); return; }
  const addMits = (ids) => act(b, async () => apply(S, await api.post(`${base}/mitigations/promote`, { ids }), `${plural(ids.length, 'mitigation')} added to Mitigating controls`));
  if ('mit' in b.dataset) { const mid = b.closest('[data-mid]').dataset.mid; addMits(mitsOf(tm).filter((m) => String(m.id) === mid).map((m) => m.id)); return; }
  if ('mitAll' in b.dataset) { addMits(mitsOf(tm).filter((m) => !m.mitigation_id).map((m) => m.id)); return; }
  const addFinding = (fid) => api.post(`${base}/findings/${encodeURIComponent(fid)}/promote`);
  if ('find' in b.dataset) { const fid = b.closest('[data-fid]').dataset.fid; act(b, async () => apply(S, await addFinding(fid), 'Risk added to Line items')); return; }
  if ('findHot' in b.dataset) {
    act(b, async () => {
      let last = null;
      let n = 0;
      try {
        for (const f of hotFindings(tm)) { last = await addFinding(f.id); n += 1; }
      } finally {
        if (last) apply(S, last, `${plural(n, 'risk')} added to Line items`);
      }
    });
  }
}
