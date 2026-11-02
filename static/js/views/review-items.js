// Line items tab: NIST CSF questions + custom questions, risks and recommendations.
// Every row can be answered, flagged as a risk and/or recommendation, rated (5x5), and closed
// by one or more mitigating controls from the review's shared register.
import { api } from '../api.js';
import { aiField, wireAi } from '../ai-text.js';
import {
  CHECK, FN_COLOR, REQ, cap, confirmDialog, debounce, esc, icon, openOverlay, riskBadge, timeAgo, toast,
} from '../ui.js';
import {
  checkRow, includeCheckLink, openControlDrawer, removeCheckLink, restoreCheckLink,
} from './shared.js';

const TEXT_FIELDS = new Set(['title', 'answer', 'notes', 'risk', 'impact_description', 'recommendation']);
const KIND = {
  question: { label: 'Question', icon: 'message', color: 'var(--K-question)' },
  risk: { label: 'Risk', icon: 'flag', color: 'var(--K-risk)' },
  recommendation: { label: 'Recommendation', icon: 'bulb', color: 'var(--K-recommendation)' },
};
const SRC = { ai: 'AI', heuristic: 'Scoping', library: 'Risk library', code: 'Code review', threat: 'Threat model', document: 'Document' };
const FILTERS = [
  { id: 'all', label: 'All' },
  { id: 'todo', label: 'Unanswered', c: '#fbbf24' },
  { id: 'done', label: 'Answered', c: '#34d399' },
  { id: 'risk', label: 'Risks', c: 'var(--K-risk)' },
  { id: 'rec', label: 'Recommendations', c: 'var(--K-recommendation)' },
  { id: 'need', label: 'Needs control', c: '#fb923c' },
  { id: 'gaps', label: 'Gaps', c: '#f43f5e' },
  { id: 'custom', label: 'Custom', c: 'var(--accent)' },
];
const PAGE = 15;

const needsControl = (i) => (i.is_risk || ['not_met', 'partial'].includes(i.status)) && !i.mitigation_ids.length;
const rateOf = (l, i) => { const s = l * i; return s >= 20 ? 'critical' : s >= 12 ? 'high' : s >= 5 ? 'medium' : 'low'; };
// Requirement frameworks: CSF functions plus NIST AI RMF / OWASP functions from /api/meta.
const fnMeta = (ctx, fid) => ctx.meta.functions.find((f) => f.id === fid) || {};
const fnColor = (ctx, fid) => { const c = fnMeta(ctx, fid).color; return c ? `var(--${c})` : FN_COLOR(fid); };
const fwOf = (ctx, i) => fnMeta(ctx, i.subcategory?.function_id).framework || 'csf';
const fwShort = (ctx, fid) => (ctx.meta.frameworks || []).find((f) => f.id === fid)?.short || fid.toUpperCase();

function state(ctx) {
  return (ctx.ui.items ||= { filter: 'all', fn: 'all', q: '', open: new Set(), sugg: {}, det: {}, ai: {}, checks: {}, copts: {}, pending: {}, timers: {}, newForm: new Set() });
}

const visible = (S, i) => {
  if (S.fn !== 'all' && i.subcategory?.function_id !== S.fn) return false;
  switch (S.filter) {
    case 'todo': if (i.answered) return false; break;
    case 'done': if (!i.answered) return false; break;
    case 'risk': if (!i.is_risk) return false; break;
    case 'rec': if (!i.is_recommendation) return false; break;
    case 'need': if (!needsControl(i)) return false; break;
    case 'gaps': if (!['not_met', 'partial'].includes(i.status)) return false; break;
    case 'custom': if (i.subcategory_id) return false; break;
    default:
  }
  if (S.q) {
    const hay = `${i.label} ${i.display_title} ${i.answer} ${i.risk} ${i.recommendation} ${i.subcategory?.text || ''} ${i.subcategory?.category_title || ''}`.toLowerCase();
    if (!hay.includes(S.q)) return false;
  }
  return true;
};

// =================================================================== render
export function render(el, ctx) {
  const S = state(ctx);
  S.det = {};
  el.innerHTML = `
    <div id="li-ai"></div>
    <section class="card" style="padding:16px 16px 8px" id="li-card">
      <div class="li-toolbar">
        <div class="row wrap">
          <h2 class="section-title" style="margin:0">${icon('list')} Line items <span class="muted small" style="font-weight:500">questions · risks · recommendations</span></h2>
          <span class="spacer"></span>
          <button class="btn sm" id="li-suggest-risks" title="Suggest design-specific risks not already recorded">${icon('sparkles')} Suggest risks</button>
          <button class="btn sm" id="li-autolink" title="Link the best existing or library control to every risk / gap without one">${icon('wand')} Auto-link controls</button>
          <div class="add-menu"><button class="btn sm primary" id="li-add">${icon('plus')} Add line ${icon('chevron')}</button></div>
        </div>
        <div class="answered-bar" id="li-answered"></div>
        <div class="row wrap">
          <div class="filters" id="li-filters"></div>
          <span class="spacer"></span>
          <select class="select sm" id="li-fn" style="width:160px" aria-label="Framework function"></select>
          <div class="search" style="width:220px">${icon('search')}<input class="input sm" id="li-q" placeholder="Search line items…" value="${esc(S.q)}" /></div>
        </div>
      </div>
      <div id="li-list"></div>
    </section>`;

  renderAI(el, ctx);
  renderToolbar(el, ctx);
  renderList(el, ctx);

  // toolbar wiring
  el.querySelector('#li-filters').addEventListener('click', (e) => {
    const b = e.target.closest('[data-f]'); if (!b) return;
    S.filter = b.dataset.f; renderToolbar(el, ctx); renderList(el, ctx);
  });
  el.querySelector('#li-fn').addEventListener('change', (e) => { S.fn = e.target.value; renderList(el, ctx); });
  el.querySelector('#li-q').addEventListener('input', debounce((e) => { S.q = e.target.value.toLowerCase(); renderList(el, ctx); }, 200));
  el.querySelector('#li-add').addEventListener('click', (e) => { e.stopPropagation(); toggleAddMenu(el, ctx); });
  el.querySelector('#li-autolink').addEventListener('click', () => autoLink(ctx));
  el.querySelector('#li-suggest-risks').addEventListener('click', () => suggestRisks(ctx));

  const list = el.querySelector('#li-list');
  list.addEventListener('click', (e) => onListClick(e, el, ctx));
  list.addEventListener('change', (e) => onListChange(e, el, ctx));
  list.addEventListener('input', (e) => {
    const f = e.target.closest('[data-field]');
    const art = e.target.closest('.li');
    if (!f || !art || !TEXT_FIELDS.has(f.dataset.field)) return;
    queueSave(el, ctx, +art.dataset.id, f.dataset.field, f.value);
  });
  wireAi(list, (ctl) => ({ review_id: ctx.r.id, item_id: +ctl.closest('.li').dataset.id }));

  // deterministic inline control suggestions for items that still need one
  api.get(`/api/reviews/${ctx.r.id}/suggestions`).then((s) => {
    S.sugg = s || {};
    Object.keys(S.sugg).forEach((id) => updateHead(el, ctx, +id));
  }).catch(() => {});
}

// =================================================================== AI scoping card
function renderAI(el, ctx) {
  const r = ctx.r;
  const ai = r.ai_meta || {};
  const box = el.querySelector('#li-ai');
  if (!ai.scoped_at) {
    box.innerHTML = `<div class="card ai-panel glow" style="margin-bottom:14px"><div class="row" style="gap:14px">
      <span class="spark">${icon('sparkles')}</span><div style="flex:1"><h2 class="section-title" style="margin:0">Not scoped yet</h2>
      <div class="small muted">Run AI scoping to select NIST CSF 2.0 questions for this profile. Upload architecture documents first for a sharper scope.</div></div>
      <button class="btn primary" id="scope-now">${icon('sparkles')} Run AI scoping</button></div></div>`;
    box.querySelector('#scope-now').addEventListener('click', ctx.rescope);
    return;
  }
  const allProviders = ctx.meta.providers.map((p) => p.name).filter((p) => !r.technologies.includes(p));
  box.innerHTML = `<details class="card ai-panel glow" style="margin-bottom:14px" id="li-ai-card" ${ctx.ui.aiOpen ? 'open' : ''}>
    <summary class="head" style="cursor:pointer;list-style:none;margin:0"><span class="spark">${icon('sparkles')}</span>
      <div style="min-width:0;flex:1"><h2 class="section-title" style="margin:0">AI scoping</h2>
      <div class="small muted">${ai.source === 'ai' ? 'Generated by' : 'Offline rules'} <span class="mono">${esc(ai.provider)}</span> · ${timeAgo(ai.scoped_at)} · ${r.technologies.length} platform${r.technologies.length === 1 ? '' : 's'} · ${(ai.key_risks || []).length} key risks</div></div>
      ${ai.inherent_risk ? riskBadge(ai.inherent_risk).replace('risk</span>', 'inherent</span>') : ''}${icon('chevron', 'chev')}
    </summary>
    <div style="margin-top:14px">
      ${ai.warning ? `<div class="warning">${icon('alert')}<div>${esc(ai.warning)}</div></div>` : ''}
      <p class="summary">${esc(ai.summary)}${ai.risk_rationale ? `<br><span class="small muted">Risk drivers: ${esc(ai.risk_rationale)}</span>` : ''}</p>
      ${(ai.key_risks || []).length ? `<div class="risks">${ai.key_risks.map((k) => `<div class="risk-item"><strong>${icon('alert')}${esc(k.title)}</strong><p>${esc(k.description)}</p>
        <div class="chips">${(k.csf || []).map((c) => `<span class="chip ctrl" data-jump-sid="${esc(c)}" style="color:${FN_COLOR(c)}">${esc(c)}</span>`).join('')}</div></div>`).join('')}</div>` : ''}
      <div class="kv">
        <span>Platforms</span>
        <div class="chips">${r.technologies.map((t) => `<span class="chip">${esc(t)}<button data-rm-tech="${esc(t)}" title="Remove">${icon('x')}</button></span>`).join('')}
          <select class="select sm" id="add-tech" style="width:auto;height:28px;padding-top:3px;padding-bottom:3px"><option value="">+ Add platform</option>${allProviders.map((p) => `<option>${esc(p)}</option>`).join('')}</select></div>
        <span>Services</span>
        <div class="chips">${r.services.map((s) => `<span class="chip">${esc(s)}<button data-rm-svc="${esc(s)}" title="Remove">${icon('x')}</button></span>`).join('')}
          <input class="input sm" id="add-svc" placeholder="+ add service, Enter" style="width:150px;height:28px" /></div>
      </div>
      <p class="small muted" style="margin:10px 0 0">Platforms filter which Checkov checks appear under each NIST question; services boost matching checks.</p>
    </div></details>`;
  const card = box.querySelector('#li-ai-card');
  card.addEventListener('toggle', () => { ctx.ui.aiOpen = card.open; });
  const stack = async (body) => {
    try { const fresh = await api.patch(`/api/reviews/${r.id}`, body); state(ctx).checks = {}; ctx.set(fresh); } catch (e) { toast(e.message, 'err'); }
  };
  box.querySelectorAll('[data-rm-tech]').forEach((b) => b.addEventListener('click', () => stack({ technologies: r.technologies.filter((t) => t !== b.dataset.rmTech) })));
  box.querySelector('#add-tech').addEventListener('change', (e) => e.target.value && stack({ technologies: [...r.technologies, e.target.value] }));
  box.querySelectorAll('[data-rm-svc]').forEach((b) => b.addEventListener('click', () => stack({ services: r.services.filter((t) => t !== b.dataset.rmSvc) })));
  box.querySelector('#add-svc').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target.value.trim()) stack({ services: [...r.services, e.target.value.trim().toLowerCase()] });
  });
  box.querySelectorAll('[data-jump-sid]').forEach((c) => c.addEventListener('click', () => {
    const it = ctx.r.items.find((i) => i.subcategory_id === c.dataset.jumpSid);
    if (it) jumpTo(ctx, it.id); else toast(`${c.dataset.jumpSid} is not in this review — add it from “Add line”`, 'warn');
  }));
}

// =================================================================== toolbar
function renderToolbar(el, ctx) {
  const S = state(ctx);
  const items = ctx.r.items;
  const count = (f) => items.filter((i) => visible({ ...S, filter: f, q: '', fn: 'all' }, i)).length;
  el.querySelector('#li-filters').innerHTML = FILTERS.map((f) => `<button class="filt ${S.filter === f.id ? 'on' : ''}" data-f="${f.id}" id="filt-${f.id}" ${f.c ? `style="--c:${f.c}"` : ''}>${f.c ? '<i></i>' : ''}${f.label}<span class="n">${count(f.id)}</span></button>`).join('');
  const fns = {};
  items.forEach((i) => { if (i.subcategory) fns[i.subcategory.function_id] = (fns[i.subcategory.function_id] || 0) + 1; });
  el.querySelector('#li-fn').innerHTML = `<option value="all">All functions</option>` +
    ctx.meta.functions.filter((f) => fns[f.id]).map((f) => `<option value="${f.id}" ${S.fn === f.id ? 'selected' : ''}>${f.framework && f.framework !== 'csf' ? `${esc(fwShort(ctx, f.framework))} · ` : ''}${esc(f.title)} (${fns[f.id]})</option>`).join('');
  renderAnswered(el, ctx);
}

function renderAnswered(el, ctx) {
  const p = ctx.r.progress || { total: 0, answered: 0 };
  const box = el.querySelector('#li-answered');
  if (!box) return;
  const left = p.total - p.answered;
  box.innerHTML = `<span><b>${p.answered}</b> of <b>${p.total}</b> answered</span>
    <div class="progress"><i style="width:${p.total ? (p.answered / p.total) * 100 : 0}%"></i></div>
    ${left ? `<button class="btn sm ghost" id="li-next">${icon('next')} Next unanswered (${left}) <kbd>N</kbd></button>` : `<span style="color:var(--ok)">${icon('check')} All answered</span>`}`;
  box.querySelector('#li-next')?.addEventListener('click', () => nextUnanswered(ctx));
}

// =================================================================== list
function renderList(el, ctx) {
  const S = state(ctx);
  const list = el.querySelector('#li-list');
  const items = ctx.r.items;
  if (!items.length) {
    list.innerHTML = `<div class="empty"><div class="ic">${icon('list')}</div><h3>No line items yet</h3><p>Run AI scoping, or add a question, risk or recommendation.</p></div>`;
    return;
  }
  const shown = items.filter((i) => visible(S, i));
  if (!shown.length) { list.innerHTML = '<div class="empty" style="padding:30px"><p>No line items match these filters.</p></div>'; return; }
  let html = '';
  let group = null;
  // Requirements are ordered framework → function (CSF first); badge the framework once several are in play.
  const multiFw = new Set(items.filter((x) => x.subcategory).map((x) => fwOf(ctx, x))).size > 1;
  for (const i of shown) {
    const g = i.subcategory_id ? i.subcategory.function_id : 'custom';
    if (g !== group) {
      group = g;
      const inGroup = items.filter((x) => (x.subcategory_id ? x.subcategory.function_id : 'custom') === g);
      const done = inGroup.filter((x) => x.answered).length;
      const fw = g === 'custom' ? 'csf' : fwOf(ctx, i);
      const badge = fw !== 'csf' || multiFw ? `<span class="badge" style="margin-right:8px">${esc(fwShort(ctx, fw))}</span>` : '';
      html += g === 'custom'
        ? `<div class="fn-group-head" style="--c:var(--accent)">Custom questions, risks &amp; recommendations <span class="muted" style="margin-left:auto;font-weight:600">${done}/${inGroup.length}</span></div>`
        : `<div class="fn-group-head" style="--c:${fnColor(ctx, g)}">${badge}${esc(i.subcategory.function_title)}${fw === 'csf' ? ` · ${g}` : ''} <span class="muted" style="margin-left:auto;font-weight:600">${done}/${inGroup.length}</span></div>`;
    }
    html += rowHTML(ctx, i);
  }
  list.innerHTML = html;
  S.open.forEach((id) => { const a = list.querySelector(`#li-${id}`); if (a) afterOpen(el, ctx, a); });
}

const findItem = (ctx, id) => ctx.r.items.find((i) => i.id === id);

function rowHTML(ctx, i) {
  const S = state(ctx);
  const open = S.open.has(i.id);
  return `<article class="li k-${i.kind} ${open ? 'open' : ''}" id="li-${i.id}" data-id="${i.id}">
    <header class="li-head">${headInner(ctx, i)}</header>
    <div class="li-body">${open ? bodyHTML(ctx, i) : ''}</div>
  </article>`;
}

function headInner(ctx, i) {
  const S = state(ctx);
  const s = i.subcategory;
  const title = i.display_title || (i.risk || i.recommendation || '').slice(0, 160);
  const cat = s
    ? `${esc(s.category_title)}${i.priority === 'high' ? ' · <span style="color:#fdba74">High priority</span>' : ''}`
    : `<span style="color:${KIND[i.kind].color}">${KIND[i.kind].label}</span>${SRC[i.source] ? ` · ${SRC[i.source]}` : ''}${i.priority === 'high' ? ' · <span style="color:#fdba74">High priority</span>' : ''}`;
  const tags = [];
  if (i.kind === 'question' && i.status !== 'open') tags.push(`<span class="req-state ${i.status}">${REQ[i.status].label}</span>`);
  if (i.is_risk) tags.push(i.risk_rating ? `<span class="pill r-${i.risk_rating}">${icon('flag')}${cap(i.risk_rating)}</span>` : `<span class="pill risk">${icon('flag')}Risk</span>`);
  if (i.is_recommendation) tags.push(`<span class="pill rec" title="Recommendation · ${esc(cap(i.rec_status || 'proposed'))}">${icon('bulb')}${esc(cap(i.rec_status || 'proposed'))}</span>`);
  if (i.mitigation_ids.length) tags.push(`<span class="pill ctl" title="${i.mitigation_ids.length} mitigating control(s)">${icon('shield')}${i.mitigation_ids.length}</span>`);
  else if (needsControl(i)) {
    const sg = S.sugg[i.id]?.controls?.[0];
    tags.push(sg ? `<span class="pill sug" data-sug title="${esc(sg.reason || '')}">${icon('sparkles')}${esc(sg.title.length > 28 ? sg.title.slice(0, 27) + '…' : sg.title)}</span>` : '<span class="pill need">Needs control</span>');
  }
  return `<span class="ans ${i.answered ? 'done' : 'todo'}" title="${i.answered ? 'Answered' : 'Not answered yet'}">${i.answered ? icon('check') : ''}</span>
    <span class="lbl">${esc(i.label)}</span>
    <div class="txt"><div class="cat">${cat}</div><div class="out ${title ? '' : 'placeholder'}">${esc(title || `Untitled ${KIND[i.kind].label.toLowerCase()}`)}</div></div>
    <div class="tags">${tags.join('')}</div>${icon('chevron', 'chev')}`;
}

function updateHead(el, ctx, id) {
  const a = el.querySelector(`#li-${id}`);
  const i = findItem(ctx, id);
  if (!a || !i) return;
  const wasDone = a.querySelector('.ans')?.classList.contains('done');
  a.querySelector('.li-head').innerHTML = headInner(ctx, i);
  a.className = `li k-${i.kind} ${state(ctx).open.has(id) ? 'open' : ''}`;
  if (!wasDone && i.answered) a.querySelector('.ans').classList.add('pop');
}

// =================================================================== body
function bodyHTML(ctx, i) {
  const S = state(ctx);
  const s = i.subcategory;
  const custom = !i.subcategory_id;
  const id = i.id;
  const parts = [];
  parts.push(`<div class="row wrap" style="margin-bottom:12px">
    ${i.kind === 'question' ? `<div class="seg status" data-role="status">${Object.entries(REQ).map(([k, v]) => `<button data-v="${k}" class="${i.status === k ? 'on' : ''}" id="st-${id}-${k}">${v.label}</button>`).join('')}</div>` : ''}
    <div class="flags">
      ${i.kind !== 'risk' ? `<button class="flag f-risk ${i.is_risk ? 'on' : ''}" data-flag="is_risk" id="fr-${id}" title="Record this as a risk">${icon('flag')} Risk</button>` : ''}
      ${i.kind !== 'recommendation' ? `<button class="flag f-rec ${i.is_recommendation ? 'on' : ''}" data-flag="is_recommendation" id="fc-${id}" title="Add a recommendation">${icon('bulb')} Recommendation</button>` : ''}
    </div>
    <span class="spacer"></span><span class="saved" data-saved></span>
    <select class="select sm" data-role="priority" style="width:130px" aria-label="Priority">${['high', 'medium', 'low'].map((p) => `<option value="${p}" ${i.priority === p ? 'selected' : ''}>${cap(p)} priority</option>`).join('')}</select>
    <button class="btn sm ghost danger" data-role="delete" title="${custom ? 'Delete' : 'Remove from review'}" id="del-${id}">${icon('trash')}</button>
  </div>`);
  if (custom) {
    parts.push(`<div class="field" style="margin-bottom:12px"><div class="field-label">${icon(KIND[i.kind].icon)} ${KIND[i.kind].label}</div>
      ${aiField({ id: `t-${id}`, field: 'title', value: i.title, input: true, placeholder: i.kind === 'question' ? 'What do you need to ask the team?' : i.kind === 'risk' ? 'Short risk title' : 'Short recommendation title' })}</div>`);
    if (i.rationale) parts.push(`<div class="rationale">${icon('info')}<div>${esc(i.rationale)}${['code', 'threat'].includes(i.source) ? ` <button class="btn sm ghost" data-role="open-tm" title="Open the linked threat models">${icon('target')} Threat model</button>` : ''}</div></div>`);
  } else {
    parts.push(`<div class="question"><div class="lbl">NIST CSF 2.0 outcome · ${esc(i.subcategory_id)}</div><p>${esc(s.text)}</p></div>`);
    if (i.rationale) parts.push(`<div class="rationale">${icon('sparkles')}<div><b style="color:var(--text)">Why it's in scope:</b> ${esc(i.rationale)} <span class="badge ${i.source === 'ai' ? 'ai' : ''}" style="height:18px;font-size:10px;margin-left:4px">${esc(i.source)}</span></div></div>`);
    if (s.examples?.length) parts.push(`<details class="ex" style="margin-bottom:12px"><summary>${icon('info')} NIST implementation examples (${s.examples.length})</summary><ul class="examples">${s.examples.map((e) => `<li>${esc(e)}</li>`).join('')}</ul></details>`);
  }
  if (i.kind === 'question') {
    parts.push(`<div class="field"><div class="field-label">${icon('message')} Answer <span class="muted" style="font-weight:500">— project team response</span></div>
      ${aiField({ id: `a-${id}`, field: 'answer', value: i.answer, rows: 3, placeholder: 'How does the solution meet this? Reference designs, evidence, tickets… then ✨ to improve wording.' })}</div>`);
  }
  if (i.is_risk) parts.push(riskHTML(ctx, i));
  if (i.is_recommendation) parts.push(recHTML(i));
  parts.push(controlsHTML(ctx, i));
  parts.push(`<div class="field" style="margin-top:14px"><div class="field-label">${icon('edit')} Reviewer notes</div>
    ${aiField({ id: `n-${id}`, field: 'notes', value: i.notes, rows: 2, placeholder: 'Findings, conditions of approval, follow-ups…' })}</div>`);
  if (s) {
    parts.push(`<details class="ex" style="margin-top:14px" data-role="nist"><summary>${icon('shield')} SP 800-53 controls (${s.controls.length}) &amp; Checkov checks</summary>
      <div class="chips" style="margin:10px 0 4px">${s.controls.map((c) => `<span class="chip ctrl" data-ctrl="${esc(c.id)}" title="${esc(c.title)}">${esc(c.id)} <span style="font-family:var(--font);color:var(--muted)">${esc(c.title)}</span></span>`).join('')}</div>
      <div class="checks" data-role="checks"></div></details>`);
  }
  return parts.join('');
}

function riskHTML(ctx, i) {
  const v = ctx.meta.profile;
  const L = v.likelihood.find((x) => x.id === i.likelihood);
  const I = v.impact.find((x) => x.id === i.impact);
  let grid = '';
  for (let l = 5; l >= 1; l--) {
    grid += `<span class="ax" title="${esc(v.likelihood[l - 1].label)}">${l}</span>`;
    for (let im = 1; im <= 5; im++) {
      const on = L?.n === l && I?.n === im;
      grid += `<span class="cell ${rateOf(l, im)} ${on ? 'on' : ''}" data-l="${v.likelihood[l - 1].id}" data-i="${v.impact[im - 1].id}" title="${esc(v.likelihood[l - 1].label)} × ${esc(v.impact[im - 1].label)} = ${cap(rateOf(l, im))}"></span>`;
    }
  }
  grid += '<span></span>' + [1, 2, 3, 4, 5].map((n) => `<span class="ax">${n}</span>`).join('');
  return `<div class="sp k-risk" data-role="risk"><div class="sp-head">${icon('flag')} Risk ${i.risk_rating ? `<span class="pill r-${i.risk_rating}" style="text-transform:none;letter-spacing:0">${cap(i.risk_rating)}</span>` : ''}
      <span class="spacer"></span>${i.kind !== 'risk' ? '' : ''}</div>
    <div class="risk-grid">
      <div class="stack" style="gap:12px;min-width:0">
        <div><div class="field-label">Risk statement</div>${aiField({ id: `r-${i.id}`, field: 'risk', value: i.risk, rows: 3, placeholder: 'There is a risk that <event> caused by <cause>, resulting in <consequence>.' })}</div>
        <div><div class="field-label">Impact</div>${aiField({ id: `im-${i.id}`, field: 'impact_description', value: i.impact_description, rows: 2, placeholder: 'Business impact if realised — data, customers, regulatory, operations.' })}</div>
        <div class="row wrap"><span class="field-label" style="margin:0">Treatment</span><div class="seg" data-role="treatment">${v.treatments.map((t) => `<button data-v="${t.id}" class="${i.treatment === t.id ? 'on' : ''}" id="tr-${i.id}-${t.id}">${esc(t.label)}</button>`).join('')}</div></div>
      </div>
      <div class="heat-wrap"><div class="field-label" style="margin:0">Likelihood × impact</div>
        <div class="heat" role="grid" aria-label="Risk matrix">${grid}</div>
        <div class="heat-cap"><span>↑ likelihood · impact →</span></div>
        <div class="small" style="color:var(--text-2)">${L ? esc(L.label) : '—'} × ${I ? esc(I.label) : '—'}</div>
      </div>
    </div></div>`;
}

function recHTML(i) {
  return `<div class="sp k-recommendation" data-role="rec"><div class="sp-head">${icon('bulb')} Recommendation</div>
    ${aiField({ id: `rc-${i.id}`, field: 'recommendation', value: i.recommendation, rows: 2, placeholder: 'Imperative, specific and testable — e.g. “Enforce MFA for all administrative access before go-live.”' })}
    <div class="row wrap" style="margin-top:10px"><span class="field-label" style="margin:0">Status</span>
      <div class="seg" data-role="rec_status">${['proposed', 'agreed', 'implemented', 'declined'].map((s) => `<button data-v="${s}" class="${(i.rec_status || 'proposed') === s ? 'on' : ''}" id="rs-${i.id}-${s}">${cap(s)}</button>`).join('')}</div></div>
  </div>`;
}

function controlsHTML(ctx, i) {
  const S = state(ctx);
  const mits = ctx.r.mitigations.filter((m) => i.mitigation_ids.includes(m.id));
  return `<div class="sp k-control" data-role="controls"><div class="sp-head">${icon('shield')} Mitigating controls
      <span class="spacer"></span>
      <button class="btn sm ghost" data-role="ai-sugg" id="ais-${i.id}" style="text-transform:none;letter-spacing:0" title="Ask AI to pick controls (reusing existing ones first), a recommendation and a rating">${icon('sparkles')} AI suggest</button></div>
    <div class="ctl-chips">${mits.map((m) => `<span class="ctl-chip" data-mid="${m.id}" title="${esc(m.description || m.title)}">
        <span class="st ${m.state === 'existing' ? 'existing' : ''}" title="${m.state === 'existing' ? 'Existing control' : 'New control'}"></span><span class="t">${esc(m.title)}</span>
        ${m.item_ids.length > 1 ? `<span class="u" title="Also closes ${m.item_ids.length - 1} other line item(s)">+${m.item_ids.length - 1}</span>` : ''}
        <button data-unlink="${m.id}" title="Unlink from this item">${icon('x')}</button></span>`).join('') || '<span class="small muted">No controls linked yet — reuse one below or add a new one.</span>'}</div>
    <div class="row wrap" style="margin-top:10px">
      <button class="btn sm" data-role="link-existing" id="le-${i.id}">${icon('link')} Link existing…</button>
      <button class="btn sm" data-role="new-ctl" id="nc-${i.id}">${icon('plus')} New control</button>
    </div>
    <div data-role="new-form">${S.newForm.has(i.id) ? newFormHTML(i) : ''}</div>
    <div data-role="sugg">${suggHTML(ctx, i)}</div>
  </div>`;
}

function newFormHTML(i) {
  return `<div class="inline-form">
    <div class="grid-2" style="gap:10px;grid-template-columns:1fr auto">
      <input class="input sm" data-nc="title" placeholder="Control title, e.g. “WAF with OWASP managed rules”" id="nct-${i.id}" />
      <div class="seg" data-nc="state"><button type="button" data-v="new" class="on">New</button><button type="button" data-v="existing">Existing</button></div>
    </div>
    ${aiField({ id: `ncd-${i.id}`, field: 'nc-desc', aiField: 'mitigation_description', rows: 2, placeholder: 'What is implemented, where, who operates it, how it is evidenced… (✨ to draft)' })}
    <div class="row"><input class="input sm" data-nc="owner" placeholder="Owner (optional)" style="max-width:220px" /><span class="spacer"></span>
      <button class="btn sm ghost" data-role="new-cancel">Cancel</button><button class="btn sm primary" data-role="new-create" id="ncc-${i.id}">${icon('check')} Create &amp; link</button></div>
  </div>`;
}

function suggHTML(ctx, i) {
  const S = state(ctx);
  const s = S.ai[i.id] || S.det[i.id];
  if (!s) return `<div class="loading" style="padding:10px 0 0"><span class="spin"></span>Finding suggested controls…</div>`;
  const linked = new Set(i.mitigation_ids);
  const linkedRefs = new Set(ctx.r.mitigations.filter((m) => linked.has(m.id)).map((m) => m.library_ref).filter(Boolean));
  const ex = (s.existing || []).filter((e) => !linked.has(e.mitigation_id));
  const lib = (s.library || []).filter((l) => !linkedRefs.has(l.library_id));
  const nw = (s.new || []);
  const rows = [
    ...ex.map((e) => `<div class="sugg-row reuse"><span class="ic">${icon('link')}</span><div style="min-width:0"><div class="t">${esc(e.title)}</div>
      <div class="w">Reuse${e.shared ? ` · already closes ${e.shared} item${e.shared === 1 ? '' : 's'}` : ''} · ${esc(e.reason || '')}</div></div>
      <button class="btn sm" data-sg-mid="${e.mitigation_id}">${icon('link')} Link</button></div>`),
    ...lib.map((l) => {
      const inReg = ctx.r.mitigations.find((m) => m.library_ref === l.library_id);
      return `<div class="sugg-row ${inReg ? 'reuse' : 'lib'}"><span class="ic">${icon(inReg ? 'link' : 'book')}</span><div style="min-width:0"><div class="t">${esc(l.title)}</div>
        <div class="w">${inReg ? 'In register · ' : 'Library · '}${esc(l.reason || (l.nist || []).join(', '))}</div></div>
        <button class="btn sm" data-sg-lib="${esc(l.library_id)}">${icon(inReg ? 'link' : 'plus')} ${inReg ? 'Link' : 'Add'}</button></div>`;
    }),
    ...nw.map((n, k) => `<div class="sugg-row new"><span class="ic">${icon('sparkles')}</span><div style="min-width:0"><div class="t">${esc(n.title)}</div>
      <div class="w" title="${esc(n.description)}">New (AI) · ${esc(n.description)}</div></div>
      <button class="btn sm" data-sg-new="${k}">${icon('plus')} Create</button></div>`),
  ];
  const apply = [];
  if (s.recommendation && s.recommendation.trim() !== (i.recommendation || '').trim()) {
    apply.push(`<div class="apply-row">${icon('bulb')}<div class="x">Suggested recommendation: <b>${esc(s.recommendation)}</b></div><button class="btn sm" data-apply="rec">Apply</button></div>`);
  }
  if (i.is_risk && s.likelihood && s.impact && (s.likelihood !== i.likelihood || s.impact !== i.impact)) {
    const v = ctx.meta.profile;
    const L = v.likelihood.find((x) => x.id === s.likelihood); const I = v.impact.find((x) => x.id === s.impact);
    apply.push(`<div class="apply-row">${icon('target')}<div class="x">Suggested rating: <b>${esc(L?.label)} × ${esc(I?.label)}</b> → ${cap(rateOf(L?.n || 3, I?.n || 3))}</div><button class="btn sm" data-apply="rating">Apply</button></div>`);
  }
  if (i.is_risk && s.impact_description && !(i.impact_description || '').trim()) {
    apply.push(`<div class="apply-row">${icon('alert')}<div class="x">Suggested impact: <b>${esc(s.impact_description)}</b></div><button class="btn sm" data-apply="impact">Apply</button></div>`);
  }
  if (!rows.length && !apply.length) return s.source === 'ai' ? '<div class="small muted" style="margin-top:10px">AI has no further suggestions for this item.</div>' : '';
  return `<div class="sugg"><div class="sugg-head">${icon('sparkles')} ${s.source === 'ai' ? `AI suggestions · ${esc(s.provider)}${s.cached ? ' · cached' : ''}` : 'Suggested — reuse existing controls first (deterministic)'}</div>
    ${s.rationale ? `<div class="small muted" style="margin:-2px 0 4px">${esc(s.rationale)}</div>` : ''}
    ${rows.join('')}${apply.join('')}</div>`;
}

// =================================================================== open / close
function toggle(el, ctx, art) {
  const S = state(ctx);
  const id = +art.dataset.id;
  if (S.open.has(id)) {
    flush(el, ctx, id);
    S.open.delete(id); art.classList.remove('open'); art.querySelector('.li-body').innerHTML = '';
  } else {
    S.open.add(id); art.classList.add('open'); art.querySelector('.li-body').innerHTML = bodyHTML(ctx, findItem(ctx, id)); afterOpen(el, ctx, art);
  }
}

function rerenderBody(el, ctx, id) {
  const art = el.querySelector(`#li-${id}`);
  if (!art || !state(ctx).open.has(id)) { updateHead(el, ctx, id); return; }
  updateHead(el, ctx, id);
  art.querySelector('.li-body').innerHTML = bodyHTML(ctx, findItem(ctx, id));
  afterOpen(el, ctx, art);
}

function afterOpen(el, ctx, art) {
  const S = state(ctx);
  const id = +art.dataset.id;
  if (!S.det[id] && !S.ai[id]) {
    api.get(`/api/reviews/${ctx.r.id}/items/${id}/suggestions`).then((s) => {
      S.det[id] = s;
      const box = el.querySelector(`#li-${id} [data-role="sugg"]`);
      if (box) box.innerHTML = suggHTML(ctx, findItem(ctx, id));
    }).catch(() => { S.det[id] = { existing: [], library: [], new: [] }; });
  }
}

// =================================================================== saving
function setSaved(el, id, txt, ok = false) {
  const s = el.querySelector(`#li-${id} [data-saved]`);
  if (!s) return;
  s.textContent = txt; s.classList.toggle('ok', ok);
  if (ok) setTimeout(() => { if (s.textContent === txt) s.textContent = ''; }, 1500);
}

function queueSave(el, ctx, id, field, value) {
  const S = state(ctx);
  (S.pending[id] ||= {})[field] = value;
  clearTimeout(S.timers[id]);
  setSaved(el, id, 'Saving…');
  S.timers[id] = setTimeout(() => flush(el, ctx, id), 700);
}

/** Send pending text edits (plus extra fields) for an item; updates counts without re-rendering. */
async function flush(el, ctx, id, extra = {}) {
  const S = state(ctx);
  clearTimeout(S.timers[id]);
  const body = { ...(S.pending[id] || {}), ...extra };
  delete S.pending[id];
  if (!Object.keys(body).length) return findItem(ctx, id);
  try {
    const res = await api.patch(`/api/reviews/${ctx.r.id}/items/${id}`, body);
    const idx = ctx.r.items.findIndex((x) => x.id === id);
    if (idx >= 0) ctx.r.items[idx] = res.item;
    ctx.progress(res.progress);
    renderAnswered(el, ctx);
    updateHead(el, ctx, id);
    setSaved(el, id, 'Saved', true);
    return res.item;
  } catch (e) { toast(e.message, 'err'); setSaved(el, id, ''); return null; }
}

// =================================================================== events
async function onListClick(e, el, ctx) {
  const S = state(ctx);
  const art = e.target.closest('.li');
  if (!art) return;
  const id = +art.dataset.id;
  const item = findItem(ctx, id);
  const t = e.target;

  if (t.closest('.pill.sug')) {
    e.stopPropagation();
    if (!S.open.has(id)) toggle(el, ctx, art);
    art.querySelector('[data-role="controls"]')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    return;
  }
  if (t.closest('.li-head')) { toggle(el, ctx, art); return; }

  const statusBtn = t.closest('[data-role="status"] button');
  if (statusBtn) { await flush(el, ctx, id, { status: statusBtn.dataset.v }); rerenderBody(el, ctx, id); return; }

  const flag = t.closest('[data-flag]');
  if (flag) {
    const k = flag.dataset.flag;
    await flush(el, ctx, id, { [k]: !item[k] });
    rerenderBody(el, ctx, id);
    if (!item[k]) setTimeout(() => el.querySelector(`#li-${id} [data-role="${k === 'is_risk' ? 'risk' : 'rec'}"] textarea`)?.focus(), 30);
    return;
  }
  const tr = t.closest('[data-role="treatment"] button');
  if (tr) { await flush(el, ctx, id, { treatment: item.treatment === tr.dataset.v ? '' : tr.dataset.v }); rerenderBody(el, ctx, id); return; }
  const rs = t.closest('[data-role="rec_status"] button');
  if (rs) { await flush(el, ctx, id, { rec_status: rs.dataset.v }); rerenderBody(el, ctx, id); return; }
  const cell = t.closest('.heat .cell');
  if (cell) { await flush(el, ctx, id, { likelihood: cell.dataset.l, impact: cell.dataset.i }); rerenderBody(el, ctx, id); return; }

  if (t.closest('[data-role="delete"]')) {
    const custom = !item.subcategory_id;
    if (!(await confirmDialog(custom ? `Delete ${item.label}?` : `Remove ${item.label}?`, custom ? 'The line item and its answers are deleted. Linked controls stay in the register.' : 'The NIST question and its answer are removed from this review.', custom ? 'Delete' : 'Remove'))) return;
    try {
      await api.del(`/api/reviews/${ctx.r.id}/items/${id}`);
      S.open.delete(id);
      await ctx.refresh();
      toast(`${item.label} removed`);
    } catch (err) { toast(err.message, 'err'); }
    return;
  }

  const unlink = t.closest('[data-unlink]');
  if (unlink) {
    e.stopPropagation();
    try { ctx.set(await api.del(`/api/reviews/${ctx.r.id}/items/${id}/mitigations/${unlink.dataset.unlink}`)); } catch (err) { toast(err.message, 'err'); }
    return;
  }
  const chip = t.closest('.ctl-chip');
  if (chip) { await flush(el, ctx, id); ctx.jumpToControl(+chip.dataset.mid); return; }

  if (t.closest('[data-role="link-existing"]')) { await flush(el, ctx, id); openLinkPicker(ctx, id); return; }
  if (t.closest('[data-role="open-tm"]')) { await flush(el, ctx, id); ctx.switchTab('threats'); return; }
  if (t.closest('[data-role="new-ctl"]')) {
    if (S.newForm.has(id)) S.newForm.delete(id); else S.newForm.add(id);
    const box = art.querySelector('[data-role="new-form"]');
    box.innerHTML = S.newForm.has(id) ? newFormHTML(item) : '';
    box.querySelector('[data-nc="title"]')?.focus();
    return;
  }
  const ncSeg = t.closest('[data-nc="state"] button');
  if (ncSeg) { ncSeg.parentElement.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b === ncSeg)); return; }
  if (t.closest('[data-role="new-cancel"]')) { S.newForm.delete(id); art.querySelector('[data-role="new-form"]').innerHTML = ''; return; }
  if (t.closest('[data-role="new-create"]')) {
    const f = art.querySelector('.inline-form');
    const title = f.querySelector('[data-nc="title"]').value.trim();
    if (title.length < 2) { toast('Give the control a title', 'warn'); f.querySelector('[data-nc="title"]').focus(); return; }
    const body = { title, description: f.querySelector('[data-field="nc-desc"]').value, owner: f.querySelector('[data-nc="owner"]').value, state: f.querySelector('[data-nc="state"] .on').dataset.v };
    await linkAndSet(el, ctx, id, { new: body }, `“${title}” created and linked`);
    S.newForm.delete(id);
    return;
  }

  const sgMid = t.closest('[data-sg-mid]');
  if (sgMid) { await linkAndSet(el, ctx, id, { mitigation_id: +sgMid.dataset.sgMid }, 'Existing control linked — one control, many items'); return; }
  const sgLib = t.closest('[data-sg-lib]');
  if (sgLib) { await linkAndSet(el, ctx, id, { library_id: sgLib.dataset.sgLib }, 'Control linked'); return; }
  const sgNew = t.closest('[data-sg-new]');
  if (sgNew) {
    const n = (S.ai[id]?.new || [])[+sgNew.dataset.sgNew];
    if (n) {
      await linkAndSet(el, ctx, id, { new: { title: n.title, description: n.description, nist: n.nist, source: 'ai' } }, `“${n.title}” created and linked`);
      S.ai[id].new = S.ai[id].new.filter((x) => x !== n);
    }
    return;
  }
  const ap = t.closest('[data-apply]');
  if (ap) {
    const s = S.ai[id] || S.det[id];
    const body = ap.dataset.apply === 'rec' ? { is_recommendation: true, recommendation: s.recommendation }
      : ap.dataset.apply === 'rating' ? { is_risk: true, likelihood: s.likelihood, impact: s.impact }
        : { impact_description: s.impact_description };
    await flush(el, ctx, id, body);
    rerenderBody(el, ctx, id);
    toast('Applied');
    return;
  }
  const aiS = t.closest('[data-role="ai-sugg"]');
  if (aiS) {
    await flush(el, ctx, id);
    aiS.disabled = true; aiS.innerHTML = '<span class="spin"></span> Thinking…';
    try {
      S.ai[id] = await api.get(`/api/reviews/${ctx.r.id}/items/${id}/suggestions?ai=true`);
      if (S.ai[id].warning) toast(S.ai[id].warning, 'warn', 6000);
    } catch (err) { toast(err.message, 'err'); }
    const box = el.querySelector(`#li-${id} [data-role="sugg"]`);
    if (box) box.innerHTML = suggHTML(ctx, findItem(ctx, id));
    aiS.disabled = false; aiS.innerHTML = `${icon('sparkles')} AI suggest`;
    return;
  }

  const ctrl = t.closest('[data-ctrl]');
  if (ctrl) { openControlDrawer(ctrl.dataset.ctrl); return; }
  if (t.closest('[data-role="nist"] > summary')) {
    setTimeout(() => { const d = art.querySelector('[data-role="nist"]'); if (d?.open) loadChecks(el, ctx, art, item.subcategory_id); }, 0);
    return;
  }
  const cs = t.closest('.check-row .cstat button');
  if (cs) { setCheck(el, ctx, cs); }
}

function onListChange(e, el, ctx) {
  const art = e.target.closest('.li');
  if (!art) return;
  if (e.target.matches('[data-role="priority"]')) flush(el, ctx, +art.dataset.id, { priority: e.target.value });
}

async function linkAndSet(el, ctx, id, body, msg) {
  await flush(el, ctx, id);
  try {
    const res = await api.post(`/api/reviews/${ctx.r.id}/items/${id}/mitigations`, body);
    ctx.set(res.review);
    toast(msg);
    flashRow(ctx, id);
  } catch (err) { toast(err.message, 'err'); }
}

function flashRow(ctx, id) {
  const a = ctx.root.querySelector(`#li-${id}`);
  if (a) { a.classList.remove('flash'); void a.offsetWidth; a.classList.add('flash'); }
}

// =================================================================== link existing picker
async function openLinkPicker(ctx, itemId) {
  let review = ctx.r;
  let changed = false;
  let q = '';
  let org = { org: [], library: [] };
  const { el, close } = openOverlay(`
    <div class="drawer-head"><div style="flex:1"><h2>Link a mitigating control</h2>
      <p class="small muted" style="margin:4px 0 0">One control can close many questions, risks and recommendations. Reuse first, then org-wide, then the library.</p></div>
      <button class="btn ghost icon" data-close id="lp-close">${icon('x')}</button></div>
    <div style="padding:14px 24px 0"><div class="search">${icon('search')}<input class="input" id="lp-q" placeholder="Search controls…" autofocus /></div></div>
    <div class="drawer-body" id="lp-list"></div>
    <div class="drawer-body row" style="flex:0;justify-content:flex-end;border-top:1px solid var(--border);padding:12px 24px"><button class="btn primary" data-close id="lp-done">Done</button></div>`,
  { modal: true, onClose: () => { if (changed) ctx.set(review); } });
  el.style.maxHeight = '84vh';
  const draw = () => {
    const it = review.items.find((x) => x.id === itemId);
    const linked = new Set(it.mitigation_ids);
    const ql = q.toLowerCase();
    const match = (o) => !ql || `${o.title} ${o.description}`.toLowerCase().includes(ql);
    const reg = review.mitigations.filter(match);
    const refs = new Set(review.mitigations.map((m) => m.library_ref).filter(Boolean));
    const titles = new Set(review.mitigations.map((m) => m.title.trim().toLowerCase()));
    const orgL = org.org.filter((o) => !(o.library_ref && refs.has(o.library_ref)) && !titles.has(o.title.trim().toLowerCase()));
    const lib = org.library.filter((l) => !refs.has(l.library_id));
    const row = (attr, on, title, sub, right = '') => `<div class="pick-item ${on ? 'on' : ''}" ${attr}><span class="cb">${icon('check')}</span>
      <div style="min-width:0"><div class="t">${esc(title)}</div><div class="w">${sub}</div></div>${right}</div>`;
    el.querySelector('#lp-list').innerHTML = `
      <div class="pick-sec">This review's register (${reg.length})</div>
      <div class="pick-list">${reg.map((m) => row(`data-reg="${m.id}"`, linked.has(m.id), m.title,
        `${m.state === 'existing' ? 'Existing' : 'New'} · ${esc(cap(m.status))} · closes ${m.item_ids.length} item${m.item_ids.length === 1 ? '' : 's'}`,
        m.item_ids.length ? `<span class="pill ctl">${m.item_ids.length}</span>` : '')).join('') || '<p class="small muted">No controls in this review yet.</p>'}</div>
      ${orgL.length ? `<div class="pick-sec">Used in other reviews (${orgL.length})</div><div class="pick-list">${orgL.map((o, k) => row(`data-org="${k}"`, false, o.title,
        `${esc(cap(o.state))} · used ${o.count}× · ${o.reviews.slice(0, 3).map((r) => esc(r.ref)).join(', ')}`)).join('')}</div>` : ''}
      <div class="pick-sec">Control library (${lib.length})</div>
      <div class="pick-list">${lib.slice(0, 60).map((l) => row(`data-lib="${esc(l.library_id)}"`, false, l.title, `${esc(l.library_id)} · ${esc((l.nist || []).join(', '))}`)).join('')}</div>`;
    el._org = orgL;
  };
  const load = async () => {
    try { org = await api.get(`/api/mitigations/org?q=${encodeURIComponent(q)}&exclude_review=${review.id}`); } catch { /* offline ok */ }
    draw();
  };
  draw();
  load();
  el.querySelector('#lp-q').addEventListener('input', debounce((e) => { q = e.target.value; load(); }, 220));
  el.querySelector('#lp-list').addEventListener('click', async (e) => {
    const p = e.target.closest('.pick-item'); if (!p || p.classList.contains('busy')) return;
    p.classList.add('busy');
    const base = `/api/reviews/${review.id}/items/${itemId}/mitigations`;
    try {
      if (p.dataset.reg) {
        const mid = +p.dataset.reg;
        const it = review.items.find((x) => x.id === itemId);
        review = it.mitigation_ids.includes(mid) ? await api.del(`${base}/${mid}`) : (await api.post(base, { mitigation_id: mid })).review;
      } else if (p.dataset.org) {
        const o = el._org[+p.dataset.org];
        const body = o.library_ref && org.library.some((l) => l.library_id === o.library_ref) ? { library_id: o.library_ref }
          : { new: { title: o.title, description: o.description, state: o.state, nist: o.nist, source: 'org' } };
        review = (await api.post(base, body)).review;
      } else if (p.dataset.lib) {
        review = (await api.post(base, { library_id: p.dataset.lib })).review;
      }
      changed = true;
      draw();
    } catch (err) { toast(err.message, 'err'); p.classList.remove('busy'); }
  });
  return close;
}

// =================================================================== checks (Checkov)
async function loadChecks(el, ctx, art, sid, force = false) {
  const S = state(ctx);
  const box = art.querySelector('[data-role="checks"]');
  if (!box) return;
  const o = (S.copts[sid] ||= { all: false, related: false, removed: false, q: '', shown: PAGE, add: null });
  const key = `${o.all}|${o.removed}|${o.q}`;
  if (force || !S.checks[sid] || S.checks[sid].key !== key) {
    box.innerHTML = '<div class="loading"><span class="spin"></span>Finding Checkov checks…</div>';
    try { S.checks[sid] = { key, ...(await api.get(`/api/reviews/${ctx.r.id}/requirements/${encodeURIComponent(sid)}/checks?q=${encodeURIComponent(o.q)}&all_platforms=${o.all}&include_removed=${o.removed}`)) }; } catch (e) { box.innerHTML = `<p class="muted small">${esc(e.message)}</p>`; return; }
  }
  drawChecks(el, ctx, art, sid);
}

function checksEmpty(data, o) {
  const map = `<a href="#/mappings" class="ck-link">${icon('link')} Manage mappings</a>`;
  if (data.policy === 'none') return `<div class="ck-empty">${icon('info')}<div><b>Organisational requirement — no IaC checks expected.</b> ${esc(data.why || 'This outcome is met through process, people or governance controls.')}<br>Pin a check with “Add check” if one is relevant here. ${map}</div></div>`;
  if (data.policy === 'unmapped') return `<div class="ck-empty">${icon('info')}<div><b>No automatic Checkov links for this requirement.</b> Add checks here or on the mappings page. ${map}</div></div>`;
  if (!o.all && data.hidden_by_provider) return `<div class="ck-empty">${icon('info')}<div><b>${data.hidden_by_provider} linked check${data.hidden_by_provider === 1 ? '' : 's'} exist for other platforms.</b> This review's platforms (${esc(data.providers.join(', '))}) have none — toggle “All platforms” to see them. ${map}</div></div>`;
  return `<div class="ck-empty">${icon('info')}<div>No Checkov checks match${o.q ? ' this search' : ''}. ${map}</div></div>`;
}

function drawChecks(el, ctx, art, sid) {
  const S = state(ctx);
  const box = art.querySelector('[data-role="checks"]');
  const o = S.copts[sid];
  const data = S.checks[sid];
  const all = data.checks;
  const list = o.related ? all : all.filter((k) => k.strength === 'strong' || k.source !== 'auto' || k.excluded || k.review_status !== 'applicable');
  const counts = {};
  all.forEach((k) => { counts[k.review_status] = (counts[k.review_status] || 0) + 1; });
  const tech = data.technologies || [];
  box.innerHTML = `
    <div class="checks-head">
      <h4>${icon('code')} Checkov checks <span class="badge">${list.length}${list.length !== all.length ? ` / ${all.length}` : ''}</span></h4>
      ${counts.fail ? `<span class="badge risk-critical">${counts.fail} fail</span>` : ''}${counts.pass ? `<span class="badge risk-low">${counts.pass} pass</span>` : ''}
      <span class="spacer"></span>
      <div class="search" style="width:190px">${icon('search')}<input class="input sm" data-c="q" placeholder="Search checks…" value="${esc(o.q)}" /></div>
      <label class="row small muted" style="gap:6px;cursor:pointer"><span class="switch" style="transform:scale(.85)"><input type="checkbox" data-c="related" ${o.related ? 'checked' : ''}/><span></span></span>Related</label>
      <label class="row small muted" style="gap:6px;cursor:pointer"><span class="switch" style="transform:scale(.85)"><input type="checkbox" data-c="all" ${o.all ? 'checked' : ''}/><span></span></span>All platforms</label>
      <button class="btn sm ${o.add ? 'primary' : ''}" data-c="add">${icon('plus')} Add check</button>
    </div>
    ${!o.all && data.provider_fallback ? `<div class="warning">${icon('info')}<div>${tech.length ? `This review's platforms (${esc(tech.join(', '))}) don't match any Checkov platform` : 'No platforms set on this review'} — showing checks for all platforms. Set platforms in the AI scoping panel to narrow the list.</div></div>` : ''}
    <div data-c="add-panel">${o.add ? addPanelHTML(ctx, o.add) : ''}</div>
    <div class="check-list">${list.slice(0, o.shown).map((k) => checkRow(k, { editable: !k.excluded, actions: true })).join('') || checksEmpty(data, o)}</div>
    <div class="row" style="margin-top:8px">
      ${list.length > o.shown ? `<button class="btn sm ghost" data-c="more">Show ${Math.min(PAGE * 2, list.length - o.shown)} more of ${list.length - o.shown}</button>` : ''}
      <span class="spacer"></span>
      ${data.removed || o.removed ? `<button class="btn sm ghost" data-c="removed">${o.removed ? 'Hide removed' : `Show ${data.removed} removed`}</button>` : ''}
    </div>`;
  box.querySelector('[data-c="q"]').addEventListener('input', debounce((e) => { o.q = e.target.value; o.shown = PAGE; loadChecks(el, ctx, art, sid); }, 300));
  box.querySelector('[data-c="related"]').addEventListener('change', (e) => { o.related = e.target.checked; o.shown = PAGE; drawChecks(el, ctx, art, sid); });
  box.querySelector('[data-c="all"]').addEventListener('change', (e) => { o.all = e.target.checked; o.shown = PAGE; loadChecks(el, ctx, art, sid); });
  box.querySelector('[data-c="more"]')?.addEventListener('click', () => { o.shown += PAGE * 2; drawChecks(el, ctx, art, sid); });
  box.querySelector('[data-c="removed"]')?.addEventListener('click', () => { o.removed = !o.removed; loadChecks(el, ctx, art, sid); });
  box.querySelector('[data-c="add"]').addEventListener('click', () => {
    o.add = o.add ? null : { q: '', prov: '', scope: 'review', offset: 0, res: null };
    drawChecks(el, ctx, art, sid);
    box.querySelector('[data-a="q"]')?.focus();
  });
  box.querySelector('[data-a="q"]')?.addEventListener('input', debounce((e) => { o.add.q = e.target.value; o.add.offset = 0; searchAdd(ctx, box, sid, o.add); }, 250));
  box.querySelector('[data-a="prov"]')?.addEventListener('change', (e) => { o.add.prov = e.target.value; o.add.offset = 0; searchAdd(ctx, box, sid, o.add); });
  box.onclick = (e) => onChecksClick(e, el, ctx, art, sid);
  if (o.add) searchAdd(ctx, box, sid, o.add);
}

// ------------------------------------------------------------------- add / remove checks on the fly
const ADD_PAGE = 8;

function addPanelHTML(ctx, a) {
  return `<div class="ck-add">
    <div class="row wrap">
      <div class="search" style="flex:1;min-width:200px">${icon('search')}<input class="input sm" data-a="q" placeholder="Search id, name, resource or 800-53 control…" value="${esc(a.q)}" /></div>
      <select class="select sm" data-a="prov" style="width:170px"><option value="">All platforms</option>${ctx.meta.providers.map((p) => `<option ${a.prov === p.name ? 'selected' : ''}>${esc(p.name)}</option>`).join('')}</select>
      <div class="seg" data-a="scope"><button data-v="review" class="${a.scope === 'review' ? 'on' : ''}">This review</button><button data-v="global" class="${a.scope === 'global' ? 'on' : ''}">All reviews</button></div>
    </div>
    <div data-a="res"><div class="loading"><span class="spin"></span>Searching…</div></div>
  </div>`;
}

async function searchAdd(ctx, box, sid, a) {
  const q = a.q.trim();
  const ctl = /^[A-Za-z]{2}-\d+(\(\d+\))?$/.test(q) ? q.toUpperCase() : '';
  const qs = new URLSearchParams({ q: ctl ? '' : q, control: ctl, provider: a.prov, offset: a.offset, limit: ADD_PAGE, requirement_id: sid, review_id: ctx.r.id });
  try { a.res = await api.get(`/api/mappings/checks?${qs}`); } catch (e) { toast(e.message, 'err'); return; }
  const res = box.querySelector('[data-a="res"]');
  if (!res) return;
  const r = a.res;
  res.innerHTML = `<div class="ck-add-list">${r.checks.map((k) => `<div class="ck-add-row">
      <span class="cid">${esc(k.id)}</span><div class="nm">${esc(k.name)} <span class="tag t-prov">${esc(k.provider)}</span></div>
      ${k.linked ? '<span class="tag strong">linked</span>' : `<button class="btn sm" data-a-add="${esc(k.id)}">${icon('plus')} Add</button>`}</div>`).join('') || '<p class="muted small">No checks match.</p>'}</div>
    ${r.total > ADD_PAGE ? `<div class="row small muted" style="margin-top:6px"><span>${r.offset + 1}–${Math.min(r.offset + ADD_PAGE, r.total)} of ${r.total}</span><span class="spacer"></span>
      <button class="btn sm ghost" data-a-page="-1" ${r.offset ? '' : 'disabled'}>Prev</button><button class="btn sm ghost" data-a-page="1" ${r.offset + ADD_PAGE < r.total ? '' : 'disabled'}>Next</button></div>` : ''}`;
}

async function onChecksClick(e, el, ctx, art, sid) {
  const S = state(ctx);
  const o = S.copts[sid];
  const t = e.target;
  const seg = t.closest('[data-a="scope"] button');
  if (seg) { o.add.scope = seg.dataset.v; seg.parentElement.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b === seg)); return; }
  const page = t.closest('[data-a-page]');
  if (page) { o.add.offset = Math.max(0, o.add.offset + +page.dataset.aPage * ADD_PAGE); searchAdd(ctx, art.querySelector('[data-role="checks"]'), sid, o.add); return; }
  const add = t.closest('[data-a-add]');
  if (add) {
    add.disabled = true;
    try {
      await includeCheckLink(sid, add.dataset.aAdd, o.add.scope, ctx.r.id);
      toast(`${add.dataset.aAdd} added ${o.add.scope === 'review' ? 'to this review' : 'for all reviews'}`);
      await loadChecks(el, ctx, art, sid, true);
    } catch (err) { toast(err.message, 'err'); add.disabled = false; }
    return;
  }
  const row = t.closest('.check-row');
  const cid = row?.dataset.check;
  const k = cid && S.checks[sid].checks.find((x) => x.id === cid);
  if (t.closest('[data-cl="remove"]')) {
    e.stopPropagation();
    const acts = row.querySelector('.ck-acts');
    if (acts.querySelector('.menu')) { acts.querySelector('.menu').remove(); return; }
    acts.insertAdjacentHTML('beforeend', `<div class="menu right ck-menu">
      <input class="input sm" data-rm-note placeholder="Reason (optional)" />
      <button data-rm="review">${icon('x')}<span>Remove for this review<small>Other reviews keep it</small></span></button>
      <button data-rm="global">${icon('trash')}<span>Remove for all reviews<small>Stops linking it to this requirement everywhere</small></span></button></div>`);
    acts.querySelector('[data-rm-note]').focus();
    return;
  }
  const rm = t.closest('[data-rm]');
  if (rm) {
    try {
      await removeCheckLink(sid, k, rm.dataset.rm, ctx.r.id, row.querySelector('[data-rm-note]')?.value || '');
      toast(`${cid} removed ${rm.dataset.rm === 'review' ? 'from this review' : 'for all reviews'}`);
      await loadChecks(el, ctx, art, sid, true);
    } catch (err) { toast(err.message, 'err'); }
    return;
  }
  if (t.closest('[data-cl="restore"]')) {
    if (k.excluded === 'global' && !(await confirmDialog(`Restore ${cid} for all reviews?`, 'It was removed from this requirement for every review. Restoring links it everywhere again.', 'Restore'))) return;
    try {
      await restoreCheckLink(sid, k, ctx.r.id);
      toast(`${cid} restored`);
      await loadChecks(el, ctx, art, sid, true);
    } catch (err) { toast(err.message, 'err'); }
  }
}

async function setCheck(el, ctx, b) {
  const S = state(ctx);
  const row = b.closest('.check-row');
  const g = b.closest('.cstat');
  const cid = row.dataset.check;
  try {
    await api.put(`/api/reviews/${ctx.r.id}/checks/${cid}`, { status: b.dataset.v, note: '' });
    Object.values(S.checks).forEach((c) => c.checks.forEach((k) => { if (k.id === cid) k.review_status = b.dataset.v; }));
    const r = ctx.r;
    const prev = r.check_states[cid]?.status;
    if (prev) r.check_counts[prev] = Math.max(0, (r.check_counts[prev] || 0) - 1);
    r.check_counts[b.dataset.v] = (r.check_counts[b.dataset.v] || 0) + 1;
    r.check_states[cid] = { status: b.dataset.v };
    g.querySelectorAll('button').forEach((y) => y.classList.toggle('on', y === b));
    row.className = `check-row st-${b.dataset.v}`;
    ctx.progress(r.progress);
  } catch (err) { toast(err.message, 'err'); }
}

// =================================================================== add menu
function toggleAddMenu(el, ctx) {
  const wrap = el.querySelector('.add-menu');
  const open = wrap.querySelector('.menu');
  if (open) { open.remove(); return; }
  const m = document.createElement('div');
  m.className = 'menu right';
  m.innerHTML = `
    <button data-add="question" style="--c:var(--K-question)" id="add-question">${icon('message')}<span>Question<small>Ask the project team something specific</small></span></button>
    <button data-add="risk" style="--c:var(--K-risk)" id="add-risk">${icon('flag')}<span>Risk<small>Record a risk with likelihood, impact and treatment</small></span></button>
    <button data-add="recommendation" style="--c:var(--K-recommendation)" id="add-rec">${icon('bulb')}<span>Recommendation<small>An action the team should take</small></span></button>
    <hr />
    <button data-add="nist" id="add-nist">${icon('target')}<span>Framework requirement<small>Add any NIST CSF, AI RMF or OWASP requirement as a question</small></span></button>
    <button data-add="suggest" id="add-suggest">${icon('sparkles')}<span>Suggested risks…<small>Design-specific risks not yet recorded</small></span></button>`;
  wrap.appendChild(m);
  const off = (e) => { if (!wrap.contains(e.target)) { m.remove(); document.removeEventListener('click', off); } };
  setTimeout(() => document.addEventListener('click', off), 0);
  m.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-add]'); if (!b) return;
    m.remove(); document.removeEventListener('click', off);
    if (b.dataset.add === 'nist') return addRequirement(ctx);
    if (b.dataset.add === 'suggest') return suggestRisks(ctx);
    try {
      const res = await api.post(`/api/reviews/${ctx.r.id}/items`, { kind: b.dataset.add, title: '' });
      const S = state(ctx);
      S.open.add(res.item_id);
      if (S.filter !== 'all' && S.filter !== 'custom') S.filter = 'all';
      ctx.set(res.review);
      setTimeout(() => {
        const a = ctx.root.querySelector(`#li-${res.item_id}`);
        a?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        const t = a?.querySelector('[data-field="title"]'); if (t) { t.select(); t.focus({ preventScroll: true }); }
        flashRow(ctx, res.item_id);
      }, 60);
    } catch (err) { toast(err.message, 'err'); }
  });
}

const fwTrees = {};
const fwTree = (fid) => (fwTrees[fid] ||= api.get(`/api/frameworks/${encodeURIComponent(fid)}/tree`)
  .catch((e) => { delete fwTrees[fid]; throw e; }));

async function addRequirement(ctx) {
  const fws = ctx.meta.frameworks?.length ? ctx.meta.frameworks : [{ id: 'csf', name: 'NIST CSF', version: '2.0' }];
  let fw = fws[0].id;
  let tree = [];
  const have = new Set(ctx.r.items.map((x) => x.subcategory_id).filter(Boolean));
  const { el, close } = openOverlay(`
    <div class="drawer-head"><div style="flex:1"><h2>Add a requirement</h2><p class="small muted" style="margin:4px 0 0">Pick any NIST CSF 2.0, NIST AI RMF or OWASP requirement to add as a question.</p></div>
      <button class="btn ghost icon" data-close>${icon('x')}</button></div>
    <div class="row" style="padding:14px 24px 0;gap:8px">
      ${fws.length > 1 ? `<select class="select" id="pick-fw" style="width:auto;max-width:45%" aria-label="Framework">${fws.map((f) => `<option value="${esc(f.id)}">${esc(f.name)} ${esc(f.version || '')}${f.count ? ` (${f.count})` : ''}</option>`).join('')}</select>` : ''}
      <div class="search" style="flex:1">${icon('search')}<input class="input" id="pick-q" placeholder="Search requirements, questions or IDs…" autofocus /></div></div>
    <div class="drawer-body" id="pick-list"><div class="loading"><span class="spin"></span>Loading…</div></div>`, { modal: true });
  const draw = () => {
    const q = el.querySelector('#pick-q').value.toLowerCase();
    el.querySelector('#pick-list').innerHTML = tree.map((f) => {
      const rows = f.categories.flatMap((c) => c.subcategories).filter((s) => !q || `${s.id} ${s.title || ''} ${s.text} ${s.question}`.toLowerCase().includes(q));
      if (!rows.length) return '';
      return `<div class="fn-group-head" style="--c:${fnColor(ctx, f.id)};margin-top:12px">${esc(f.title)}</div>` + rows.map((s) => `
        <div class="pick-row ${have.has(s.id) ? 'added' : ''}" data-sid="${s.id}" style="--c:${fnColor(ctx, f.id)}">
          <span class="id">${s.id}</span><div><div style="font-size:13px;font-weight:550">${esc(s.question)}</div><div class="small muted">${s.title && s.title !== s.id ? `<b>${esc(s.title)}</b> — ` : ''}${esc(s.text)}</div></div>
          ${have.has(s.id) ? '<span class="badge">Added</span>' : `<span class="badge">${s.scope}</span>`}</div>`).join('');
    }).join('') || '<p class="small muted">No requirements match your search.</p>';
  };
  const load = async () => {
    const want = fw;
    let t = [];
    try { t = await fwTree(want); } catch (err) { toast(err.message, 'err'); }
    if (want !== fw) return;
    tree = t;
    draw();
  };
  load();
  el.querySelector('#pick-q').addEventListener('input', draw);
  el.querySelector('#pick-fw')?.addEventListener('change', (e) => { fw = e.target.value; load(); });
  el.querySelector('#pick-list').addEventListener('click', async (e) => {
    const row = e.target.closest('.pick-row'); if (!row || row.classList.contains('added')) return;
    try {
      const res = await api.post(`/api/reviews/${ctx.r.id}/items`, { kind: 'question', subcategory_id: row.dataset.sid });
      close();
      state(ctx).open.add(res.item_id);
      ctx.set(res.review);
      toast(`${row.dataset.sid} added`);
      setTimeout(() => jumpTo(ctx, res.item_id), 50);
    } catch (err) { toast(err.message, 'err'); }
  });
}

// =================================================================== bulk actions
async function autoLink(ctx) {
  try {
    const res = await api.post(`/api/reviews/${ctx.r.id}/auto-mitigate`, {});
    ctx.set(res.review);
    toast(res.linked ? `Linked controls to ${res.linked} item${res.linked === 1 ? '' : 's'} — existing controls reused first` : 'Nothing to link — every risk and gap already has a control', res.linked ? 'ok' : 'warn');
  } catch (e) { toast(e.message, 'err'); }
}

async function suggestRisks(ctx) {
  const { el, close } = openOverlay(`
    <div class="drawer-head"><div style="flex:1"><h2>${icon('sparkles')} Suggested risks</h2>
      <p class="small muted" style="margin:4px 0 0" id="sr-sub">Analysing the profile, design, documents and code review…</p></div>
      <button class="btn ghost icon" data-close>${icon('x')}</button></div>
    <div class="drawer-body" id="sr-list"><div class="loading"><span class="spin"></span>Finding risks that are not already recorded…</div></div>
    <div class="drawer-body row" style="flex:0;border-top:1px solid var(--border);padding:12px 24px">
      <button class="btn sm ghost" id="sr-all">Select all</button><button class="btn sm ghost" id="sr-none">None</button><span class="spacer"></span>
      <button class="btn" data-close>Cancel</button><button class="btn primary" id="sr-add" disabled>${icon('plus')} Add risks</button></div>`, { modal: true });
  el.style.maxHeight = '86vh';
  el.style.width = 'min(860px, 94vw)';
  let res;
  try { res = await api.post(`/api/reviews/${ctx.r.id}/risks/suggest`, { ai: true }); } catch (e) {
    el.querySelector('#sr-list').innerHTML = `<p class="muted">${esc(e.message)}</p>`; return;
  }
  const list = res.suggestions || [];
  const sel = new Set(list.map((s, k) => (['critical', 'high'].includes(s.rating) ? k : -1)).filter((k) => k >= 0));
  el.querySelector('#sr-sub').innerHTML = `${list.length} new risk${list.length === 1 ? '' : 's'} · ${res.existing_risks} already recorded · via <b>${esc(res.provider === 'heuristic' ? 'risk library + code review (deterministic)' : res.provider)}</b>`;
  const SRCL = { library: ['book', 'Risk library'], code: ['code', 'Code review'], ai: ['sparkles', 'AI'] };
  const draw = () => {
    el.querySelector('#sr-list').innerHTML = (res.warning ? `<div class="warning">${icon('alert')}<div>${esc(res.warning)}</div></div>` : '') + (list.length ? `<div class="pick-list">${list.map((s, k) => `
      <div class="pick-item ${sel.has(k) ? 'on' : ''}" data-k="${k}" style="align-items:flex-start">
        <span class="cb" style="margin-top:2px">${icon('check')}</span>
        <div style="min-width:0">
          <div class="row" style="gap:8px;flex-wrap:wrap"><span class="t">${esc(s.title)}</span>
            <span class="pill r-${s.rating}">${cap(s.rating)}</span><span class="src ${s.source === 'ai' ? 'ai' : s.source === 'code' ? 'holistic' : ''}">${icon(SRCL[s.source][0])}${SRCL[s.source][1]}</span></div>
          <div class="w" style="margin-top:4px;color:var(--text-2)">${esc(s.risk)}</div>
          ${s.rationale ? `<div class="w" style="margin-top:4px">${icon('info')} ${esc(s.rationale)}</div>` : ''}
          ${(s.mitigation_refs || []).length ? `<div class="chips" style="margin-top:6px">${s.mitigation_refs.map((m) => `<span class="chip" style="font-size:11px">${icon(m.reuse ? 'link' : 'shield')} ${esc(m.title)}${m.reuse ? ' · reuse' : ''}</span>`).join('')}</div>` : ''}
        </div><span></span></div>`).join('')}</div>`
      : `<div class="empty" style="padding:30px"><div class="ic">${icon('check')}</div><h3>No new risks</h3><p>Every library and code-review risk that applies to this profile is already recorded. Add documents or code, or configure Gemini for design-specific AI risks.</p></div>`);
    el.querySelectorAll('.w svg, .chip svg').forEach((s) => { s.style.cssText = 'width:11px;height:11px;vertical-align:-1px'; });
    const btn = el.querySelector('#sr-add');
    btn.disabled = !sel.size;
    btn.innerHTML = `${icon('plus')} Add ${sel.size || ''} risk${sel.size === 1 ? '' : 's'}`;
  };
  draw();
  el.querySelector('#sr-list').addEventListener('click', (e) => {
    const p = e.target.closest('[data-k]'); if (!p) return;
    const k = +p.dataset.k; if (sel.has(k)) sel.delete(k); else sel.add(k); draw();
  });
  el.querySelector('#sr-all').addEventListener('click', () => { list.forEach((_, k) => sel.add(k)); draw(); });
  el.querySelector('#sr-none').addEventListener('click', () => { sel.clear(); draw(); });
  el.querySelector('#sr-add').addEventListener('click', async () => {
    const risks = [...sel].map((k) => list[k]).map((s) => ({
      title: s.title, risk: s.risk, likelihood: s.likelihood, impact: s.impact, recommendation: s.recommendation || '',
      library_ref: s.library_ref || '', csf: s.csf || [], mitigations: s.mitigations || [], rationale: s.rationale || '', source: s.source,
    }));
    try {
      const out = await api.post(`/api/reviews/${ctx.r.id}/risks/accept`, { risks });
      close();
      const S = state(ctx);
      S.filter = 'risk';
      ctx.set(out.review);
      toast(`Added ${out.created.length} risk${out.created.length === 1 ? '' : 's'} with suggested controls`);
    } catch (e) { toast(e.message, 'err'); }
  });
}

// =================================================================== navigation (used by shell)
export function jumpTo(ctx, id) {
  const S = state(ctx);
  const it = findItem(ctx, id);
  if (!it) return;
  const el = ctx.root.querySelector('#rv-tab');
  if (!visible(S, it)) {
    S.filter = 'all'; S.fn = 'all'; S.q = '';
    const q = el.querySelector('#li-q'); if (q) q.value = '';
    renderToolbar(el, ctx);
  }
  S.open.add(id);
  renderList(el, ctx);
  const a = el.querySelector(`#li-${id}`);
  a?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  flashRow(ctx, id);
}

export function nextUnanswered(ctx) {
  const S = state(ctx);
  const el = ctx.root.querySelector('#rv-tab');
  if (!el.querySelector('#li-list')) return;
  const items = ctx.r.items;
  let pool = items.filter((i) => visible(S, i) && !i.answered);
  if (!pool.length) {
    pool = items.filter((i) => !i.answered);
    if (!pool.length) { toast('Everything is answered 🎉'); return; }
    S.filter = 'all'; S.fn = 'all'; S.q = '';
    const q = el.querySelector('#li-q'); if (q) q.value = '';
  }
  // the next unanswered after the last opened one, wrapping around
  const lastOpen = [...S.open].pop();
  const order = items.map((i) => i.id);
  const start = lastOpen ? order.indexOf(lastOpen) : -1;
  const next = pool.find((i) => order.indexOf(i.id) > start) || pool[0];
  S.open.forEach((oid) => flush(el, ctx, oid));
  S.open.clear();
  S.open.add(next.id);
  renderToolbar(el, ctx);
  renderList(el, ctx);
  const a = el.querySelector(`#li-${next.id}`);
  if (a) {
    a.scrollIntoView({ behavior: 'smooth', block: 'center' });
    flashRow(ctx, next.id);
    setTimeout(() => a.querySelector('[data-field="answer"], [data-field="title"], [data-field="risk"], [data-field="recommendation"]')?.focus({ preventScroll: true }), 350);
  }
}
