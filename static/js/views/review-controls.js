// Mitigating controls register: one control can close many questions, risks and recommendations.
import { api } from '../api.js';
import { aiField, wireAi } from '../ai-text.js';
import { cap, confirmDialog, debounce, esc, icon, openOverlay, toast } from '../ui.js';

const STATUSES = ['proposed', 'planned', 'in_progress', 'implemented', 'verified'];

function state(ctx) {
  return (ctx.ui.controls ||= { q: '', f: 'all', showNew: false });
}

export function render(el, ctx) {
  const S = state(ctx);
  const r = ctx.r;
  const mits = r.mitigations;
  const closing = new Set(mits.flatMap((m) => m.item_ids)).size;
  const done = mits.filter((m) => ['implemented', 'verified'].includes(m.status)).length;
  el.innerHTML = `<section class="card" style="padding:18px" id="mc-card">
    <div class="row wrap" style="margin-bottom:14px">
      <h2 class="section-title" style="margin:0">${icon('shield')} Mitigating controls register</h2>
      <span class="muted small">One control can close many line items</span>
      <span class="spacer"></span>
      <button class="btn sm" id="mc-lib">${icon('book')} Add from library</button>
      <button class="btn sm primary" id="mc-new-btn">${icon('plus')} New control</button>
    </div>
    <div class="grid-3" style="grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px">
      ${stat('Controls', mits.length, `${mits.filter((m) => m.state === 'existing').length} existing · ${mits.filter((m) => m.state === 'new').length} new`)}
      ${stat('Items closed', closing, `of ${r.items.length} line items`)}
      ${stat('Implemented', done, mits.length ? `${Math.round((done / mits.length) * 100)}% of controls` : '—')}
      ${stat('Still need a control', r.progress?.no_control || 0, 'risks & gaps', (r.progress?.no_control || 0) ? '#fdba74' : 'var(--ok)')}
    </div>
    <div id="mc-new">${S.showNew ? newFormHTML() : ''}</div>
    <div class="row wrap" style="margin-bottom:12px">
      <div class="filters" id="mc-filters">${[['all', 'All'], ['new', 'New'], ['existing', 'Existing'], ['open', 'Not implemented'], ['unlinked', 'Not linked']].map(([k, l]) => `<button class="filt ${S.f === k ? 'on' : ''}" data-f="${k}" id="mcf-${k}">${l}<span class="n">${count(mits, k)}</span></button>`).join('')}</div>
      <span class="spacer"></span>
      <div class="search" style="width:240px">${icon('search')}<input class="input sm" id="mc-q" placeholder="Search controls…" value="${esc(S.q)}" /></div>
    </div>
    <div class="reg-grid" id="mc-grid"></div>
  </section>`;
  drawGrid(el, ctx);

  el.querySelector('#mc-filters').addEventListener('click', (e) => {
    const b = e.target.closest('[data-f]'); if (!b) return;
    S.f = b.dataset.f;
    el.querySelectorAll('#mc-filters .filt').forEach((x) => x.classList.toggle('on', x === b));
    drawGrid(el, ctx);
  });
  el.querySelector('#mc-q').addEventListener('input', debounce((e) => { S.q = e.target.value.toLowerCase(); drawGrid(el, ctx); }, 200));
  el.querySelector('#mc-new-btn').addEventListener('click', () => {
    S.showNew = !S.showNew;
    el.querySelector('#mc-new').innerHTML = S.showNew ? newFormHTML() : '';
    el.querySelector('#mcn-title')?.focus();
  });
  el.querySelector('#mc-lib').addEventListener('click', () => openLibrary(ctx));

  const newBox = el.querySelector('#mc-new');
  wireAi(newBox, () => ({ review_id: ctx.r.id }));
  newBox.addEventListener('click', async (e) => {
    const seg = e.target.closest('[data-nc-state] button');
    if (seg) { seg.parentElement.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b === seg)); return; }
    if (e.target.closest('#mcn-cancel')) { S.showNew = false; newBox.innerHTML = ''; return; }
    if (e.target.closest('#mcn-create')) {
      const title = newBox.querySelector('#mcn-title').value.trim();
      if (title.length < 2) { toast('Give the control a title', 'warn'); return; }
      try {
        const res = await api.post(`/api/reviews/${ctx.r.id}/mitigations`, {
          title, description: newBox.querySelector('#mcn-desc').value, owner: newBox.querySelector('#mcn-owner').value,
          state: newBox.querySelector('[data-nc-state] .on').dataset.v,
        });
        S.showNew = false;
        ctx.set(res.review);
        toast(`“${title}” added — apply it to the items it closes`);
        jumpTo(ctx, res.mitigation_id);
      } catch (err) { toast(err.message, 'err'); }
    }
  });

  const grid = el.querySelector('#mc-grid');
  wireAi(grid, (ctl) => ({ review_id: ctx.r.id, mitigation_id: +ctl.closest('.ctl-card').dataset.mid }));
  const pending = {};
  const timers = {};
  const save = async (mid) => {
    const body = pending[mid]; delete pending[mid];
    if (!body) return;
    try {
      const fresh = await api.patch(`/api/reviews/${ctx.r.id}/mitigations/${mid}`, body);
      ctx.r = fresh;
      ctx.progress(fresh.progress);
      const s = grid.querySelector(`#mc-${mid} [data-saved]`); if (s) { s.textContent = 'Saved'; s.classList.add('ok'); }
    } catch (err) { toast(err.message, 'err'); }
  };
  grid.addEventListener('input', (e) => {
    const card = e.target.closest('.ctl-card'); if (!card) return;
    const f = e.target.dataset.mf || (e.target.dataset.field === 'description' ? 'description' : null);
    if (!f || e.target.type === 'date') return;
    const mid = +card.dataset.mid;
    (pending[mid] ||= {})[f] = e.target.value;
    const s = card.querySelector('[data-saved]'); if (s) { s.textContent = 'Saving…'; s.classList.remove('ok'); }
    clearTimeout(timers[mid]); timers[mid] = setTimeout(() => save(mid), 700);
  });
  grid.addEventListener('change', async (e) => {
    const card = e.target.closest('.ctl-card'); if (!card) return;
    const mid = +card.dataset.mid;
    if (e.target.dataset.mf === 'status' || e.target.dataset.mf === 'due_date') {
      clearTimeout(timers[mid]);
      const body = { ...(pending[mid] || {}), [e.target.dataset.mf]: e.target.value }; delete pending[mid];
      try { ctx.set(await api.patch(`/api/reviews/${ctx.r.id}/mitigations/${mid}`, body)); } catch (err) { toast(err.message, 'err'); }
    }
  });
  grid.addEventListener('click', async (e) => {
    const card = e.target.closest('.ctl-card'); if (!card) return;
    const mid = +card.dataset.mid;
    const m = ctx.r.mitigations.find((x) => x.id === mid);
    const seg = e.target.closest('[data-mf-state] button');
    if (seg && !seg.classList.contains('on')) {
      clearTimeout(timers[mid]);
      const body = { ...(pending[mid] || {}), state: seg.dataset.v }; delete pending[mid];
      try { ctx.set(await api.patch(`/api/reviews/${ctx.r.id}/mitigations/${mid}`, body)); } catch (err) { toast(err.message, 'err'); }
      return;
    }
    const chip = e.target.closest('[data-jump]');
    if (chip) { ctx.jumpToItem(+chip.dataset.jump); return; }
    if (e.target.closest('[data-apply-items]')) { await save(mid); openApply(ctx, mid); return; }
    if (e.target.closest('[data-del]')) {
      if (!(await confirmDialog(`Delete “${m.title}”?`, m.item_ids.length ? `It is unlinked from the ${m.item_ids.length} line item(s) it closes.` : 'The control is removed from the register.'))) return;
      try { ctx.set(await api.del(`/api/reviews/${ctx.r.id}/mitigations/${mid}`)); toast('Control deleted'); } catch (err) { toast(err.message, 'err'); }
    }
  });
}

const stat = (k, v, sub, color) => `<div class="card tight mini-stat" style="padding:12px 14px"><div class="k">${k}</div>
  <div class="v" style="font-size:24px;${color ? `color:${color}` : ''}">${v}</div><div class="small muted">${sub}</div></div>`;

function count(mits, f) {
  return mits.filter((m) => match(m, f, '')).length;
}
function match(m, f, q) {
  if (f === 'new' && m.state !== 'new') return false;
  if (f === 'existing' && m.state !== 'existing') return false;
  if (f === 'open' && ['implemented', 'verified'].includes(m.status)) return false;
  if (f === 'unlinked' && m.item_ids.length) return false;
  if (q && !`${m.title} ${m.description} ${m.owner} ${(m.nist || []).join(' ')}`.toLowerCase().includes(q)) return false;
  return true;
}

function newFormHTML() {
  return `<div class="inline-form" style="margin:0 0 14px">
    <div class="row wrap"><input class="input" id="mcn-title" placeholder="Control title, e.g. “Centralised secrets vault with rotation”" style="flex:1;min-width:260px" />
      <div class="seg" data-nc-state><button type="button" data-v="new" class="on">New</button><button type="button" data-v="existing">Existing</button></div></div>
    ${aiField({ id: 'mcn-desc', field: 'mcn-desc', aiField: 'mitigation_description', rows: 2, placeholder: 'What is implemented, where, who operates it, how it is evidenced… (✨ to draft)' })}
    <div class="row"><input class="input sm" id="mcn-owner" placeholder="Owner (optional)" style="max-width:240px" /><span class="spacer"></span>
      <button class="btn sm ghost" id="mcn-cancel">Cancel</button><button class="btn sm primary" id="mcn-create">${icon('check')} Create control</button></div>
  </div>`;
}

function drawGrid(el, ctx) {
  const S = state(ctx);
  const grid = el.querySelector('#mc-grid');
  const list = ctx.r.mitigations.filter((m) => match(m, S.f, S.q));
  if (!ctx.r.mitigations.length) {
    grid.style.display = 'block';
    grid.innerHTML = `<div class="empty"><div class="ic">${icon('shield')}</div><h3>No mitigating controls yet</h3>
      <p>Link controls from a line item, use “Auto-link controls”, or add one here and apply it to every item it closes.</p></div>`;
    return;
  }
  grid.style.display = '';
  if (!list.length) { grid.innerHTML = '<div class="empty" style="padding:30px;grid-column:1/-1"><p>No controls match.</p></div>'; return; }
  const byId = Object.fromEntries(ctx.r.items.map((i) => [i.id, i]));
  grid.innerHTML = list.map((m) => {
    const items = m.item_ids.map((id) => byId[id]).filter(Boolean);
    return `<div class="ctl-card" id="mc-${m.id}" data-mid="${m.id}">
      <div class="top"><span class="ic ${m.state === 'existing' ? 'existing' : ''}" title="${m.state === 'existing' ? 'Existing control' : 'New control'}">${icon(m.state === 'existing' ? 'check' : 'shield')}</span>
        <input class="title-in" data-mf="title" value="${esc(m.title)}" aria-label="Control title" id="mct-${m.id}" />
        <span class="saved" data-saved></span>
        <button class="btn sm ghost icon danger" data-del title="Delete control" id="mcd-${m.id}">${icon('trash')}</button></div>
      <div class="ctl-meta">
        <div class="seg" data-mf-state><button data-v="existing" class="${m.state === 'existing' ? 'on' : ''}">Existing</button><button data-v="new" class="${m.state === 'new' ? 'on' : ''}">New</button></div>
        <select class="select sm" data-mf="status" aria-label="Status">${STATUSES.map((s) => `<option value="${s}" ${m.status === s ? 'selected' : ''}>${cap(s)}</option>`).join('')}</select>
        <input class="input sm" data-mf="owner" value="${esc(m.owner)}" placeholder="Owner" aria-label="Owner" />
        <input class="input sm" type="date" data-mf="due_date" value="${esc(m.due_date)}" aria-label="Due date" />
      </div>
      ${aiField({ id: `mcx-${m.id}`, field: 'description', aiField: 'mitigation_description', value: m.description, rows: 2, placeholder: 'Describe the control and its evidence…' })}
      <div class="closes"><span class="small muted" style="margin-right:4px">Closes</span>
        ${items.map((i) => `<span class="lbl-chip k-${i.kind}" data-jump="${i.id}" title="${esc(i.display_title || i.risk || '')}">${esc(i.label)}</span>`).join('') || '<span class="small" style="color:#fdba74">nothing yet</span>'}
        <button class="chip add" data-apply-items id="mca-${m.id}">${icon('plus')} Apply to items…</button></div>
      ${(m.nist || []).length || m.library_ref ? `<div class="row wrap small muted" style="gap:6px">${m.library_ref ? `<span class="pill src">${esc(m.library_ref)}</span>` : ''}${(m.nist || []).map((c) => `<span class="chip" style="font-family:var(--mono);font-size:11px">${esc(c)}</span>`).join('')}</div>` : ''}
    </div>`;
  }).join('');
}

// ------------------------------------------------------------------ apply one control to many items
function openApply(ctx, mid) {
  const m = ctx.r.mitigations.find((x) => x.id === mid);
  const sel = new Set(m.item_ids);
  let q = '';
  let onlyNeed = false;
  const { el, close } = openOverlay(`
    <div class="drawer-head"><div style="flex:1"><h2>Apply “${esc(m.title)}”</h2>
      <p class="small muted" style="margin:4px 0 0">Select every question, risk and recommendation this control closes.</p></div>
      <button class="btn ghost icon" data-close>${icon('x')}</button></div>
    <div style="padding:14px 24px 0" class="row"><div class="search" style="flex:1">${icon('search')}<input class="input" id="ap-q" placeholder="Filter line items…" autofocus /></div>
      <label class="row small muted" style="gap:6px;cursor:pointer;white-space:nowrap"><span class="switch"><input type="checkbox" id="ap-need" /><span></span></span>Needs a control</label></div>
    <div class="drawer-body" id="ap-list"></div>
    <div class="drawer-body row" style="flex:0;border-top:1px solid var(--border);padding:12px 24px"><span class="small muted" id="ap-n"></span><span class="spacer"></span>
      <button class="btn" data-close>Cancel</button><button class="btn primary" id="ap-save">${icon('check')} Save links</button></div>`, { modal: true });
  el.style.maxHeight = '86vh';
  const draw = () => {
    const ql = q.toLowerCase();
    const items = ctx.r.items.filter((i) => (!ql || `${i.label} ${i.display_title} ${i.risk}`.toLowerCase().includes(ql))
      && (!onlyNeed || sel.has(i.id) || ((i.is_risk || ['not_met', 'partial'].includes(i.status)) && !i.mitigation_ids.length)));
    const sec = (title, rows) => (rows.length ? `<div class="pick-sec">${title} (${rows.length})</div><div class="pick-list">${rows.map((i) => `
      <div class="pick-item ${sel.has(i.id) ? 'on' : ''}" data-id="${i.id}"><span class="cb">${icon('check')}</span>
        <div style="min-width:0"><div class="t"><span class="mono" style="color:var(--K-${i.kind})">${esc(i.label)}</span> ${esc(i.display_title || i.risk || '')}</div>
        <div class="w">${i.is_risk ? `${cap(i.risk_rating || 'unrated')} risk · ` : ''}${i.mitigation_ids.length} control(s)${i.answered ? ' · answered' : ''}</div></div>
        ${i.risk_rating ? `<span class="pill r-${i.risk_rating}">${cap(i.risk_rating)}</span>` : '<span></span>'}</div>`).join('')}</div>` : '');
    el.querySelector('#ap-list').innerHTML =
      sec('Risks', items.filter((i) => i.is_risk)) +
      sec('Recommendations', items.filter((i) => !i.is_risk && i.is_recommendation)) +
      sec('Questions', items.filter((i) => !i.is_risk && !i.is_recommendation)) || '<p class="muted small">No line items match.</p>';
    el.querySelector('#ap-n').textContent = `${sel.size} selected`;
  };
  draw();
  el.querySelector('#ap-q').addEventListener('input', debounce((e) => { q = e.target.value; draw(); }, 150));
  el.querySelector('#ap-need').addEventListener('change', (e) => { onlyNeed = e.target.checked; draw(); });
  el.querySelector('#ap-list').addEventListener('click', (e) => {
    const p = e.target.closest('[data-id]'); if (!p) return;
    const id = +p.dataset.id; if (sel.has(id)) sel.delete(id); else sel.add(id);
    p.classList.toggle('on'); el.querySelector('#ap-n').textContent = `${sel.size} selected`;
  });
  el.querySelector('#ap-save').addEventListener('click', async () => {
    try {
      const fresh = await api.post(`/api/reviews/${ctx.r.id}/mitigations/${mid}/links`, { item_ids: [...sel] });
      close();
      ctx.set(fresh);
      toast(`“${m.title}” now closes ${sel.size} item${sel.size === 1 ? '' : 's'}`);
      jumpTo(ctx, mid);
    } catch (err) { toast(err.message, 'err'); }
  });
}

// ------------------------------------------------------------------ library / org picker
async function openLibrary(ctx) {
  let q = '';
  let data = { org: [], library: [] };
  const { el, close } = openOverlay(`
    <div class="drawer-head"><div style="flex:1"><h2>Add a control</h2><p class="small muted" style="margin:4px 0 0">From the control library or controls already used in other reviews.</p></div>
      <button class="btn ghost icon" data-close>${icon('x')}</button></div>
    <div style="padding:14px 24px 0"><div class="search">${icon('search')}<input class="input" id="lib-q" placeholder="Search…" autofocus /></div></div>
    <div class="drawer-body" id="lib-list"><div class="loading"><span class="spin"></span>Loading…</div></div>`, { modal: true });
  el.style.maxHeight = '84vh';
  const refs = new Set(ctx.r.mitigations.map((m) => m.library_ref).filter(Boolean));
  const titles = new Set(ctx.r.mitigations.map((m) => m.title.trim().toLowerCase()));
  const draw = () => {
    const lib = data.library;
    const org = data.org.filter((o) => !titles.has(o.title.trim().toLowerCase()));
    el.querySelector('#lib-list').innerHTML = `
      ${org.length ? `<div class="pick-sec">Used in other reviews</div><div class="pick-list">${org.map((o, k) => `<div class="pick-item" data-org="${k}"><span class="cb">${icon('check')}</span>
        <div style="min-width:0"><div class="t">${esc(o.title)}</div><div class="w">${esc(cap(o.state))} · used ${o.count}× · ${o.reviews.slice(0, 3).map((r) => esc(r.ref)).join(', ')}</div></div><span></span></div>`).join('')}</div>` : ''}
      <div class="pick-sec">Control library</div><div class="pick-list">${lib.map((l) => `<div class="pick-item ${refs.has(l.library_id) ? 'on' : ''}" data-lib="${esc(l.library_id)}"><span class="cb">${icon('check')}</span>
        <div style="min-width:0"><div class="t">${esc(l.title)}</div><div class="w">${esc(l.description)}</div></div><span class="mono small muted">${esc((l.nist || []).slice(0, 3).join(' '))}</span></div>`).join('')}</div>`;
    el._org = org;
  };
  const load = async () => { data = await api.get(`/api/mitigations/org?q=${encodeURIComponent(q)}&exclude_review=${ctx.r.id}`); draw(); };
  load();
  el.querySelector('#lib-q').addEventListener('input', debounce((e) => { q = e.target.value; load(); }, 200));
  el.querySelector('#lib-list').addEventListener('click', async (e) => {
    const p = e.target.closest('.pick-item'); if (!p || p.classList.contains('on')) return;
    let body;
    if (p.dataset.lib) {
      const l = data.library.find((x) => x.library_id === p.dataset.lib);
      body = { title: l.title, description: l.description, nist: l.nist, library_ref: l.library_id, source: 'library' };
    } else {
      const o = el._org[+p.dataset.org];
      body = { title: o.title, description: o.description, nist: o.nist, state: o.state, library_ref: o.library_ref || '', source: 'org' };
    }
    try {
      const res = await api.post(`/api/reviews/${ctx.r.id}/mitigations`, body);
      close();
      ctx.set(res.review);
      toast(`“${body.title}” added — now apply it to the items it closes`);
      jumpTo(ctx, res.mitigation_id);
      setTimeout(() => openApply(ctx, res.mitigation_id), 400);
    } catch (err) { toast(err.message, 'err'); }
  });
}

export function jumpTo(ctx, mid) {
  const S = state(ctx);
  const el = ctx.root.querySelector('#rv-tab');
  let card = el.querySelector(`#mc-${mid}`);
  if (!card && (S.f !== 'all' || S.q)) {
    S.f = 'all'; S.q = '';
    render(el, ctx);
    card = el.querySelector(`#mc-${mid}`);
  }
  if (!card) return;
  card.scrollIntoView({ behavior: 'smooth', block: 'center' });
  card.classList.remove('flash'); void card.offsetWidth; card.classList.add('flash');
}
