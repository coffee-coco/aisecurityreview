// Drawers shared between the review workspace and the control library.
import { api } from '../api.js';
import { CHECK, FN_COLOR, esc, icon, openOverlay } from '../ui.js';

export async function openControlDrawer(cid) {
  const { el } = openOverlay(`<div class="drawer-head"><div style="flex:1"><div class="loading"><span class="spin"></span>Loading ${esc(cid)}…</div></div>
    <button class="btn ghost icon" data-close id="ctrl-close">${icon('x')}</button></div><div class="drawer-body"></div>`);
  try {
    const c = await api.get(`/api/catalog/controls/${encodeURIComponent(cid)}`);
    const checks = await api.get(`/api/catalog/checks?control=${encodeURIComponent(cid)}&limit=400`);
    el.querySelector('.drawer-head > div').innerHTML = `
      <div class="eyebrow">${icon('shield')} NIST SP 800-53 Rev 5 · ${esc(c.family_title)}</div>
      <h2><span class="mono" style="font-size:16px;color:var(--accent-2)">${esc(c.id)}</span> ${esc(c.title)}</h2>`;
    const byProv = {};
    checks.forEach((k) => { (byProv[k.provider] ||= []).push(k); });
    el.querySelector('.drawer-body').innerHTML = `
      <h2 class="section-title">${icon('file')} Control statement</h2>
      <div class="statement">${esc(c.statement || 'No statement text available.')}</div>
      <h2 class="section-title" style="margin-top:22px">${icon('target')} Satisfies CSF 2.0 outcomes</h2>
      <div class="chips">${c.subcategories.map((s) => `<span class="chip" style="color:${FN_COLOR(s)};font-family:var(--mono);font-size:11.5px">${esc(s)}</span>`).join('') || '<span class="muted small">Not directly referenced by CSF 2.0</span>'}</div>
      <h2 class="section-title" style="margin-top:22px">${icon('code')} Checkov checks mapped to this control <span class="badge">${checks.length}</span></h2>
      ${Object.entries(byProv).sort((a, b) => b[1].length - a[1].length).map(([p, list]) => `
        <details class="ex" style="margin-bottom:10px" ${Object.keys(byProv).length < 3 ? 'open' : ''}>
          <summary><strong style="color:var(--text)">${esc(p)}</strong> <span class="badge">${list.length}</span></summary>
          <div class="check-list" style="margin-top:8px">${list.map(checkRowStatic).join('')}</div>
        </details>`).join('') || '<p class="muted small">No Checkov checks are mapped to this control.</p>'}`;
  } catch (e) {
    el.querySelector('.drawer-body').innerHTML = `<p class="muted">${esc(e.message)}</p>`;
  }
}

export function checkRowStatic(k) {
  return `<div class="check-row" style="grid-template-columns:118px minmax(0,1fr)">
    <span class="cid">${esc(k.id)}</span>
    <div><div class="nm">${esc(k.name)}</div>
      <div class="sub"><span class="tag t-prov">${esc(k.provider)}</span>${k.frameworks.map((f) => `<span class="tag">${esc(f)}</span>`).join('')}
      ${k.controls.map((c) => `<span class="tag" style="font-family:var(--mono)">${esc(c)}</span>`).join('')}</div></div>
  </div>`;
}

const LINK_SRC = {
  auto: { label: 'auto', title: 'Linked automatically by the curated mapping' },
  global: { label: 'added · all reviews', title: 'Added by a reviewer for every review' },
  review: { label: 'added · this review', title: 'Added by a reviewer for this review only' },
};

/** Source badge + reason line for a requirement → check link (from the mappings API). */
export function linkInfo(k) {
  const src = LINK_SRC[k.source];
  const badge = src ? `<span class="tag ck-src s-${esc(k.source)}" title="${esc(src.title)}">${esc(src.label)}</span>` : '';
  const removed = k.excluded ? `<span class="tag ck-src s-removed" title="${esc(k.note || '')}">removed · ${k.excluded === 'review' ? 'this review' : 'all reviews'}</span>` : '';
  const reason = k.reason ? `<div class="ck-why">${esc(k.reason)}${k.note ? ` — <i>${esc(k.note)}</i>` : ''}</div>` : '';
  return { badge: badge + removed, reason };
}

// Reviewer link edits. scope: 'review' (only reviewId) | 'global' (every review).
const linkUrl = (rid, cid) => `/api/mappings/requirements/${encodeURIComponent(rid)}/checks/${encodeURIComponent(cid)}`;

export function includeCheckLink(rid, cid, scope, reviewId, note = '') {
  return api.put(linkUrl(rid, cid), { action: 'include', note, review_id: scope === 'review' ? reviewId : null });
}

/** A check pinned only by a reviewer at this scope is unpinned; anything else is excluded. */
export function removeCheckLink(rid, k, scope, reviewId, note = '') {
  if (!k.auto && k.source === scope) return api.del(linkUrl(rid, k.id) + (scope === 'review' ? `?review_id=${reviewId}` : ''));
  return api.put(linkUrl(rid, k.id), { action: 'exclude', note, review_id: scope === 'review' ? reviewId : null });
}

export function restoreCheckLink(rid, k, reviewId) {
  return api.del(linkUrl(rid, k.id) + (k.excluded === 'review' ? `?review_id=${reviewId}` : ''));
}

export function checkRow(k, { editable = true, actions = false } = {}) {
  const st = k.review_status || 'applicable';
  const li = linkInfo(k);
  const stat = editable ? `<div class="cstat">${Object.entries(CHECK).map(([v, l]) => `<button data-v="${v}" class="${st === v ? 'on' : ''}">${l}</button>`).join('')}</div>` : '';
  const acts = actions ? `<div class="ck-acts">${k.excluded
    ? `<button class="btn sm ghost" data-cl="restore" title="Restore this check">${icon('undo')} Restore</button>`
    : `<button class="btn sm ghost icon" data-cl="remove" title="Remove from this requirement">${icon('x')}</button>`}</div>` : '';
  return `<div class="check-row st-${st}${k.excluded ? ' ck-removed' : ''}" data-check="${esc(k.id)}" id="chk-${esc(k.id)}">
    <span class="cid">${esc(k.id)}</span>
    <div><div class="nm">${esc(k.name)}</div>
      <div class="sub">
        <span class="tag t-prov">${esc(k.provider)}</span>
        ${k.frameworks.slice(0, 3).map((f) => `<span class="tag">${esc(f)}</span>`).join('')}
        ${k.strength === 'strong' ? '<span class="tag strong">strong match</span>' : k.strength === 'related' ? '<span class="tag">related</span>' : ''}
        ${li.badge}
        ${(k.stack_match || []).map((s) => `<span class="tag t-stack">${icon('zap', '')} ${esc(s)}</span>`).join('')}
        ${(k.shared_controls || []).map((c) => `<span class="tag" style="font-family:var(--mono)" title="Linking 800-53 control">${esc(c)}</span>`).join('')}
      </div>${li.reason}</div>
    ${actions ? `<div class="ck-right">${k.excluded ? '' : stat}${acts}</div>` : stat}
  </div>`;
}
