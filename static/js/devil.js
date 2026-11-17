// Devil's advocate and AI review on content boxes.
//
// Views call devil({type, ref, kind?, owner?}) to render a selection checkbox and a tiny red devil button. The devil
// challenges one entry; selecting one or many entries opens a bar that runs an AI review or a devil's advocate pass
// over all of them as a background job. Each result can be applied, overridden or removed.
import { api, pollJob } from './api.js';
import { confirmDialog, esc, icon, openOverlay, progressOverlay, toast } from './ui.js';
import { canWrite, rerender } from './app.js';

export const DEVIL_SVG = `<svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M5 2c-.2 2.2.4 4 1.7 5.3A7.5 7.5 0 0 0 4.5 13c0 4.4 3.4 8 7.5 8s7.5-3.6 7.5-8a7.5 7.5 0 0 0-2.2-5.7C18.6 6 19.2 4.2 19 2c-1.6 1.3-3.3 2-5 2.2a7.4 7.4 0 0 0-4 0C8.3 4 6.6 3.3 5 2z"/><path fill="#0b0f19" d="m8.3 11.8 2.6 1.3-2.6 1zm7.4 0-2.6 1.3 2.6 1zM9 16.2c1.9 1.3 4.1 1.3 6 0-.6 1.6-1.7 2.4-3 2.4s-2.4-.8-3-2.4z"/></svg>`;
const MODES = {
  devil: { label: "Devil's advocate", icon: DEVIL_SVG, prompt: 'Your challenge', placeholder: 'e.g. How on earth has this got anything to do with this application?', hint: 'Leave blank to challenge whether each entry is accurate and aligned with this application.' },
  review: { label: 'AI review', icon: icon('sparkles'), prompt: 'Instructions (optional)', placeholder: 'e.g. Make each one specific to our AWS components', hint: 'The AI checks each entry is accurate, specific to this application and actionable, and proposes improved text.' },
};
const VERDICT = {
  upheld: ['Challenge upheld', 'bad'], partly_upheld: ['Challenge partly upheld', 'warn'],
  rejected: ['Challenge rejected — the entry stands', 'ok'], inconclusive: ['Inconclusive', 'muted'],
  aligned: ['Aligned with the application', 'ok'], needs_improvement: ['Needs improvement', 'warn'],
  not_applicable: ['Not applicable to this application', 'bad'],
};
const ACTION = { keep: 'Keep as is', revise: 'Revise the text', remove: 'Remove the entry' };

const selected = new Map();
const keyOf = (t) => `${t.owner}|${t.type}|${t.kind || ''}|${t.ref}`;
const pageOwner = () => Number(location.hash.match(/^#\/(?:review|threat-model)\/(\d+)/)?.[1]) || null;
const ownerPath = (t) => `/api/reviews/${t.owner}/devil`;

/** Checkbox + devil button for one entry. owner defaults to the review / threat model of the current page. */
export function devil({ type, ref = '', kind = '', owner = null }) {
  if (!canWrite()) return '';
  const t = { type, ref: String(ref), kind, owner: owner ?? pageOwner() };
  if (!t.owner) return '';
  return `<span class="devil-tools" data-devil="${esc(JSON.stringify(t))}">
    <input type="checkbox" class="devil-sel" ${selected.has(keyOf(t)) ? 'checked' : ''} aria-label="Select for AI review or devil's advocate" title="Select for AI review / devil's advocate" />
    <button type="button" class="devil-btn" title="Devil's advocate: challenge this">${DEVIL_SVG}</button></span>`;
}

const targetOf = (el) => JSON.parse(el.closest('.devil-tools').dataset.devil);

// ------------------------------------------------------------------ result rendering
function fieldsHTML(fields, proposed = {}) {
  return fields.filter((f) => !Object.keys(proposed).length || f.name in proposed).map((f) => `
    <div class="dv-field"><div class="label">${esc(f.label)}</div>
      ${f.name in proposed
        ? `<div class="dv-diff"><div class="dv-old">${esc(f.value || '—')}</div><div class="dv-new">${esc(proposed[f.name])}</div></div>`
        : `<div class="dv-cur">${esc(f.value || '—')}</div>`}</div>`).join('');
}

function verdictHTML(res) {
  const [label, tone] = VERDICT[res.verdict] || VERDICT.inconclusive;
  return `<div class="dv-verdict ${tone}"><b>${esc(label)}</b><span>AI recommends: ${esc(ACTION[res.recommendation] || res.recommendation)}</span></div>
    ${res.reasoning ? `<p class="dv-reason">${esc(res.reasoning)}</p>` : ''}
    ${res.evidence?.length ? `<ul class="dv-evidence">${res.evidence.map((e) => `<li>${esc(e)}</li>`).join('')}</ul>` : ''}`;
}

function editorHTML(entry, values) {
  return `<div class="dv-editor">${entry.fields.map((f) => `<div class="field"><label>${esc(f.label)}</label>
    ${f.multiline ? `<textarea class="textarea" rows="4" data-ef="${esc(f.name)}">${esc(values[f.name] ?? f.value)}</textarea>`
      : `<input class="input" data-ef="${esc(f.name)}" value="${esc(values[f.name] ?? f.value)}" />`}</div>`).join('')}
    <div class="row" style="justify-content:flex-end"><button class="btn sm" data-act="cancel-edit">Cancel</button>
      <button class="btn sm primary" data-act="save-override">${icon('check')} Save my text</button></div></div>`;
}

function readEditor(box, entry) {
  const out = {};
  box.querySelectorAll('[data-ef]').forEach((el) => {
    const f = entry.fields.find((x) => x.name === el.dataset.ef);
    if (f && el.value.trim() !== (f.value || '').trim()) out[f.name] = el.value;
  });
  return out;
}

async function act(kind, t, entry, ctx) {
  const base = { target: t, question: ctx.question || '', verdict: ctx.res?.verdict || '', mode: ctx.mode };
  if (kind === 'remove') {
    if (!(await confirmDialog(`Remove this ${entry.type_label.toLowerCase()}?`, entry.label, 'Remove'))) return false;
    await api.post(`${ownerPath(t)}/remove`, base);
    toast(`${entry.type_label} removed`);
    return true;
  }
  if (!Object.keys(ctx.fields || {}).length) { toast('Nothing changed', 'warn'); return false; }
  await api.post(`${ownerPath(t)}/apply`, { ...base, fields: ctx.fields, source: kind });
  toast(kind === 'ai' ? 'AI correction applied' : 'Your text was saved');
  return true;
}

// ------------------------------------------------------------------ single entry
async function openDevil(t) {
  let entry;
  try {
    entry = await api.get(`${ownerPath(t)}?${new URLSearchParams({ type: t.type, ref: t.ref, kind: t.kind || '' })}`);
  } catch (e) { toast(e.message, 'err'); return; }
  const state = { mode: 'devil', question: '', res: null };
  const { el, close } = openOverlay(`
    <div class="drawer-head"><span class="devil-badge">${DEVIL_SVG}</span><div style="flex:1;min-width:0">
      <h2>Devil's advocate</h2><p class="muted small" style="margin:4px 0 0">${esc(entry.type_label)} · ${esc(entry.label)}</p></div>
      <button class="btn ghost icon" data-close aria-label="Close">${icon('x')}</button></div>
    <div class="drawer-body">
      <div class="dv-current">${fieldsHTML(entry.fields)}</div>
      <div class="field" style="margin-top:14px"><label for="dv-q">Argue that this is wrong or not aligned with the application</label>
        <textarea class="textarea" id="dv-q" rows="3" placeholder="${esc(MODES.devil.placeholder)}"></textarea></div>
      ${entry.ai_enabled ? '' : '<p class="small muted">No AI provider is configured for this workspace — you can still override the text or remove the entry.</p>'}
      <div class="row wrap" style="margin-top:10px">
        <button class="btn primary" data-act="challenge" ${entry.ai_enabled ? '' : 'disabled'}>${DEVIL_SVG} Challenge</button>
        <span class="spacer"></span>
        <button class="btn" data-act="edit">${icon('edit')} Override text</button>
        ${entry.can_remove ? `<button class="btn danger" data-act="remove">${icon('trash')} Remove</button>` : ''}
      </div>
      <div id="dv-result"></div><div id="dv-edit"></div>
    </div>`, { modal: true });
  el.classList.add('dv-modal');
  const done = () => { close(); rerender(); };

  el.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-act]');
    if (!b) return;
    state.question = el.querySelector('#dv-q').value.trim();
    try {
      if (b.dataset.act === 'challenge') {
        if (state.question.length < 3) { toast('Type your challenge first', 'warn'); return; }
        b.disabled = true;
        b.innerHTML = '<span class="spin"></span> Thinking…';
        state.res = await api.post(`${ownerPath(t)}/challenge`, { target: t, question: state.question, mode: 'devil' });
        const p = state.res.fields || {};
        el.querySelector('#dv-result').innerHTML = `<div class="dv-result">${verdictHTML(state.res)}
          ${Object.keys(p).length ? `<div class="dv-proposed">${fieldsHTML(entry.fields, p)}</div>` : ''}
          <div class="row wrap" style="justify-content:flex-end">
            ${Object.keys(p).length ? `<button class="btn" data-act="edit-ai">${icon('edit')} Edit before applying</button>
              <button class="btn primary" data-act="apply-ai">${icon('check')} Apply AI correction</button>` : ''}
            ${state.res.recommendation === 'remove' && entry.can_remove ? `<button class="btn danger" data-act="remove">${icon('trash')} Remove as recommended</button>` : ''}
          </div></div>`;
        b.disabled = false;
        b.innerHTML = `${DEVIL_SVG} Challenge again`;
      } else if (b.dataset.act === 'apply-ai') {
        if (await act('ai', t, entry, { ...state, fields: state.res.fields })) done();
      } else if (b.dataset.act === 'edit' || b.dataset.act === 'edit-ai') {
        el.querySelector('#dv-edit').innerHTML = editorHTML(entry, b.dataset.act === 'edit-ai' ? state.res.fields : {});
        el.querySelector('#dv-edit [data-ef]')?.focus();
      } else if (b.dataset.act === 'cancel-edit') {
        el.querySelector('#dv-edit').innerHTML = '';
      } else if (b.dataset.act === 'save-override') {
        if (await act('override', t, entry, { ...state, fields: readEditor(el.querySelector('#dv-edit'), entry) })) done();
      } else if (b.dataset.act === 'remove') {
        if (await act('remove', t, entry, state)) done();
      }
    } catch (err) {
      toast(err.message, 'err');
      if (b.dataset.act === 'challenge') { b.disabled = false; b.innerHTML = `${DEVIL_SVG} Challenge`; }
    }
  });
  el.querySelector('#dv-q').focus();
}

// ------------------------------------------------------------------ selection + batch
function updateBar() {
  let bar = document.getElementById('devil-bar');
  if (!selected.size) { bar?.remove(); return; }
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'devil-bar';
    bar.setAttribute('role', 'region');
    bar.setAttribute('aria-label', 'Selected entries');
    document.body.appendChild(bar);
    bar.addEventListener('click', (e) => {
      const b = e.target.closest('[data-bar]');
      if (!b) return;
      if (b.dataset.bar === 'clear') return clearSelection();
      if (b.dataset.bar === 'all') {
        document.querySelectorAll('#view .devil-sel').forEach((cb) => { cb.checked = true; const t = targetOf(cb); selected.set(keyOf(t), t); });
        return updateBar();
      }
      openBatch(b.dataset.bar);
    });
  }
  bar.innerHTML = `<b>${selected.size}</b><span>selected</span>
    <button class="btn sm ghost" data-bar="all">Select all on page</button>
    <button class="btn sm ghost" data-bar="clear">Clear</button>
    <button class="btn sm" data-bar="review">${icon('sparkles')} AI review</button>
    <button class="btn sm devil-run" data-bar="devil">${DEVIL_SVG} Devil's advocate</button>`;
}

function clearSelection() {
  selected.clear();
  document.querySelectorAll('.devil-sel').forEach((cb) => { cb.checked = false; });
  updateBar();
}

function openBatch(mode) {
  const m = MODES[mode];
  const targets = [...selected.values()];
  const { el, close } = openOverlay(`
    <div class="drawer-head"><span class="devil-badge ${mode}">${m.icon}</span><div style="flex:1">
      <h2>${m.label} · ${targets.length} entr${targets.length === 1 ? 'y' : 'ies'}</h2>
      <p class="muted small" style="margin:4px 0 0">${esc(m.hint)}</p></div>
      <button class="btn ghost icon" data-close aria-label="Close">${icon('x')}</button></div>
    <div class="drawer-body">
      <div class="field"><label for="dvb-q">${esc(m.prompt)}</label><textarea class="textarea" id="dvb-q" rows="3" placeholder="${esc(m.placeholder)}"></textarea></div>
      <div class="row" style="justify-content:flex-end;margin-top:12px"><button class="btn" data-close>Cancel</button>
        <button class="btn primary" id="dvb-run">${m.icon} Run ${esc(m.label.toLowerCase())}</button></div>
    </div>`, { modal: true });
  el.classList.add('dv-modal');
  el.querySelector('#dvb-q').focus();
  el.querySelector('#dvb-run').addEventListener('click', () => {
    const question = el.querySelector('#dvb-q').value.trim();
    close();
    runBatch(mode, targets, question);
  });
}

async function runBatch(mode, targets, question) {
  const m = MODES[mode];
  const owner = pageOwner() || targets[0].owner;
  const prog = progressOverlay(`${m.label}: ${targets.length} entr${targets.length === 1 ? 'y' : 'ies'}`, 'Queued…');
  try {
    const { job_id } = await api.post(`/api/reviews/${owner}/devil/batch`, { targets, mode, question });
    const job = await pollJob(job_id, (j) => prog.set(j.message, j.progress));
    prog.close();
    showResults(mode, question, job.result.results || []);
  } catch (e) { prog.close(); toast(e.message, 'err'); }
}

const MAX_BATCH = 300;

/** Devil's advocate (or AI review) over a whole review: choose which registers to challenge. */
export function openMassDevil(r) {
  const t = (type, ref = '') => ({ type, ref: String(ref), kind: '', owner: r.id });
  const items = r.items || [];
  const groups = [
    { id: 'risks', label: 'Risks', on: true, targets: items.filter((i) => i.is_risk).map((i) => t('item', i.id)) },
    { id: 'recs', label: 'Recommendations', on: true, targets: items.filter((i) => i.is_recommendation && !i.is_risk).map((i) => t('item', i.id)) },
    { id: 'controls', label: 'Mitigating controls', on: true, targets: (r.mitigations || []).map((m) => t('mitigation', m.id)) },
    { id: 'questions', label: 'Questions (incl. NIST CSF requirements)', on: false, targets: items.filter((i) => !i.is_risk && !i.is_recommendation).map((i) => t('item', i.id)) },
    { id: 'context', label: 'Design summary and review details', on: false, targets: [...(r.design?.analyzed_at ? [t('design')] : []), t('review')] },
  ].filter((g) => g.targets.length);
  const { el, close } = openOverlay(`
    <div class="drawer-head"><span class="devil-badge">${DEVIL_SVG}</span><div style="flex:1">
      <h2>Challenge the whole review</h2><p class="muted small" style="margin:4px 0 0">${esc(r.ref)} · ${esc(r.title)}</p></div>
      <button class="btn ghost icon" data-close aria-label="Close">${icon('x')}</button></div>
    <div class="drawer-body">
      <div class="seg dv-mode" role="group" aria-label="Mode"><button data-mode="devil" class="on">${DEVIL_SVG} Devil's advocate</button><button data-mode="review">${icon('sparkles')} AI review</button></div>
      <p class="small muted" id="dvm-hint" style="margin:8px 0 12px">${esc(MODES.devil.hint)}</p>
      <div class="label" style="margin-bottom:6px">Challenge</div>
      <div class="dv-scope">${groups.map((g) => `<label class="dv-scope-row"><input type="checkbox" data-g="${g.id}" ${g.on ? 'checked' : ''} />
        <span>${esc(g.label)}</span><span class="n">${g.targets.length}</span></label>`).join('') || '<p class="small muted">This review has nothing to challenge yet.</p>'}</div>
      <div class="field" style="margin-top:14px"><label for="dvm-q" id="dvm-label">${esc(MODES.devil.prompt)}</label>
        <textarea class="textarea" id="dvm-q" rows="3" placeholder="${esc(MODES.devil.placeholder)}"></textarea></div>
      <div class="row" style="justify-content:flex-end;margin-top:12px"><span class="small muted" id="dvm-count"></span><span class="spacer"></span>
        <button class="btn" data-close>Cancel</button><button class="btn primary" id="dvm-run"></button></div>
    </div>`, { modal: true });
  el.classList.add('dv-modal');
  let mode = 'devil';
  const chosen = () => groups.filter((g) => el.querySelector(`[data-g="${g.id}"]`)?.checked).flatMap((g) => g.targets);
  const refresh = () => {
    const n = chosen().length;
    const run = el.querySelector('#dvm-run');
    run.innerHTML = `${MODES[mode].icon} Run on ${n} entr${n === 1 ? 'y' : 'ies'}`;
    run.disabled = !n || n > MAX_BATCH;
    el.querySelector('#dvm-count').textContent = n > MAX_BATCH ? `Select at most ${MAX_BATCH} entries per run` : '';
  };
  el.querySelector('.dv-mode').addEventListener('click', (e) => {
    const b = e.target.closest('[data-mode]');
    if (!b) return;
    mode = b.dataset.mode;
    el.querySelectorAll('.dv-mode button').forEach((x) => x.classList.toggle('on', x === b));
    el.querySelector('#dvm-hint').textContent = MODES[mode].hint;
    el.querySelector('#dvm-label').textContent = MODES[mode].prompt;
    el.querySelector('#dvm-q').placeholder = MODES[mode].placeholder;
    refresh();
  });
  el.querySelector('.dv-scope').addEventListener('change', refresh);
  el.querySelector('#dvm-run').addEventListener('click', () => {
    const targets = chosen();
    const question = el.querySelector('#dvm-q').value.trim();
    close();
    runBatch(mode, targets, question);
  });
  refresh();
  el.querySelector('#dvm-q').focus();
}

function batchItemHTML(r, i) {
  const p = r.fields_proposed || {};
  const has = Object.keys(p).length;
  return `<article class="dv-item" data-i="${i}">
    <div class="dv-item-head"><span class="tag">${esc(r.type_label || r.target.type)}</span><b>${esc(r.label)}</b>
      <span class="spacer"></span><span class="dv-state small"></span></div>
    ${r.error ? `<div class="warning">${icon('alert')}<div>${esc(r.error)}</div></div>` : `${verdictHTML(r)}
      ${has ? `<div class="dv-proposed">${fieldsHTML(r.entry_fields, p)}</div>` : ''}
      <div class="row wrap dv-actions" style="justify-content:flex-end">
        <button class="btn sm ghost" data-bi="keep">Keep</button>
        <button class="btn sm" data-bi="edit">${icon('edit')} Override</button>
        ${r.can_remove ? `<button class="btn sm ${r.recommendation === 'remove' ? 'danger-solid' : 'danger'}" data-bi="remove">${icon('trash')} Remove</button>` : ''}
        ${has ? `<button class="btn sm primary" data-bi="apply">${icon('check')} Apply AI text</button>` : ''}
      </div><div class="dv-edit-slot"></div>`}
  </article>`;
}

function showResults(mode, question, raw) {
  const m = MODES[mode];
  const results = raw.map((r) => ({ ...r, entry_fields: r.fields || [], fields_proposed: r.proposed || {} }));
  const counts = results.reduce((a, r) => { const k = r.error ? 'error' : r.recommendation; a[k] = (a[k] || 0) + 1; return a; }, {});
  let changed = false;
  const { el, close } = openOverlay(`
    <div class="drawer-head"><span class="devil-badge ${mode}">${m.icon}</span><div style="flex:1">
      <h2>${m.label} results</h2>
      <p class="muted small" style="margin:4px 0 0">${question ? `“${esc(question)}” · ` : ''}${['revise', 'remove', 'keep', 'error'].filter((k) => counts[k]).map((k) => `${counts[k]} ${k === 'error' ? 'failed' : ACTION[k].toLowerCase()}`).join(' · ')}</p></div>
      <button class="btn sm primary" id="dvr-apply-all" ${counts.revise ? '' : 'disabled'}>${icon('check')} Apply all AI text (${counts.revise || 0})</button>
      <button class="btn ghost icon" data-close aria-label="Close">${icon('x')}</button></div>
    <div class="drawer-body">${results.map(batchItemHTML).join('')}</div>`, { onClose: () => { clearSelection(); if (changed) rerender(); } });
  el.classList.add('dv-drawer');

  const finish = (art, text, tone = 'ok') => {
    art.classList.add('done');
    art.querySelector('.dv-actions')?.remove();
    art.querySelector('.dv-edit-slot').innerHTML = '';
    art.querySelector('.dv-state').innerHTML = `<span class="dv-done ${tone}">${icon(tone === 'ok' ? 'check' : 'trash')} ${esc(text)}</span>`;
  };
  const entryOf = (r) => ({ label: r.label, type_label: r.type_label || r.target.type, fields: r.entry_fields });
  const ctxOf = (r, fields) => ({ mode, question, res: r, fields });

  el.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-bi], [data-act]');
    if (!b) return;
    const art = b.closest('.dv-item');
    const r = results[+art.dataset.i];
    const entry = entryOf(r);
    try {
      const a = b.dataset.bi || b.dataset.act;
      if (a === 'keep') finish(art, 'Kept', 'ok');
      else if (a === 'apply' && await act('ai', r.target, entry, ctxOf(r, r.fields_proposed))) { changed = true; finish(art, 'AI text applied'); }
      else if (a === 'remove' && await act('remove', r.target, entry, ctxOf(r))) { changed = true; finish(art, 'Removed', 'bad'); }
      else if (a === 'edit') art.querySelector('.dv-edit-slot').innerHTML = editorHTML(entry, r.fields_proposed);
      else if (a === 'cancel-edit') art.querySelector('.dv-edit-slot').innerHTML = '';
      else if (a === 'save-override' && await act('override', r.target, entry, ctxOf(r, readEditor(art, entry)))) { changed = true; finish(art, 'Your text saved'); }
    } catch (err) { toast(err.message, 'err'); }
  });
  el.querySelector('#dvr-apply-all').addEventListener('click', async (e) => {
    e.currentTarget.disabled = true;
    let n = 0;
    for (const art of el.querySelectorAll('.dv-item:not(.done)')) {
      const r = results[+art.dataset.i];
      if (r.error || !Object.keys(r.fields_proposed).length) continue;
      try {
        await api.post(`${ownerPath(r.target)}/apply`, { target: r.target, fields: r.fields_proposed, question, verdict: r.verdict, mode, source: 'ai' });
        finish(art, 'AI text applied');
        changed = true;
        n += 1;
      } catch (err) { toast(`${r.label}: ${err.message}`, 'err'); }
    }
    toast(`Applied AI text to ${n} entr${n === 1 ? 'y' : 'ies'}`);
  });
}

// ------------------------------------------------------------------ wiring
let installed = false;
export function installDevil() {
  if (installed) return;
  installed = true;
  // Capture phase: keep clicks on the devil tools from also toggling / opening the card they sit in.
  document.addEventListener('click', (e) => {
    const tools = e.target.closest('.devil-tools');
    if (!tools) return;
    e.stopPropagation();
    if (e.target.closest('.devil-btn')) {
      e.preventDefault();
      openDevil(targetOf(e.target));
    }
  }, true);
  document.addEventListener('change', (e) => {
    if (!e.target.matches('.devil-sel')) return;
    const t = targetOf(e.target);
    if (e.target.checked) selected.set(keyOf(t), t); else selected.delete(keyOf(t));
    updateBar();
  });
  ['mousedown', 'dragstart'].forEach((ev) => document.addEventListener(ev, (e) => {
    if (e.target.closest?.('.devil-tools')) e.stopPropagation();
  }, true));
  window.addEventListener('hashchange', clearSelection);
}
