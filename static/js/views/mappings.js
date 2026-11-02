// Requirement ↔ Checkov check mappings: review the curated automatic links, exclude wrong ones,
// pin missing ones (for every review), and export / import the reviewer overrides.
import { api, getMeta } from '../api.js';
import { FN_COLOR, confirmDialog, debounce, esc, icon, toast } from '../ui.js';
import { checkRow, includeCheckLink, removeCheckLink, restoreCheckLink } from './shared.js';

const PAGE = 20;
const POLICY = { none: 'organisational', curated: 'curated', unmapped: 'reviewer links only' };

export async function render(root) {
  const meta = await getMeta();
  const S = {
    q: '', framework: '', sel: null, reqs: null, detail: null, dq: '', dprov: '',
    add: { q: '', prov: '', resource: '', control: '', offset: 0, res: null, picked: new Set() },
  };
  const provOpts = (v) => `<option value="">All platforms</option>${meta.providers.map((p) => `<option ${v === p.name ? 'selected' : ''}>${esc(p.name)}</option>`).join('')}`;

  root.innerHTML = `<div class="page">
    <div class="page-head">
      <div>
        <div class="eyebrow">${icon('link')} Knowledge base</div>
        <h1>Check <span class="grad-text">mappings</span></h1>
        <p>Which Checkov checks evidence each requirement. Automatic links come from the curated mapping; reviewer includes and excludes made here apply to every review (a review can still override them).</p>
      </div>
      <div class="row">
        <button class="btn" id="mp-export">${icon('download')} Export</button>
        <label class="btn" id="mp-import-btn">${icon('upload')} Import<input type="file" accept=".yaml,.yml" id="mp-import" hidden /></label>
      </div>
    </div>
    <div class="mp-grid">
      <aside class="mp-side">
        <div class="search">${icon('search')}<input class="input" id="mp-q" placeholder="Search requirements…" /></div>
        <select class="select sm" id="mp-fw" aria-label="Framework"><option value="">All frameworks</option></select>
        <div class="mp-reqs" id="mp-reqs"><div class="loading"><span class="spin"></span>Loading…</div></div>
      </aside>
      <section class="mp-main" id="mp-main"><div class="card empty"><div class="ic">${icon('link')}</div><h3>Select a requirement</h3><p>Pick a requirement on the left to review its linked Checkov checks.</p></div></section>
    </div>
  </div>`;
  const $ = (s) => root.querySelector(s);

  // ------------------------------------------------------------- requirement list
  const loadReqs = async () => {
    const qs = new URLSearchParams({ q: S.q, framework: S.framework });
    try { S.reqs = await api.get(`/api/mappings/requirements?${qs}`); } catch (e) { toast(e.message, 'err'); return; }
    const fw = $('#mp-fw');
    if (fw.options.length === 1) fw.insertAdjacentHTML('beforeend', S.reqs.frameworks.map((f) => `<option value="${esc(f.id)}">${esc(f.name)} (${f.count})</option>`).join(''));
    drawReqs();
  };

  const drawReqs = () => {
    const rows = S.reqs.requirements;
    let html = '';
    let group = null;
    for (const r of rows) {
      const g = `${r.framework_short} · ${r.function_title}`;
      if (g !== group) {
        group = g;
        const inGroup = rows.filter((x) => `${x.framework_short} · ${x.function_title}` === g);
        html += `<div class="mp-fn" style="--c:${FN_COLOR(r.function_id)}">${esc(g)}<span class="n">${inGroup.reduce((a, x) => a + x.total, 0)} links</span></div>`;
      }
      html += `<button class="mp-req ${S.sel === r.id ? 'on' : ''} p-${r.policy}" data-rid="${esc(r.id)}" style="--c:${FN_COLOR(r.function_id)}" title="${esc(r.why || r.text)}">
        <span class="id">${esc(r.id)}</span><span class="t">${esc(r.title && r.title !== r.id ? r.title : r.text)}</span>
        <span class="cnt">${r.policy === 'none' && !r.total ? '<span class="tag">org</span>' : `<b>${r.total}</b>`}${r.included ? `<i class="plus">+${r.included}</i>` : ''}${r.excluded ? `<i class="minus">−${r.excluded}</i>` : ''}</span></button>`;
    }
    $('#mp-reqs').innerHTML = html || '<p class="muted small" style="padding:10px">No requirements match.</p>';
  };

  $('#mp-q').addEventListener('input', debounce((e) => { S.q = e.target.value; loadReqs(); }, 250));
  $('#mp-fw').addEventListener('change', (e) => { S.framework = e.target.value; loadReqs(); });
  $('#mp-reqs').addEventListener('click', (e) => {
    const b = e.target.closest('[data-rid]');
    if (!b) return;
    S.sel = b.dataset.rid; S.dq = ''; S.add.offset = 0; S.add.picked.clear();
    root.querySelectorAll('.mp-req').forEach((x) => x.classList.toggle('on', x === b));
    loadDetail();
  });

  // ------------------------------------------------------------- selected requirement
  const loadDetail = async () => {
    const qs = new URLSearchParams({ q: S.dq, provider: S.dprov });
    try { S.detail = await api.get(`/api/mappings/requirements/${encodeURIComponent(S.sel)}?${qs}`); } catch (e) { toast(e.message, 'err'); return; }
    drawDetail();
    searchAdd();
  };

  const refresh = async () => { await Promise.all([loadDetail(), loadReqs()]); };

  const drawDetail = () => {
    const d = S.detail;
    const r = d.requirement;
    const live = d.checks.filter((k) => !k.excluded);
    const removed = d.checks.filter((k) => k.excluded);
    $('#mp-main').innerHTML = `
      <div class="card mp-head" style="--c:${FN_COLOR(r.function_id)}">
        <div class="eyebrow" style="color:var(--c)">${esc(r.framework_short)} · ${esc(r.function_title)} · ${esc(r.category_title)}</div>
        <h2><span class="mono" style="color:var(--c)">${esc(r.id)}</span> ${esc(r.text)}</h2>
        <div class="row wrap small" style="margin-top:8px">
          <span class="tag mp-pol p-${esc(d.policy)}">${esc(POLICY[d.policy] || d.policy)}</span>
          ${d.why ? `<span class="muted">${esc(d.why)}</span>` : ''}
          <span class="spacer"></span>
          <span class="muted">${d.auto} automatic · ${d.counts.global_include} added · ${d.counts.global_exclude} removed</span>
        </div>
      </div>
      <div class="card" style="margin-top:14px">
        <div class="checks-head">
          <h4>${icon('code')} Linked checks <span class="badge">${live.length}</span></h4>
          <span class="spacer"></span>
          <div class="search" style="width:220px">${icon('search')}<input class="input sm" id="mp-dq" placeholder="Filter linked checks…" value="${esc(S.dq)}" /></div>
          <select class="select sm" id="mp-dprov" style="width:170px">${provOpts(S.dprov)}</select>
        </div>
        <div class="check-list" id="mp-linked">${live.map((k) => checkRow(k, { editable: false, actions: true })).join('')
          || `<div class="ck-empty">${icon('info')}<div>${d.policy === 'none' ? '<b>Organisational requirement</b> — no IaC checks are expected. Add one below only if it genuinely evidences this outcome.' : 'No linked checks. Add checks below.'}</div></div>`}</div>
        ${removed.length ? `<details class="ex" style="margin-top:12px"><summary>${icon('undo')} Removed (${removed.length})</summary>
          <div class="check-list" style="margin-top:8px">${removed.map((k) => checkRow(k, { editable: false, actions: true })).join('')}</div></details>` : ''}
      </div>
      <div class="card mp-add" style="margin-top:14px">
        <div class="checks-head"><h4>${icon('plus')} Add checks <span class="muted small" style="font-weight:500">— linked for all reviews</span></h4></div>
        <div class="row wrap">
          <div class="search" style="flex:1;min-width:220px">${icon('search')}<input class="input sm" id="mp-aq" placeholder="Search check id or name…" value="${esc(S.add.q)}" /></div>
          <select class="select sm" id="mp-aprov" style="width:170px">${provOpts(S.add.prov)}</select>
          <input class="input sm" id="mp-ares" placeholder="Resource e.g. aws_s3_bucket" style="width:190px" value="${esc(S.add.resource)}" />
          <input class="input sm" id="mp-actl" placeholder="800-53 e.g. SC-28" style="width:130px" value="${esc(S.add.control)}" />
        </div>
        <div class="row" style="margin-top:10px">
          <input class="input sm" id="mp-anote" placeholder="Note for added checks (optional)" style="flex:1" />
          <button class="btn sm primary" id="mp-bulk" disabled>${icon('plus')} Add selected</button>
        </div>
        <div id="mp-ares-list" style="margin-top:10px"><div class="loading"><span class="spin"></span>Searching…</div></div>
      </div>`;
    $('#mp-dq').addEventListener('input', debounce((e) => { S.dq = e.target.value; loadDetail(); }, 250));
    $('#mp-dprov').addEventListener('change', (e) => { S.dprov = e.target.value; loadDetail(); });
    const addSearch = (k) => debounce((e) => { S.add[k] = e.target.value; S.add.offset = 0; searchAdd(); }, 250);
    $('#mp-aq').addEventListener('input', addSearch('q'));
    $('#mp-ares').addEventListener('input', addSearch('resource'));
    $('#mp-actl').addEventListener('input', addSearch('control'));
    $('#mp-aprov').addEventListener('change', (e) => { S.add.prov = e.target.value; S.add.offset = 0; searchAdd(); });
    $('#mp-bulk').addEventListener('click', bulkAdd);
    syncBulk();
  };

  // ------------------------------------------------------------- add checks (search, multi-select)
  const searchAdd = async () => {
    const a = S.add;
    const qs = new URLSearchParams({ q: a.q, provider: a.prov, resource: a.resource, control: a.control, offset: a.offset, limit: PAGE, requirement_id: S.sel });
    try { a.res = await api.get(`/api/mappings/checks?${qs}`); } catch (e) { toast(e.message, 'err'); return; }
    const box = $('#mp-ares-list');
    if (!box) return;
    const r = a.res;
    box.innerHTML = `<div class="ck-add-list">${r.checks.map((k) => `<div class="ck-add-row mp-pick ${a.picked.has(k.id) ? 'on' : ''} ${k.linked ? 'linked' : ''}" data-pick="${esc(k.id)}">
        <span class="cb">${k.linked ? '' : icon('check')}</span><span class="cid">${esc(k.id)}</span>
        <div class="nm">${esc(k.name)} <span class="tag t-prov">${esc(k.provider)}</span>${(k.controls || []).slice(0, 4).map((c) => `<span class="tag mono">${esc(c)}</span>`).join('')}</div>
        ${k.linked ? '<span class="tag strong">linked</span>' : `<button class="btn sm" data-add1="${esc(k.id)}">${icon('plus')} Add</button>`}</div>`).join('') || '<p class="muted small">No checks match.</p>'}</div>
      <div class="row small muted" style="margin-top:8px"><span>${r.total ? `${r.offset + 1}–${Math.min(r.offset + PAGE, r.total)} of ${r.total}` : ''}</span><span class="spacer"></span>
        <button class="btn sm ghost" data-page="-1" ${r.offset ? '' : 'disabled'}>Prev</button><button class="btn sm ghost" data-page="1" ${r.offset + PAGE < r.total ? '' : 'disabled'}>Next</button></div>`;
  };

  const syncBulk = () => {
    const b = $('#mp-bulk');
    if (!b) return;
    b.disabled = !S.add.picked.size;
    b.innerHTML = `${icon('plus')} Add selected${S.add.picked.size ? ` (${S.add.picked.size})` : ''}`;
  };

  const addChecks = async (ids) => {
    const note = $('#mp-anote')?.value || '';
    let ok = 0;
    for (const cid of ids) {
      try { await includeCheckLink(S.sel, cid, 'global', null, note); ok += 1; } catch (e) { toast(`${cid}: ${e.message}`, 'err'); }
    }
    if (ok) toast(`${ok} check${ok === 1 ? '' : 's'} linked to ${S.sel} for all reviews`);
    ids.forEach((cid) => S.add.picked.delete(cid));
    await refresh();
  };

  async function bulkAdd() { if (S.add.picked.size) await addChecks([...S.add.picked]); }

  $('#mp-main').addEventListener('click', async (e) => {
    const t = e.target;
    const page = t.closest('[data-page]');
    if (page) { S.add.offset = Math.max(0, S.add.offset + +page.dataset.page * PAGE); searchAdd(); return; }
    const one = t.closest('[data-add1]');
    if (one) { one.disabled = true; await addChecks([one.dataset.add1]); return; }
    const pick = t.closest('[data-pick]');
    if (pick && !pick.classList.contains('linked')) {
      const cid = pick.dataset.pick;
      if (S.add.picked.has(cid)) S.add.picked.delete(cid); else S.add.picked.add(cid);
      pick.classList.toggle('on', S.add.picked.has(cid));
      syncBulk();
      return;
    }
    const row = t.closest('.check-row');
    const k = row && S.detail.checks.find((x) => x.id === row.dataset.check);
    if (t.closest('[data-cl="remove"]')) {
      const acts = row.querySelector('.ck-acts');
      if (acts.querySelector('.menu')) { acts.querySelector('.menu').remove(); return; }
      acts.insertAdjacentHTML('beforeend', `<div class="menu right ck-menu">
        <input class="input sm" data-rm-note placeholder="Why is it wrong here? (optional)" />
        <button data-rm>${icon('trash')}<span>Remove for all reviews<small>${k.auto ? 'Excludes this automatic link' : 'Unpins this reviewer link'}</small></span></button></div>`);
      acts.querySelector('[data-rm-note]').focus();
      return;
    }
    if (t.closest('[data-rm]')) {
      try {
        await removeCheckLink(S.sel, k, 'global', null, row.querySelector('[data-rm-note]')?.value || '');
        toast(`${k.id} removed from ${S.sel}`);
        await refresh();
      } catch (err) { toast(err.message, 'err'); }
      return;
    }
    if (t.closest('[data-cl="restore"]')) {
      try { await restoreCheckLink(S.sel, k, null); toast(`${k.id} restored`); await refresh(); } catch (err) { toast(err.message, 'err'); }
    }
  });

  // ------------------------------------------------------------- export / import
  $('#mp-export').addEventListener('click', () => { window.location.href = '/api/mappings/export'; });
  $('#mp-import').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    e.target.value = '';
    if (!file) return;
    const replace = await confirmDialog('Replace existing links?', 'Replace removes every reviewer link that applies to all reviews before importing. Cancel to merge the file into the existing links instead.', 'Replace');
    try {
      const res = await api.post('/api/mappings/import', { content: await file.text(), replace });
      toast(`Imported ${res.imported} link${res.imported === 1 ? '' : 's'}${res.skipped.length ? ` · ${res.skipped.length} skipped` : ''}`, res.skipped.length ? 'warn' : 'ok', 6000);
      await loadReqs();
      if (S.sel) await loadDetail();
    } catch (err) { toast(err.message, 'err'); }
  });

  await loadReqs();
}
