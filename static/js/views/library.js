import { api, getMeta, getTree } from '../api.js';
import { FN_COLOR, debounce, esc, icon, openOverlay } from '../ui.js';
import { checkRow, checkRowStatic, openControlDrawer } from './shared.js';

export async function render(root) {
  const [meta, tree] = await Promise.all([getMeta(), getTree()]);
  const frameworks = meta.frameworks || [];
  const fnInfo = Object.fromEntries((meta.functions || []).map((f) => [f.id, f]));
  const fwOfFn = (id) => fnInfo[id]?.framework || 'csf';
  const col = (id) => (fnInfo[id]?.color ? `var(--${fnInfo[id].color})` : FN_COLOR(id));
  let tab = 'csf';
  let fw = 'csf';
  let fn = tree[0].id;
  let q = '';

  root.innerHTML = `<div class="page">
    <div class="page-head">
      <div>
        <div class="eyebrow">${icon('book')} Knowledge base</div>
        <h1>Control <span class="grad-text">library</span></h1>
        <p>Browse how each NIST CSF 2.0 outcome maps to SP 800-53 Rev 5 controls (NIST's official mapping) and on to Checkov technical checks, plus the NIST AI RMF and OWASP requirement frameworks.</p>
      </div>
      <div class="seg lg" id="lib-tabs">
        <button data-t="csf" class="on" id="lib-tab-csf">${icon('target')} Requirements → controls</button>
        <button data-t="checks" id="lib-tab-checks">${icon('code')} Checkov checks</button>
      </div>
    </div>
    <div id="lib-body"></div>
  </div>`;

  const drawCSF = () => {
    const fns = tree.filter((x) => fwOfFn(x.id) === fw);
    const f = fns.find((x) => x.id === fn) || fns[0];
    fn = f.id;
    const ql = q.toLowerCase();
    const body = root.querySelector('#lib-body');
    body.innerHTML = `<div class="lib-grid">
      <div class="fn-nav">
        ${frameworks.length > 1 ? `<select class="select" id="lib-fw" style="margin-bottom:8px" aria-label="Framework">${frameworks.map((x) => `<option value="${esc(x.id)}" ${x.id === fw ? 'selected' : ''}>${esc(x.name)} ${esc(x.version || '')}</option>`).join('')}</select>` : ''}
        <div class="search" style="margin-bottom:8px">${icon('search')}<input class="input" id="lib-q" placeholder="Search outcomes…" value="${esc(q)}" /></div>
        ${fns.map((x) => `<div class="fn-card ${x.id === fn ? 'on' : ''}" data-fn="${x.id}" style="--c:${col(x.id)}" id="lib-fn-${x.id}">
          <div class="t"><span class="id">${x.id}</span>${esc(x.title)}<span class="spacer"></span><span class="badge">${x.categories.reduce((a, c) => a + c.subcategories.length, 0)}</span></div>
          <small>${esc(x.text)}</small></div>`).join('')}
      </div>
      <div style="--c:${col(f.id)}">
        ${f.categories.map((c) => {
          const subs = c.subcategories.filter((s) => !ql || `${s.id} ${s.text} ${s.question} ${s.controls.map((x) => x.id).join(' ')}`.toLowerCase().includes(ql));
          if (!subs.length) return '';
          return `<div class="cat-block"><h3><span class="id">${c.id}</span>${esc(c.title)}</h3><p>${esc(c.text)}</p>
            ${subs.map((s) => `<div class="sub-row" data-sid="${s.id}" id="lib-sub-${s.id}">
              <span class="id">${s.id}</span>
              <div><div class="o">${esc(s.text)}</div><div class="q">${icon('message', '').replace('<svg', '<svg style="width:12px;height:12px;vertical-align:-2px;margin-right:4px"')}${esc(s.question)}</div>
                <div class="chips" style="margin-top:8px">${s.controls.map((x) => `<span class="chip ctrl" data-ctrl="${esc(x.id)}" title="${esc(x.title)}">${esc(x.id)}</span>`).join('')}</div></div>
              <div class="cnt"><b>${s.check_count}</b>checks<br><span class="badge" style="margin-top:6px">${s.scope}</span></div>
            </div>`).join('')}</div>`;
        }).join('') || '<div class="card empty"><p>No outcomes match your search in this function.</p></div>'}
      </div></div>`;
    body.querySelectorAll('.fn-card').forEach((c) => c.addEventListener('click', () => { fn = c.dataset.fn; drawCSF(); }));
    body.querySelector('#lib-fw')?.addEventListener('change', (e) => { fw = e.target.value; drawCSF(); });
    body.querySelector('#lib-q').addEventListener('input', debounce((e) => {
      q = e.target.value;
      // jump to the first function with a hit
      const ql2 = q.toLowerCase();
      const hit = fns.find((x) => x.categories.some((c) => c.subcategories.some((s) => `${s.id} ${s.text} ${s.question}`.toLowerCase().includes(ql2))));
      if (hit && q) fn = hit.id;
      drawCSF();
      const inp = root.querySelector('#lib-q'); inp.focus(); inp.setSelectionRange(q.length, q.length);
    }, 250));
    body.querySelectorAll('[data-ctrl]').forEach((c) => c.addEventListener('click', (e) => { e.stopPropagation(); openControlDrawer(c.dataset.ctrl); }));
    body.querySelectorAll('.sub-row').forEach((row) => row.addEventListener('click', () => openSubDrawer(row.dataset.sid)));
  };

  const openSubDrawer = async (sid) => {
    const providers = meta.providers.map((p) => p.name);
    const { el } = openOverlay(`<div class="drawer-head"><div style="flex:1" id="sd-head"></div><button class="btn ghost icon" data-close>${icon('x')}</button></div>
      <div class="drawer-body"><div class="loading"><span class="spin"></span>Loading…</div></div>`);
    let prov = 'AWS';
    let showRelated = false;
    const load = async () => {
      const res = await api.get(`/api/catalog/subcategories/${sid}/checks?providers=${encodeURIComponent(prov)}`);
      const s = res.subcategory;
      const c = col(s.function_id);
      el.querySelector('#sd-head').innerHTML = `<div class="eyebrow" style="color:${c}">${esc(s.function_title)} · ${esc(s.category_title)}</div>
        <h2><span class="mono" style="color:${c};font-size:15px">${s.id}</span> ${esc(s.text)}</h2>`;
      const list = showRelated ? res.checks : res.checks.filter((k) => k.strength === 'strong');
      el.querySelector('.drawer-body').innerHTML = `
        <div class="question" style="--c:${c}"><div class="lbl">Review question</div><p>${esc(s.question)}</p></div>
        ${s.examples.length ? `<details class="ex" style="margin-bottom:16px"><summary>${icon('info')} ${fwOfFn(s.function_id) === 'csf' ? 'NIST implementation examples' : 'Implementation examples'} (${s.examples.length})</summary><ul class="examples">${s.examples.map((e) => `<li>${esc(e)}</li>`).join('')}</ul></details>` : ''}
        <h2 class="section-title">${icon('shield')} SP 800-53 Rev 5 controls</h2>
        <div class="chips" style="margin-bottom:22px">${s.controls.map((c) => `<span class="chip ctrl" data-ctrl="${esc(c.id)}">${esc(c.id)} <span style="font-family:var(--font);color:var(--muted)">${esc(c.title)}</span></span>`).join('')}</div>
        <div class="checks-head"><h4>${icon('code')} Checkov checks <span class="badge">${list.length}</span></h4><span class="spacer"></span>
          <label class="row small muted" style="gap:6px;cursor:pointer"><span class="switch" style="transform:scale(.85)"><input type="checkbox" id="sd-related" ${showRelated ? 'checked' : ''}/><span></span></span>Related</label>
          <select class="select sm" id="sd-prov" style="width:180px">${providers.map((p) => `<option ${p === prov ? 'selected' : ''}>${esc(p)}</option>`).join('')}</select></div>
        <div class="check-list">${list.map((k) => checkRow(k, { editable: false })).join('') || '<p class="muted small">No checks for this platform — this outcome is mainly met through process controls.</p>'}</div>`;
      el.querySelector('#sd-prov').addEventListener('change', (e) => { prov = e.target.value; load(); });
      el.querySelector('#sd-related').addEventListener('change', (e) => { showRelated = e.target.checked; load(); });
      el.querySelectorAll('[data-ctrl]').forEach((c) => c.addEventListener('click', () => openControlDrawer(c.dataset.ctrl)));
    };
    load();
  };

  const drawChecks = () => {
    const body = root.querySelector('#lib-body');
    body.innerHTML = `<div class="toolbar">
        <div class="search" style="width:380px">${icon('search')}<input class="input" id="ck-q" placeholder="Search check id, name or resource (e.g. s3, CKV_AWS_19)…" /></div>
        <select class="select" id="ck-prov" style="width:200px"><option value="">All platforms</option>${meta.providers.map((p) => `<option value="${esc(p.name)}">${esc(p.name)} (${p.count})</option>`).join('')}</select>
        <input class="input" id="ck-ctrl" placeholder="800-53 control e.g. SC-28" style="width:200px" />
        <span class="spacer"></span><span class="muted small" id="ck-count"></span>
      </div><div class="check-list" id="ck-list"></div>`;
    const run = async () => {
      const qs = new URLSearchParams({ q: body.querySelector('#ck-q').value, provider: body.querySelector('#ck-prov').value, control: body.querySelector('#ck-ctrl').value.toUpperCase().trim(), limit: 300 });
      const list = await api.get(`/api/catalog/checks?${qs}`);
      body.querySelector('#ck-count').textContent = `${list.length}${list.length === 300 ? '+' : ''} checks`;
      body.querySelector('#ck-list').innerHTML = list.map(checkRowStatic).join('') || '<div class="card empty"><p>No checks match.</p></div>';
    };
    body.querySelector('#ck-q').addEventListener('input', debounce(run, 250));
    body.querySelector('#ck-ctrl').addEventListener('input', debounce(run, 300));
    body.querySelector('#ck-prov').addEventListener('change', run);
    run();
  };

  root.querySelectorAll('#lib-tabs button').forEach((b) => b.addEventListener('click', () => {
    tab = b.dataset.t;
    root.querySelectorAll('#lib-tabs button').forEach((x) => x.classList.toggle('on', x === b));
    tab === 'csf' ? drawCSF() : drawChecks();
  }));
  drawCSF();
}
