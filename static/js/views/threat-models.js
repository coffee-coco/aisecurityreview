// Threat models list: create one (optionally cloning a git repo), then open its workspace.
// A threat model is built from code and documents, then linked from one or more security reviews.
import { api } from '../api.js';
import { esc, icon, timeAgo, toast } from '../ui.js';

const ARTIFACTS = [
  ['threat_model', 'Threat Model'], ['attack_tree', 'Attack Tree'], ['dfd', 'Data Flow Diagram'],
  ['mitigations', 'Mitigations'], ['dread', 'DREAD'], ['test_cases', 'Test Cases'],
];

function sourceChip(s) {
  if (s.type === 'git') {
    const at = [s.ref, s.commit ? s.commit.slice(0, 8) : ''].filter(Boolean).join(' @ ');
    return `<span class="tag t-stack" title="${esc(s.url || '')}">${icon('code')} ${esc(s.name || 'Git repository')}${at ? ` · ${esc(at)}` : ''}</span>`;
  }
  const n = s.files ?? 0;
  return `<span class="tag" title="${esc(s.name || '')}">${icon(s.type === 'archive' ? 'package' : s.type === 'snippet' ? 'code' : 'file')} ${esc(s.type)} · ${n} file${n === 1 ? '' : 's'}</span>`;
}

function card(t) {
  const counts = t.counts || {};
  const cr = t.code_review || {};
  const linked = t.linked_reviews || [];
  const sources = t.sources || [];
  return `<article class="card tm-card" data-id="${t.id}" id="tm-card-${t.id}" tabindex="0" role="link" style="padding:16px;cursor:pointer">
    <div class="row" style="gap:8px;margin-bottom:6px"><span class="mono" style="color:var(--accent-2);font-size:12px">${esc(t.ref)}</span><span class="spacer"></span><span class="small muted">${timeAgo(t.updated_at)}</span></div>
    <h3 style="margin:0 0 6px;font-size:16px">${esc(t.title)}</h3>
    <p class="small muted" style="margin:0 0 10px;line-height:1.5">${esc((t.description || 'No description').slice(0, 180))}${(t.description || '').length > 180 ? '…' : ''}</p>
    <div class="row wrap" style="gap:6px;margin-bottom:10px">${sources.map(sourceChip).join('') || '<span class="small muted">No code linked yet</span>'}
      ${t.documents ? `<span class="tag">${icon('file')} ${t.documents} document${t.documents === 1 ? '' : 's'}</span>` : ''}</div>
    <div class="row wrap" style="gap:6px;margin-bottom:10px">${ARTIFACTS.map(([k, l]) => `<span class="chip" title="${t.updated?.[k] ? `Updated ${esc(timeAgo(t.updated[k]))}` : 'Not generated'}" style="${counts[k] ? '' : 'opacity:.5'}">${esc(l)} <b>${counts[k] || 0}</b></span>`).join('')}</div>
    <div class="small" style="margin-bottom:${linked.length ? 10 : 0}px">${icon('code')} Code review: ${cr.ran_at ? `<b>${cr.findings ?? 0}</b> finding${cr.findings === 1 ? '' : 's'}` : '<span class="muted">not run</span>'}</div>
    ${linked.length ? `<div class="row wrap" style="gap:6px"><span class="small muted">Linked to</span>${linked.map((r) => `<a class="chip ctrl" href="#/review/${r.id}" title="${esc(r.title)}">${esc(r.ref)}</a>`).join('')}</div>` : ''}
  </article>`;
}

export async function render(root) {
  root.innerHTML = `
  <div class="page">
    <div class="page-head">
      <div>
        <div class="eyebrow">${icon('target')} Threat modelling</div>
        <h1><span class="grad-text">Threat</span> models</h1>
        <p>Link a git repository or upload code, then generate a threat model, attack tree, data flow diagram, mitigations, DREAD scores and test cases. Link the threat model to one or more security reviews, where its findings can be promoted to risks and controls.</p>
      </div>
    </div>
    <form class="card" id="tm-new-form" autocomplete="off" style="padding:20px;margin-bottom:22px">
      <h2 class="section-title">${icon('plus')} New threat model</h2>
      <div class="stack" style="gap:12px">
        <div class="grid-2" style="gap:12px">
          <div class="field"><label for="tmn-title">Name</label><input class="input" id="tmn-title" required minlength="3" maxlength="200" placeholder="e.g. Payments API" /></div>
          <div class="field"><label for="tmn-desc">Description</label><input class="input" id="tmn-desc" placeholder="What the system does (optional)" /></div>
        </div>
        <div class="grid-2" style="grid-template-columns:2fr 1fr 1fr;gap:12px">
          <div class="field"><label for="tmn-url">Git repository URL <span class="muted">(optional)</span></label><input class="input" id="tmn-url" placeholder="https://github.com/owner/repo" /></div>
          <div class="field"><label for="tmn-ref">Branch or tag</label><input class="input" id="tmn-ref" placeholder="Default branch" /></div>
          <div class="field"><label for="tmn-token">Access token</label><input class="input" id="tmn-token" type="password" placeholder="Private repos only" /></div>
        </div>
        <div class="row"><span class="small muted">The repository is cloned shallow and read-only. The token is used for this clone only and is never stored. You can also upload code later.</span><span class="spacer"></span>
          <button class="btn primary" type="submit" id="tmn-submit">${icon('plus')} Create threat model</button></div>
      </div>
    </form>
    <div id="tm-list"><div class="loading"><span class="spin"></span>Loading…</div></div>
  </div>`;

  const listEl = root.querySelector('#tm-list');
  const draw = (rows) => {
    if (!rows.length) {
      listEl.innerHTML = `<div class="card empty"><div class="ic">${icon('target')}</div><h3>No threat models yet</h3>
        <p>Create one above. Start from a git repository or upload code so threats can cite real files.</p></div>`;
      return;
    }
    listEl.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:14px">${rows.map(card).join('')}</div>`;
  };
  const open = (id) => { location.hash = `#/threat-model/${id}`; };
  listEl.addEventListener('click', (e) => {
    if (e.target.closest('a')) return;
    const c = e.target.closest('[data-id]'); if (c) open(c.dataset.id);
  });
  listEl.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || e.target.closest('a')) return;
    const c = e.target.closest('[data-id]'); if (c) open(c.dataset.id);
  });

  const form = root.querySelector('#tm-new-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = root.querySelector('#tmn-submit');
    const url = root.querySelector('#tmn-url').value.trim();
    btn.disabled = true;
    let tm;
    try {
      tm = await api.post('/api/threat-models', {
        title: root.querySelector('#tmn-title').value.trim(),
        description: root.querySelector('#tmn-desc').value.trim(),
      });
    } catch (err) { toast(err.message, 'err', 6000); btn.disabled = false; return; }
    if (url) {
      btn.innerHTML = '<span class="spin"></span> Cloning…';
      try {
        await api.post(`/api/reviews/${tm.id}/code/git`, { url, ref: root.querySelector('#tmn-ref').value.trim(), token: root.querySelector('#tmn-token').value });
      } catch (err) { toast(`Threat model created, but the clone failed: ${err.message}`, 'err', 9000); }
    }
    toast(`${tm.ref} created`);
    open(tm.id);
  });

  try { draw(await api.get('/api/threat-models')); } catch (e) {
    listEl.innerHTML = `<div class="card empty"><div class="ic">${icon('alert')}</div><h3>Could not load threat models</h3><p>${esc(e.message)}</p></div>`;
  }
}
