// Code & repository tab (threat model page): link a git repo or upload snippets, files or zips; run a holistic
// whole-codebase review (AI + cross-file heuristics) alongside static rules and real Checkov on infrastructure as code.
// Findings feed linked security reviews, where they can be promoted to risks.
import { api, upload } from '../api.js';
import { cap, confirmDialog, esc, icon, openOverlay, timeAgo, toast } from '../ui.js';
import { CODE_ACCEPT, dropzone, fmtSize, wireDrop } from './upload.js';

const LANGS = ['python', 'javascript', 'typescript', 'java', 'go', 'csharp', 'ruby', 'php', 'kotlin', 'rust', 'terraform', 'bicep', 'yaml', 'json', 'dockerfile', 'shell', 'sql', 'html', 'text'];
const LANG_COLORS = ['#8b5cf6', '#22d3ee', '#f472b6', '#fbbf24', '#34d399', '#60a5fa', '#fb923c', '#a78bfa', '#2dd4bf', '#f87171', '#94a3b8', '#e879f9'];
const SRC = { ai: ['sparkles', 'AI holistic'], holistic: ['layers', 'Cross-file'], rule: ['search', 'Static rule'], checkov: ['shield', 'Checkov'] };
const SEVS = ['critical', 'high', 'medium', 'low'];

function state(ctx) { return (ctx.ui.code ||= { sev: '', src: '', open: new Set(), ai: true, checkov: true }); }

export function render(el, ctx) {
  const S = state(ctx);
  const r = ctx.r;
  const sources = (r.documents || []).filter((d) => d.kind === 'code');
  const running = ctx.runningJob('code_review');
  el.innerHTML = `
    <div class="grid-2" style="grid-template-columns:1.15fr 1fr;gap:14px;margin-bottom:14px" id="code-top">
      <section class="card" style="padding:18px">
        <h2 class="section-title">${icon('upload')} Add code</h2>
        ${dropzone({ id: 'code-drop', accept: CODE_ACCEPT, title: 'Drop a repository zip or source files', sub: 'Zips are safely unpacked (zip-slip, symlink and size limits) · vendored & build folders skipped', iconName: 'package', sm: true })}
        <details class="ex" style="margin-top:12px" ${sources.length ? '' : 'open'}><summary>${icon('package')} Link a git repository</summary>
          <div class="stack" style="gap:8px;margin-top:10px">
            <input class="input sm" id="git-url" placeholder="https://github.com/owner/repo" autocomplete="off" />
            <div class="row"><input class="input sm" id="git-ref" placeholder="Branch or tag (default branch if blank)" style="flex:1" autocomplete="off" />
              <input class="input sm" id="git-token" type="password" placeholder="Access token (private repos only)" style="flex:1" autocomplete="off" /></div>
            <div class="small muted">Shallow, read-only clone with the same limits as a zip. The token is used for this clone only and is never stored. Linking the same URL again refreshes it.</div>
            <div class="row"><span class="spacer"></span><button class="btn sm" id="git-add">${icon('plus')} Link repository</button></div>
          </div></details>
        <details class="ex" style="margin-top:12px" ${sources.length ? '' : 'open'}><summary>${icon('code')} Paste a snippet</summary>
          <div class="stack" style="gap:8px;margin-top:10px">
            <div class="row"><input class="input sm" id="snip-name" placeholder="Name, e.g. auth_handler" style="flex:1" />
              <select class="select sm" id="snip-lang" style="width:150px">${LANGS.map((l) => `<option value="${l}">${cap(l)}</option>`).join('')}</select></div>
            <textarea class="textarea" id="snip-code" rows="7" placeholder="Paste code…" style="font-family:var(--mono);font-size:12px"></textarea>
            <div class="row"><span class="spacer"></span><button class="btn sm" id="snip-add">${icon('plus')} Add snippet</button></div>
          </div></details>
      </section>
      <section class="card" style="padding:18px;display:flex;flex-direction:column">
        <h2 class="section-title">${icon('package')} Sources <span class="badge" style="margin-left:6px">${sources.length}</span></h2>
        <div class="stack" style="gap:6px;flex:1">${sources.map((d) => `<div class="source-row" id="src-${d.id}"><span class="ic">${icon(d.meta?.type === 'archive' ? 'package' : d.meta?.type === 'snippet' ? 'code' : 'file')}</span>
          <div class="n"><b>${esc(d.filename)}</b><small>${d.meta?.type === 'git' ? `<span title="${esc(d.meta.url || '')}">Git ${esc(d.meta.ref || '')}${d.meta.commit ? ` @ ${esc(d.meta.commit.slice(0, 8))}` : ''}</span>` : esc(cap(d.meta?.type || 'files'))} · ${d.meta?.files ?? '?'} file${d.meta?.files === 1 ? '' : 's'} · ${fmtSize(d.size)}${d.meta?.skipped ? ` · ${d.meta.skipped} skipped` : ''}</small></div>
          <button class="btn sm ghost icon danger" data-src-del="${d.id}" title="Remove">${icon('trash')}</button></div>`).join('') || '<p class="small muted" style="margin:0">No code uploaded yet. Single snippets work too — the review still considers the threat model profile and design.</p>'}</div>
        <div class="opt-row" style="margin:14px 0 12px">
          <label><span class="switch"><input type="checkbox" id="opt-ai" ${S.ai ? 'checked' : ''} /><span></span></span>AI whole-codebase review</label>
          <label><span class="switch"><input type="checkbox" id="opt-ck" ${S.checkov ? 'checked' : ''} /><span></span></span>Checkov on IaC</label>
        </div>
        <button class="btn primary" id="code-run" ${sources.length && !running ? '' : 'disabled'} style="width:100%">${running ? '<span class="spin"></span> Reviewing…' : `${icon('sparkles')} ${r.code_review?.ran_at ? 'Re-run code review' : 'Run code review'}`}</button>
      </section>
    </div>
    <section class="card code-panel glow" style="padding:18px" id="code-results"></section>`;

  drawResults(el, ctx);

  wireDrop(el.querySelector('#code-drop'), (files) => send(el, ctx, files));
  el.querySelector('#snip-add').addEventListener('click', () => {
    const code = el.querySelector('#snip-code').value;
    if (!code.trim()) { toast('Paste some code first', 'warn'); return; }
    send(el, ctx, [], { snippet: code, snippet_name: el.querySelector('#snip-name').value || 'snippet', language: el.querySelector('#snip-lang').value });
  });
  el.querySelector('#git-add').addEventListener('click', (e) => linkRepo(el, ctx, e.currentTarget));
  el.querySelector('#opt-ai').addEventListener('change', (e) => { S.ai = e.target.checked; });
  el.querySelector('#opt-ck').addEventListener('change', (e) => { S.checkov = e.target.checked; });
  el.querySelector('#code-run').addEventListener('click', () => run(ctx));
  el.querySelectorAll('[data-src-del]').forEach((b) => b.addEventListener('click', async () => {
    const d = sources.find((x) => x.id === +b.dataset.srcDel);
    if (!(await confirmDialog(`Remove ${d.filename}?`, 'The uploaded code is deleted. Existing findings stay until you re-run the review.', 'Remove'))) return;
    try { ctx.set(await api.del(`/api/reviews/${r.id}/documents/${d.id}`)); } catch (err) { toast(err.message, 'err'); }
  }));
}

async function send(el, ctx, files, snippet) {
  const fd = new FormData();
  files.forEach((f) => fd.append('files', f));
  if (snippet) Object.entries(snippet).forEach(([k, v]) => fd.append(k, v));
  const zone = el.querySelector('#code-drop');
  zone.querySelector('[data-pills]').innerHTML = files.map((f) => `<span class="chip"><span class="spin" style="width:10px;height:10px;border-width:2px"></span>${esc(f.name)}</span>`).join('');
  try {
    const res = await upload(`/api/reviews/${ctx.r.id}/code`, fd);
    res.rejected.forEach((m) => toast(m, 'warn', 7000));
    ctx.set(res.review);
    if (res.added.length) { toast('Code added — starting the review…'); run(ctx); }
  } catch (e) { toast(e.message, 'err'); zone.querySelector('[data-pills]').innerHTML = ''; }
}

async function linkRepo(el, ctx, btn) {
  const url = el.querySelector('#git-url').value.trim();
  if (!url) { toast('Enter the repository URL', 'warn'); return; }
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Cloning…';
  try {
    const res = await api.post(`/api/reviews/${ctx.r.id}/code/git`, { url, ref: el.querySelector('#git-ref').value.trim(), token: el.querySelector('#git-token').value });
    ctx.set(res.review);
    toast('Repository linked — starting the review…');
    run(ctx);
  } catch (e) {
    toast(e.message, 'err', 8000);
    btn.disabled = false; btn.innerHTML = `${icon('plus')} Link repository`;
  }
}

async function run(ctx) {
  const S = state(ctx);
  try {
    const { job_id } = await api.post(`/api/reviews/${ctx.r.id}/code/review`, { ai: S.ai, checkov: S.checkov });
    ctx.trackJob({ id: job_id, kind: 'code_review', message: 'Queued…', progress: 0 });
    const b = ctx.root.querySelector('#code-run');
    if (b) { b.disabled = true; b.innerHTML = '<span class="spin"></span> Reviewing…'; }
  } catch (e) { toast(e.message, 'err'); }
}

// ------------------------------------------------------------------ results
function drawResults(el, ctx) {
  const S = state(ctx);
  const box = el.querySelector('#code-results');
  const cr = ctx.r.code_review || {};
  if (!cr.ran_at) {
    box.innerHTML = `<div class="empty" style="padding:34px 20px"><div class="ic">${icon('code')}</div><h3>No code review yet</h3>
      <p>Checkov secures individual resources. This review looks at the codebase <b>as a whole</b> — authentication across routes, data flows,<br>secrets, AI guardrails, missing rate limiting. Findings feed the security reviews that link this threat model,<br>where they can be promoted to risks.</p></div>`;
    return;
  }
  const inv = cr.inventory || {};
  const ck = cr.checkov || {};
  const f = cr.findings || [];
  const bySev = Object.fromEntries(SEVS.map((s) => [s, f.filter((x) => x.severity === s).length]));
  const bySrc = Object.fromEntries(Object.keys(SRC).map((s) => [s, f.filter((x) => x.source === s).length]));
  const shown = f.filter((x) => (!S.sev || x.severity === S.sev) && (!S.src || x.source === S.src));
  const v = ctx.meta.profile;
  const sys = (cr.system_types || []).map((s) => v.system_types.find((x) => x.id === s)?.label || s);
  const newSys = (cr.system_types || []).filter((s) => !(ctx.r.system_types || []).includes(s));
  const cov = cr.coverage || {};
  const arch = cr.architecture || {};

  box.innerHTML = `
    <div class="head" style="margin-bottom:12px"><span class="spark">${icon('sparkles')}</span>
      <div style="flex:1;min-width:0"><h2 class="section-title" style="margin:0">Whole-codebase security review</h2>
      <div class="small muted">${esc(cr.provider === 'heuristic' ? 'Static rules + cross-file heuristics' : `AI review by ${cr.provider}`)} · ${timeAgo(cr.ran_at)} · ${cov.files_reviewed ? `${cov.files_reviewed}/${cov.files_total} files read by AI (${esc(cov.mode)})` : `${inv.files || 0} files scanned`}</div></div></div>
    ${(cr.warnings || []).map((w) => `<div class="warning">${icon('alert')}<div>${esc(w)}</div></div>`).join('')}
    <div class="code-sum">
      <div>
        <p class="summary" style="margin-top:0">${esc(cr.summary || '')}</p>
        ${sys.length ? `<div class="row wrap" style="margin-bottom:12px"><span class="small muted">Looks like</span>${sys.map((s) => `<span class="badge">${icon('layers')} ${esc(s)}</span>`).join('')}
          ${newSys.length || (cr.data_types || []).some((d) => !(ctx.r.data_types || []).includes(d)) ? `<button class="btn sm" id="code-apply">${icon('target')} Apply to profile</button>` : ''}</div>` : ''}
        ${Object.keys(arch).length ? `<div class="kv">${Object.entries(arch).filter(([, x]) => (Array.isArray(x) ? x.length : x)).map(([k, x]) => `<span>${esc(cap(k))}</span><div class="chips">${(Array.isArray(x) ? x : [x]).map((y) => `<span class="chip">${esc(typeof y === 'string' ? y : JSON.stringify(y))}</span>`).join('')}</div>`).join('')}</div>` : ''}
      </div>
      <div class="card tight" style="background:rgba(5,8,16,0.35)">
        <div class="row"><b style="font-size:20px">${(inv.files || 0).toLocaleString()}</b><span class="small muted">files</span><b style="font-size:20px;margin-left:10px">${(inv.lines || 0).toLocaleString()}</b><span class="small muted">lines</span>
          <span class="spacer"></span><button class="btn sm ghost" id="code-browse">${icon('eye')} Browse</button></div>
        <div class="lang-bar">${(inv.languages || []).map((l, k) => `<i style="width:${l.pct}%;background:${LANG_COLORS[k % LANG_COLORS.length]}" title="${esc(l.name)} ${l.pct}%"></i>`).join('')}</div>
        <div class="lang-legend">${(inv.languages || []).slice(0, 8).map((l, k) => `<span><i style="background:${LANG_COLORS[k % LANG_COLORS.length]}"></i>${esc(l.name)} <span class="muted">${l.pct}%</span></span>`).join('')}</div>
        <div class="kv" style="margin-top:12px;grid-template-columns:96px 1fr">
          ${(inv.frameworks || []).length ? `<span>Frameworks</span><div class="chips">${inv.frameworks.slice(0, 12).map((x) => `<span class="chip ${(inv.ai_frameworks || []).includes(x) ? 'tog on' : ''}">${esc(x)}</span>`).join('')}</div>` : ''}
          ${(inv.iac || []).length ? `<span>IaC</span><div class="chips">${inv.iac.map((x) => `<span class="chip">${esc(x.type)} · ${x.files}</span>`).join('')}</div>` : ''}
          <span>Routes</span><div>${(inv.routes || []).length} HTTP route${(inv.routes || []).length === 1 ? '' : 's'} · ${inv.dependency_count || 0} dependencies</div>
          <span>Checkov</span><div>${ck.ran ? `<span style="color:#fda4af">${ck.failed} failed</span> · <span style="color:#6ee7b7">${ck.passed} passed</span>${(ck.frameworks || []).length ? ` · ${esc(ck.frameworks.join(', '))}` : ''}` : `<span class="muted">${esc(ck.error || 'not run')}</span>`}</div>
        </div>
      </div>
    </div>
    <div class="sev-row" style="margin-bottom:12px">${SEVS.map((s) => `<div class="sev-box ${S.sev === s ? 'on' : ''}" data-sev="${s}" style="--c:${{ critical: '#f43f5e', high: '#fb923c', medium: '#fbbf24', low: '#34d399' }[s]}" id="sev-${s}"><b>${bySev[s]}</b><span>${s}</span></div>`).join('')}</div>
    <div class="row wrap" style="margin-bottom:10px"><div class="filters">
      <button class="filt ${!S.src ? 'on' : ''}" data-src="">All sources<span class="n">${f.length}</span></button>
      ${Object.entries(SRC).filter(([k]) => bySrc[k]).map(([k, [, l]]) => `<button class="filt ${S.src === k ? 'on' : ''}" data-src="${k}">${l}<span class="n">${bySrc[k]}</span></button>`).join('')}</div>
      <span class="spacer"></span><span class="small muted">${shown.length} finding${shown.length === 1 ? '' : 's'}</span></div>
    <div id="findings">${shown.map((x) => findingHTML(S, x)).join('') || '<div class="empty" style="padding:24px"><p>No findings for this filter.</p></div>'}</div>
    ${(cr.strengths || []).length || (cr.open_questions || []).length ? `<div class="grid-2" style="margin-top:14px">
      ${(cr.strengths || []).length ? `<div><h3 class="label" style="margin:0 0 6px;color:#6ee7b7">Strengths observed</h3>${cr.strengths.map((s) => `<div class="q-row">${icon('check')}<div class="x">${esc(s)}</div></div>`).join('')}</div>` : '<div></div>'}
      ${(cr.open_questions || []).length ? `<div><h3 class="label" style="margin:0 0 6px">Questions for the team</h3>${cr.open_questions.map((q) => `<div class="q-row">${icon('message')}<div class="x">${esc(q)}</div></div>`).join('')}</div>` : ''}
    </div>` : ''}`;

  box.querySelectorAll('[data-sev]').forEach((b) => b.addEventListener('click', () => { S.sev = S.sev === b.dataset.sev ? '' : b.dataset.sev; drawResults(el, ctx); }));
  box.querySelectorAll('[data-src]').forEach((b) => b.addEventListener('click', () => { S.src = b.dataset.src; drawResults(el, ctx); }));
  box.querySelector('#code-browse')?.addEventListener('click', () => browse(ctx));
  box.querySelector('#code-apply')?.addEventListener('click', async () => {
    try {
      const fresh = await api.post(`/api/reviews/${ctx.r.id}/design/apply`, { fields: ['system_types', 'data_types', 'flags'], source: 'code', rescope: false });
      ctx.set(fresh);
      toast('Profile updated from the code review');
    } catch (e) { toast(e.message, 'err'); }
  });
  const fl = box.querySelector('#findings');
  fl.addEventListener('click', (e) => {
    const card = e.target.closest('.finding'); if (!card) return;
    const fid = card.dataset.fid;
    const x = f.find((y) => y.id === fid);
    const ev = e.target.closest('[data-ev]');
    if (ev) { const it = x.evidence[+ev.dataset.ev]; openFile(ctx, it.file, it.line); return; }
    if (e.target.closest('.finding-head')) {
      if (S.open.has(fid)) S.open.delete(fid); else S.open.add(fid);
      card.outerHTML = findingHTML(S, x);
    }
  });
}

function findingHTML(S, x) {
  const open = S.open.has(x.id);
  const files = [...new Set((x.evidence || []).map((e) => e.file))];
  const [si, sl] = SRC[x.source] || ['info', x.source];
  return `<div class="finding sev-${x.severity} ${open ? 'open' : ''}" data-fid="${esc(x.id)}" id="f-${esc(x.id).replace(/[^a-zA-Z0-9_-]/g, '_')}">
    <div class="finding-head"><span class="sev">${esc(x.severity)}</span>
      <div class="t">${esc(x.title)}<small>${esc(cap(x.category || ''))}${x.occurrences ? ` · ${x.occurrences} occurrence${x.occurrences === 1 ? '' : 's'}` : ''}${files.length ? ` · ${files.length} file${files.length === 1 ? '' : 's'}` : ''}${x.rule ? ` · ${esc(x.rule)}` : ''}</small></div>
      <span class="src ${x.source}">${icon(si)}${sl}</span>
      ${icon('chevron', 'chev')}</div>
    ${open ? `<div class="finding-body">
      <p style="margin:0 0 8px">${esc(x.description || '')}</p>
      ${x.recommendation ? `<div class="apply-row" style="margin:8px 0">${icon('bulb')}<div class="x"><b>Fix:</b> ${esc(x.recommendation)}</div></div>` : ''}
      ${(x.evidence || []).length ? `<div class="evidence">${x.evidence.slice(0, 12).map((e, k) => `<div class="ev" data-ev="${k}" title="Open file"><span class="f">${esc(e.file)}${e.line ? `:${e.line}` : ''}</span><span class="s">${esc(e.snippet || '')}</span></div>`).join('')}
        ${x.evidence.length > 12 ? `<span class="small muted">+${x.evidence.length - 12} more</span>` : ''}</div>` : ''}
      <div class="row wrap" style="gap:6px">
        ${(x.csf || []).map((c) => `<span class="chip" style="font-family:var(--mono);font-size:11px">${esc(c)}</span>`).join('')}
        ${(x.nist || []).map((c) => `<span class="chip" style="font-family:var(--mono);font-size:11px;color:#a5f3fc">${esc(c)}</span>`).join('')}
      </div></div>` : ''}
  </div>`;
}

// ------------------------------------------------------------------ file viewer
async function openFile(ctx, path, line) {
  const { el } = openOverlay(`<div class="drawer-head"><div style="flex:1;min-width:0"><div class="eyebrow">${icon('code')} Source</div>
    <h2 class="mono" style="font-size:14px;overflow:hidden;text-overflow:ellipsis">${esc(path)}${line ? `<span class="muted">:${line}</span>` : ''}</h2></div>
    <button class="btn ghost icon" data-close>${icon('x')}</button></div><div class="drawer-body"><div class="loading"><span class="spin"></span>Loading…</div></div>`);
  el.style.width = 'min(960px, 96vw)';
  try {
    const res = await fetch(`/api/reviews/${ctx.r.id}/code/file?path=${encodeURIComponent(path)}`);
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'File not available');
    const text = await res.text();
    const lines = text.split('\n');
    el.querySelector('.drawer-body').innerHTML = `<div class="code-view">${lines.map((l, k) => `<div class="ln ${k + 1 === line ? 'hl' : ''}" ${k + 1 === line ? 'id="hl-line"' : ''}><span>${k + 1}</span><span>${esc(l) || ' '}</span></div>`).join('')}</div>`;
    setTimeout(() => el.querySelector('#hl-line')?.scrollIntoView({ block: 'center' }), 50);
  } catch (e) { el.querySelector('.drawer-body').innerHTML = `<p class="muted">${esc(e.message)}</p>`; }
}

async function browse(ctx) {
  const { el } = openOverlay(`<div class="drawer-head"><div style="flex:1"><h2>${icon('package')} Files reviewed</h2></div><button class="btn ghost icon" data-close>${icon('x')}</button></div>
    <div style="padding:14px 24px 0"><div class="search">${icon('search')}<input class="input" id="fb-q" placeholder="Filter files…" autofocus /></div></div>
    <div class="drawer-body" id="fb-list"><div class="loading"><span class="spin"></span>Loading…</div></div>`);
  const { files } = await api.get(`/api/reviews/${ctx.r.id}/code/files`);
  const flagged = new Set((ctx.r.code_review?.findings || []).flatMap((f) => (f.evidence || []).map((e) => e.file)));
  const draw = (q = '') => {
    const ql = q.toLowerCase();
    const list = files.filter((f) => !ql || f.path.toLowerCase().includes(ql)).slice(0, 600);
    el.querySelector('#fb-list').innerHTML = `<div class="pick-list">${list.map((f) => `<div class="pick-item" data-path="${esc(f.path)}" style="grid-template-columns:18px minmax(0,1fr) auto">
      <span style="color:${flagged.has(f.path) ? '#fb923c' : 'var(--muted)'}">${icon(flagged.has(f.path) ? 'alert' : 'file')}</span>
      <div style="min-width:0"><div class="t mono" style="font-size:12px;overflow:hidden;text-overflow:ellipsis">${esc(f.path)}</div></div>
      <span class="small muted">${esc(f.lang || '')} · ${f.lines}</span></div>`).join('')}</div>${files.length > list.length && !ql ? `<p class="small muted">Showing ${list.length} of ${files.length} — filter to find more.</p>` : ''}`;
  };
  draw();
  el.querySelector('#fb-q').addEventListener('input', (e) => draw(e.target.value));
  el.querySelector('#fb-list').addEventListener('click', (e) => { const p = e.target.closest('[data-path]'); if (p) openFile(ctx, p.dataset.path, 0); });
}
