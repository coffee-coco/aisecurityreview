// Threat model workspace: header, background-job banner, tabs and sidebar.
// Tabs: Code & repository · Documents & diagrams · Threat model.
import { api, getMeta, pollJob } from '../api.js';
import { confirmDialog, debounce, esc, fmtDate, icon, timeAgo, toast } from '../ui.js';
import * as docsTab from './review-docs.js';
import * as codeTab from './review-code.js';
import * as threatsTab from './review-threats.js';

const TABS = [
  { id: 'code', label: 'Code & repository', icon: 'code', mod: codeTab },
  { id: 'docs', label: 'Documents & diagrams', icon: 'file', mod: docsTab },
  { id: 'threats', label: 'Threat model', icon: 'target', mod: threatsTab },
];
const JOB_LABEL = { design: 'Analysing documents', code_review: 'Reviewing code' };

export async function render(root, id) {
  const [meta, initial] = await Promise.all([getMeta(), api.get(`/api/reviews/${id}`)]);
  const tabKey = `sentinel.tmtab.${id}`;
  const watching = new Set();
  const jobState = {};
  const cleanups = [];
  let alive = true;

  const saved = sessionStorage.getItem(tabKey);
  const hasCode = (initial.documents || []).some((d) => d.kind === 'code');
  const ctx = {
    meta, root, r: initial,
    ui: { tab: TABS.some((t) => t.id === saved) ? saved : hasCode ? 'threats' : 'code' },
    set(fresh) { ctx.r = fresh; drawAll(); },
    async refresh() { ctx.set(await api.get(`/api/reviews/${ctx.r.id}`)); },
    async patch(body, msg) {
      try {
        const fresh = await api.patch(`/api/reviews/${ctx.r.id}`, body);
        ctx.r = fresh; renderHead(); renderTabs(); renderSide();
        if (msg) toast(msg);
        return fresh;
      } catch (e) { toast(e.message, 'err'); return null; }
    },
    switchTab(t) { ctx.ui.tab = t; sessionStorage.setItem(tabKey, t); renderTabs(); renderTab(); root.querySelector('.rv-tabs')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); },
    trackJob,
    runningJob: (kind) => Object.values(jobState).some((j) => j.kind === kind),
    jumpToItem() {},
    jumpToControl() {},
    onCleanup(fn) { cleanups.push(fn); },
  };

  root.innerHTML = `<div class="page" id="tm-page">
    <a href="#/threat-models" class="back">${icon('left')} Threat models</a>
    <div id="rv-head"></div>
    <div class="review-grid">
      <div style="min-width:0">
        <div id="rv-jobs"></div>
        <nav class="rv-tabs" id="rv-tabs" role="tablist"></nav>
        <div id="rv-tab"></div>
      </div>
      <aside id="rv-side"></aside>
    </div>
  </div>`;

  // ------------------------------------------------------------------ header
  function renderHead() {
    const r = ctx.r;
    const linked = r.linked_reviews || [];
    root.querySelector('#rv-head').innerHTML = `
      <div class="review-head">
        <div style="min-width:0;flex:1">
          <span class="ref">${esc(r.ref)}</span>
          <h1>${esc(r.title)}</h1>
          <div class="row wrap" style="gap:6px">
            <span class="small muted">Linked security reviews</span>
            ${linked.map((l) => `<a class="chip ctrl" href="#/review/${l.id}" title="${esc(l.title)}">${esc(l.ref)}</a>`).join('')
              || `<span class="small muted">none — link this threat model from a security review's Threat model tab</span>`}
          </div>
        </div>
        <div class="row wrap">
          <a class="btn" id="export-btn" href="/api/reviews/${r.id}/threats/export.md">${icon('download')} Export</a>
          <button class="btn icon danger" id="delete-btn" title="Delete threat model">${icon('trash')}</button>
        </div>
      </div>`;
    root.querySelector('#delete-btn').addEventListener('click', async () => {
      const warn = linked.length ? ` It is linked to ${linked.map((l) => l.ref).join(', ')}; those reviews keep any risks and controls they already promoted.` : '';
      if (!(await confirmDialog(`Delete ${r.ref}?`, `This permanently removes the threat model, its code, documents and generated artifacts.${warn}`))) return;
      try {
        await api.del(`/api/reviews/${r.id}`);
        toast(`${r.ref} deleted`);
        location.hash = '#/threat-models';
      } catch (e) { toast(e.message, 'err'); }
    });
  }

  // ------------------------------------------------------------------ jobs
  function renderJobs() {
    root.querySelector('#rv-jobs').innerHTML = Object.values(jobState).map((j) => `<div class="job-banner" id="job-${esc(j.id)}"><span class="spin"></span>
      <div style="flex:1;min-width:0"><b>${esc(JOB_LABEL[j.kind] || j.kind)}</b> <span class="muted">· ${esc(j.message || '')}</span></div>
      <div class="progress"><i style="width:${Math.round((j.progress || 0) * 100)}%"></i></div></div>`).join('');
  }
  function trackJob(job, { onDone } = {}) {
    const jid = typeof job === 'object' ? job.id : job;
    if (watching.has(jid)) return Promise.resolve();
    watching.add(jid);
    jobState[jid] = typeof job === 'object' ? job : { id: jid, kind: '', message: 'Queued…', progress: 0 };
    renderJobs(); renderTabs();
    return pollJob(jid, (j) => { if (!alive) return; jobState[jid] = j; renderJobs(); })
      .then(async (j) => {
        delete jobState[jid]; watching.delete(jid);
        if (!alive) return j;
        renderJobs();
        await ctx.refresh();
        onDone?.(j);
        toast(j.kind === 'code_review' ? `Code review finished · ${j.result?.findings ?? 0} findings` : j.kind === 'design' ? 'Design understanding ready' : 'Job finished');
        return j;
      })
      .catch((e) => { delete jobState[jid]; watching.delete(jid); if (alive) { renderJobs(); renderTabs(); toast(e.message, 'err', 8000); } });
  }

  // ------------------------------------------------------------------ tabs
  function renderTabs() {
    const r = ctx.r;
    const docs = (r.documents || []).filter((d) => d.kind !== 'code').length;
    const findings = (r.code_review?.findings || []).length;
    const counts = {
      code: `${findings ? `<span class="n">${findings}</span>` : ''}${ctx.runningJob('code_review') ? '<span class="live"></span>' : ''}`,
      docs: `<span class="n">${docs}</span>${ctx.runningJob('design') ? '<span class="live"></span>' : ''}`,
      threats: '',
    };
    root.querySelector('#rv-tabs').innerHTML = TABS.map((t) => `<button class="rv-tab ${ctx.ui.tab === t.id ? 'on' : ''}" role="tab" data-tab="${t.id}" id="tab-${t.id}" aria-selected="${ctx.ui.tab === t.id}">${icon(t.icon)}${t.label}${counts[t.id]}</button>`).join('');
  }
  root.querySelector('#rv-tabs').addEventListener('click', (e) => {
    const b = e.target.closest('[data-tab]'); if (b && b.dataset.tab !== ctx.ui.tab) ctx.switchTab(b.dataset.tab);
  });
  function renderTab() {
    const t = TABS.find((x) => x.id === ctx.ui.tab) || TABS[0];
    const el = root.querySelector('#rv-tab');
    el.innerHTML = '';
    t.mod.render(el, ctx);
  }

  // ------------------------------------------------------------------ sidebar
  function renderSide() {
    const r = ctx.r;
    const side = root.querySelector('#rv-side');
    side.innerHTML = `
      <div class="card side-card">
        <h2 class="section-title">${icon('info')} Details</h2>
        <div class="stack" style="gap:12px">
          <div class="field"><label for="d-desc">Description</label><textarea class="textarea" id="d-desc" data-detail="description" rows="5">${esc(r.description)}</textarea></div>
          <div class="field"><label for="d-stack">Tech stack</label><input class="input sm" id="d-stack" data-detail="tech_stack" value="${esc(r.tech_stack)}" /></div>
          <div class="field"><label for="d-exp">Exposure</label><select class="select sm" id="d-exp">${meta.profile.exposures.map((x) => `<option value="${esc(x.id)}" ${r.exposure === x.id ? 'selected' : ''}>${esc(x.label)}</option>`).join('')}</select></div>
          <label class="row small" style="gap:8px;cursor:pointer"><span class="switch"><input type="checkbox" id="d-ai" ${r.uses_ai ? 'checked' : ''} /><span></span></span>Uses AI</label>
          <div class="small muted">Exposure and AI use select which threat references apply. Created ${fmtDate(r.created_at)} · updated ${timeAgo(r.updated_at)}</div>
        </div>
      </div>
      <div class="card side-card">
        <h2 class="section-title">${icon('clock')} Activity</h2>
        <div class="timeline">${(r.activity || []).slice(0, 40).map((a) => `<div class="tl"><i class="${esc(a.action)}"></i><div>
          <div class="t"><b>${esc(a.action)}</b> · ${esc(a.detail)}</div><div class="w">${timeAgo(a.ts)}</div></div></div>`).join('') || '<p class="muted small">No activity yet</p>'}</div>
      </div>`;
    side.querySelectorAll('[data-detail]').forEach((inp) => {
      const save = async () => {
        if ((ctx.r[inp.dataset.detail] ?? '') === inp.value) return;
        try {
          await api.patch(`/api/reviews/${ctx.r.id}`, { [inp.dataset.detail]: inp.value });
          ctx.r[inp.dataset.detail] = inp.value;
          toast('Saved');
        } catch (e) { toast(e.message, 'err'); }
      };
      inp.addEventListener('change', save);
      if (inp.tagName === 'TEXTAREA') inp.addEventListener('input', debounce(save, 900));
    });
    // These drive the app-type detection, so reload the open tab (the threat model re-fetches it).
    const saveProfile = async (body) => { if (await ctx.patch(body, 'Saved')) renderTab(); };
    side.querySelector('#d-exp').addEventListener('change', (e) => saveProfile({ exposure: e.target.value }));
    side.querySelector('#d-ai').addEventListener('change', (e) => saveProfile({ uses_ai: e.target.checked }));
  }

  function drawAll() { renderHead(); renderTabs(); renderTab(); renderSide(); }

  drawAll();
  (ctx.r.jobs || []).filter((j) => JOB_LABEL[j.kind]).forEach((j) => trackJob(j));

  return () => {
    alive = false;
    cleanups.forEach((fn) => fn());
  };
}
