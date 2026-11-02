// Review workspace shell: header, progress overview, background-job banner, tabs and sidebar.
// Tabs: Line items · Mitigating controls · Threat model (linked threat models) · Documents & design.
import { api, getMeta, pollJob } from '../api.js';
import { aiField, wireAi } from '../ai-text.js';
import {
  CLS, STATUS, cap, clsBadge, confirmDialog, debounce, esc, fmtDate, icon, riskBadge, scopingOverlay, timeAgo, toast,
} from '../ui.js';
import { profileFields, wireProfile } from './profile.js';
import * as itemsTab from './review-items.js';
import * as controlsTab from './review-controls.js';
import * as docsTab from './review-docs.js';
import * as linkTab from './review-threat-link.js';

const TABS = [
  { id: 'items', label: 'Line items', icon: 'list', mod: itemsTab },
  { id: 'controls', label: 'Mitigating controls', icon: 'shield', mod: controlsTab },
  { id: 'threats', label: 'Threat model', icon: 'target', mod: linkTab },
  { id: 'docs', label: 'Documents & design', icon: 'file', mod: docsTab },
];
const EXP = { internal: ['building', 'Internal'], partner: ['link', 'Partner / B2B'], public: ['globe', 'Public'] };

export async function render(root, id) {
  const [meta, initial] = await Promise.all([getMeta(), api.get(`/api/reviews/${id}`)]);
  const tabKey = `sentinel.tab.${id}`;
  const savedTab = sessionStorage.getItem(tabKey);
  const watching = new Set();
  const cleanups = [];
  let alive = true;

  const ctx = {
    meta, root, r: initial,
    ui: { tab: TABS.some((t) => t.id === savedTab) ? savedTab : 'items' },
    set(fresh) { ctx.r = fresh; drawAll(); },
    async refresh() { ctx.set(await api.get(`/api/reviews/${ctx.r.id}`)); },
    async patch(body, msg) {
      try {
        const fresh = await api.patch(`/api/reviews/${ctx.r.id}`, body);
        ctx.r = fresh; renderHead(); renderOverview(); renderTabs(); renderSide();
        if (msg) toast(msg);
        return fresh;
      } catch (e) { toast(e.message, 'err'); return null; }
    },
    /** Lightweight update after an item autosave: counts only, no re-render of the tab body. */
    progress(p) { ctx.r.progress = p; renderOverview(); renderTabs(); },
    switchTab(t) { ctx.ui.tab = t; sessionStorage.setItem(tabKey, t); renderTabs(); renderTab(); root.querySelector('.rv-tabs')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); },
    jumpToItem(itemId) {
      if (ctx.ui.tab !== 'items') { ctx.ui.tab = 'items'; sessionStorage.setItem(tabKey, 'items'); renderTabs(); renderTab(); }
      itemsTab.jumpTo(ctx, itemId);
    },
    jumpToControl(mid) {
      if (ctx.ui.tab !== 'controls') { ctx.ui.tab = 'controls'; sessionStorage.setItem(tabKey, 'controls'); renderTabs(); renderTab(); }
      controlsTab.jumpTo(ctx, mid);
    },
    trackJob,
    rescope,
    onCleanup(fn) { cleanups.push(fn); },
  };

  root.innerHTML = `<div class="page" id="review-page">
    <a href="#/" class="back">${icon('left')} Review queue</a>
    <div id="rv-head"></div>
    <div class="review-grid">
      <div style="min-width:0">
        <div class="overview four" id="rv-overview"></div>
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
    const st = STATUS[r.status];
    const eff = r.effective_classification || r.data_classification;
    const [ei, el] = EXP[r.exposure] || EXP.internal;
    const sys = (r.system_types || []).map((s) => meta.profile.system_types.find((x) => x.id === s)?.label || s);
    root.querySelector('#rv-head').innerHTML = `
      <div class="review-head">
        <div style="min-width:0;flex:1">
          <span class="ref">${r.ref}</span>
          <h1>${esc(r.title)}</h1>
          <div class="row wrap">
            <span class="badge">${r.change_type === 'new' ? `${icon('sparkles')} New initiative` : `${icon('refresh')} Change`}</span>
            <span class="badge">${icon(ei)} ${esc(el)}</span>
            ${clsBadge(eff, 'Effective classification: ')}
            ${eff !== r.data_classification ? `<span class="small muted" title="Stores ${esc(CLS[r.data_classification]?.label)} data but connects to ${esc(CLS[eff]?.label)} systems">(stores ${CLS[r.data_classification]?.code})</span>` : ''}
            ${riskBadge(r.risk_rating)}
            ${sys.slice(0, 3).map((s) => `<span class="badge">${icon('layers')} ${esc(s)}</span>`).join('')}
            ${r.uses_ai ? `<span class="badge ai">${icon('cpu')} AI</span>` : ''}${r.third_party ? `<span class="badge">${icon('building')} Third party</span>` : ''}
          </div>
        </div>
        <div class="row wrap">
          <div class="status-select" style="--c:${st.color}">
            <select id="status-select" aria-label="Review status">${Object.entries(STATUS).map(([k, v]) => `<option value="${k}" ${k === r.status ? 'selected' : ''}>${v.label}</option>`).join('')}</select>
          </div>
          <button class="btn" id="rescope-btn">${icon('sparkles')} ${r.ai_meta?.scoped_at ? 'Re-run scoping' : 'Run AI scoping'}</button>
          <a class="btn" id="export-btn" href="/api/reviews/${r.id}/report.md">${icon('download')} Export</a>
          <button class="btn icon danger" id="delete-btn" title="Delete review">${icon('trash')}</button>
        </div>
      </div>`;
    root.querySelector('#status-select').addEventListener('change', (e) => ctx.patch({ status: e.target.value }, `Status → ${STATUS[e.target.value].label}`));
    root.querySelector('#rescope-btn').addEventListener('click', rescope);
    root.querySelector('#delete-btn').addEventListener('click', async () => {
      if (await confirmDialog(`Delete ${r.ref}?`, 'This permanently removes the review, all line items, controls, uploads and check results.')) {
        await api.del(`/api/reviews/${r.id}`);
        toast(`${r.ref} deleted`);
        location.hash = '#/';
      }
    });
  }

  // ------------------------------------------------------------------ overview
  let lastPct = 0;
  function renderOverview() {
    const r = ctx.r;
    const p = r.progress || { total: 0, answered: 0, question: {}, risk: {}, recommendation: {}, risks: {} };
    const pct = p.total ? Math.round((p.answered / p.total) * 100) : 0;
    const C = 2 * Math.PI * 40;
    const cc = r.check_counts || {};
    const marked = ['pass', 'fail', 'exception', 'na'].reduce((a, k) => a + (cc[k] || 0), 0);
    const kind = (k, label, color) => `<div class="k" style="--c:${color}"><i></i>${label}<b>${p[k]?.answered || 0}/${p[k]?.total || 0}</b></div>`;
    const rmax = Math.max(1, ...['critical', 'high', 'medium', 'low'].map((k) => p.risks?.[k] || 0));
    const rb = (k, color) => `<div class="rb" style="--c:${color}">${cap(k)}<div class="t"><i style="width:${((p.risks?.[k] || 0) / rmax) * 100}%"></i></div><b>${p.risks?.[k] || 0}</b></div>`;
    root.querySelector('#rv-overview').innerHTML = `
      <div class="card tight ring-wrap">
        <div class="ring"><svg viewBox="0 0 100 100"><defs><linearGradient id="ringGrad" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#8b5cf6"/><stop offset="1" stop-color="#22d3ee"/></linearGradient></defs>
          <circle class="bg" cx="50" cy="50" r="40"/><circle class="fg" cx="50" cy="50" r="40" stroke-dasharray="${C}" stroke-dashoffset="${C * (1 - lastPct / 100)}" id="ring-fg"/></svg>
          <div class="pct">${pct}%</div></div>
        <div style="flex:1;min-width:0">
          <div class="small" style="margin-bottom:8px;font-weight:600"><b>${p.answered}</b> <span class="muted">of ${p.total} answered</span></div>
          <div class="ov-kinds">${kind('question', 'Questions', 'var(--K-question)')}${kind('risk', 'Risks', 'var(--K-risk)')}${kind('recommendation', 'Recommendations', 'var(--K-recommendation)')}</div>
          ${p.total > p.answered ? `<button class="btn sm" id="ov-next" style="margin-top:10px;width:100%">${icon('next')} Next unanswered <kbd>N</kbd></button>` : `<div class="small" style="margin-top:10px;color:var(--ok)">${icon('check')} Everything answered</div>`}
        </div>
      </div>
      <div class="card tight mini-stat">
        <div class="k">Risks</div>
        <div class="row" style="align-items:baseline"><div class="v">${p.risk_total || 0}</div><span class="muted small">recorded</span>
          ${p.risk_untreated ? `<span class="spacer"></span><span class="pill need" title="No treatment and no control">${p.risk_untreated} untreated</span>` : ''}</div>
        <div class="risk-bars">${rb('critical', '#f43f5e')}${rb('high', '#fb923c')}${rb('medium', '#fbbf24')}${rb('low', '#34d399')}</div>
      </div>
      <div class="card tight mini-stat">
        <div class="k">Mitigating controls</div>
        <div class="row" style="align-items:baseline"><div class="v">${p.controls || 0}</div><span class="muted small">${p.controls_new || 0} new · ${(p.controls || 0) - (p.controls_new || 0)} existing</span></div>
        <div class="small" style="margin:8px 0 10px;color:${p.no_control ? '#fdba74' : 'var(--ok)'}">${p.no_control ? `${p.no_control} risk/gap item${p.no_control === 1 ? '' : 's'} without a control` : `${icon('check')} Every risk and gap has a control`}</div>
        ${p.no_control ? `<button class="btn sm" id="ov-auto" style="width:100%">${icon('wand')} Auto-link suggested controls</button>` : `<button class="btn sm ghost" id="ov-reg" style="width:100%">${icon('shield')} Open register</button>`}
      </div>
      <div class="card tight mini-stat">
        <div class="k">Residual risk</div>
        <select class="select sm" id="risk-select" style="margin:8px 0 8px">
          <option value="">Unrated</option>${['low', 'medium', 'high', 'critical'].map((v) => `<option value="${v}" ${r.risk_rating === v ? 'selected' : ''}>${cap(v)}</option>`).join('')}
        </select>
        <div class="small muted">${r.ai_meta?.inherent_risk ? `Inherent (AI): <b style="color:var(--text)">${esc(r.ai_meta.inherent_risk)}</b>` : 'Set after assessing gaps'}</div>
        <div class="small muted" style="margin-top:6px">${icon('code')} Checkov: <b style="color:var(--text)">${marked}</b> verified${cc.fail ? ` · <span style="color:#fda4af">${cc.fail} failing</span>` : ''}</div>
      </div>`;
    requestAnimationFrame(() => { const fg = root.querySelector('#ring-fg'); if (fg) fg.style.strokeDashoffset = C * (1 - pct / 100); lastPct = pct; });
    root.querySelector('#risk-select').addEventListener('change', (e) => ctx.patch({ risk_rating: e.target.value }, 'Residual risk updated'));
    root.querySelector('#ov-next')?.addEventListener('click', () => { if (ctx.ui.tab !== 'items') ctx.switchTab('items'); itemsTab.nextUnanswered(ctx); });
    root.querySelector('#ov-auto')?.addEventListener('click', autoLink);
    root.querySelector('#ov-reg')?.addEventListener('click', () => ctx.switchTab('controls'));
  }

  async function autoLink() {
    try {
      const res = await api.post(`/api/reviews/${ctx.r.id}/auto-mitigate`, {});
      ctx.set(res.review);
      toast(res.linked ? `Linked controls to ${res.linked} item${res.linked === 1 ? '' : 's'} — existing controls reused first` : 'No confident suggestions — link controls manually', res.linked ? 'ok' : 'warn');
    } catch (e) { toast(e.message, 'err'); }
  }

  // ------------------------------------------------------------------ jobs
  const JOB_LABEL = { design: 'Analysing documents' };
  function renderJobs(state = {}) {
    const el = root.querySelector('#rv-jobs');
    const list = Object.values(state);
    el.innerHTML = list.map((j) => `<div class="job-banner" id="job-${j.id}"><span class="spin"></span>
      <div style="flex:1;min-width:0"><b>${esc(JOB_LABEL[j.kind] || j.kind)}</b> <span class="muted">· ${esc(j.message || '')}</span></div>
      <div class="progress"><i style="width:${Math.round((j.progress || 0) * 100)}%"></i></div></div>`).join('');
  }
  const jobState = {};
  function trackJob(job, { onDone } = {}) {
    const jid = typeof job === 'object' ? job.id : job;
    if (watching.has(jid)) return Promise.resolve();
    watching.add(jid);
    jobState[jid] = typeof job === 'object' ? job : { id: jid, kind: '', message: 'Queued…', progress: 0 };
    renderJobs(jobState); renderTabs();
    return pollJob(jid, (j) => { if (!alive) return; jobState[jid] = j; renderJobs(jobState); })
      .then(async (j) => {
        delete jobState[jid]; watching.delete(jid);
        if (!alive) return j;
        renderJobs(jobState);
        await ctx.refresh();
        onDone?.(j);
        toast(j.kind === 'design' ? 'Design understanding ready' : 'Job finished');
        return j;
      })
      .catch((e) => { delete jobState[jid]; watching.delete(jid); if (alive) { renderJobs(jobState); renderTabs(); toast(e.message, 'err', 8000); } });
  }
  ctx.runningJob = (kind) => Object.values(jobState).some((j) => j.kind === kind);

  // ------------------------------------------------------------------ tabs
  function renderTabs() {
    const r = ctx.r;
    const p = r.progress || {};
    const docs = (r.documents || []).filter((d) => d.kind !== 'code').length;
    const tms = (r.linked_threat_models || []).length;
    const counts = {
      items: `<span class="n ${p.total - p.answered ? '' : ''}">${p.answered || 0}/${p.total || 0}</span>`,
      controls: `<span class="n">${p.controls || 0}</span>`,
      threats: tms ? `<span class="n">${tms}</span>` : '',
      docs: `<span class="n">${docs}</span>${ctx.runningJob('design') ? '<span class="live"></span>' : ''}`,
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
        <h2 class="section-title">${icon('zap')} Decision</h2>
        <div class="row" style="gap:8px;margin-bottom:12px">
          <button class="btn sm" style="flex:1;color:#6ee7b7" data-decide="approved" id="decide-approve">${icon('check')} Approve</button>
          <button class="btn sm" style="flex:1;color:#fcd34d" data-decide="awaiting_info" id="decide-info">${icon('message')} Need info</button>
          <button class="btn sm" style="flex:1;color:#fda4af" data-decide="rejected" id="decide-reject">${icon('x')} Reject</button>
        </div>
        <div class="field"><label class="row" for="decision-notes">Decision notes &amp; conditions <span class="spacer"></span><span class="saved" id="dn-saved"></span></label>
          ${aiField({ id: 'decision-notes', field: 'decision_notes', value: r.decision_notes, rows: 4, placeholder: 'Approval conditions, accepted risks, follow-ups…' })}</div>
      </div>
      <div class="card side-card">
        <h2 class="section-title">${icon('target')} Profile <span class="small muted" style="font-weight:500;margin-left:auto">drives scoping &amp; risks</span></h2>
        ${profileFields(r, meta, { compact: true, id: 'side-pf' })}
        <div id="pf-hint"></div>
      </div>
      <div class="card side-card">
        <h2 class="section-title">${icon('info')} Details</h2>
        <div class="stack" style="gap:12px">
          ${[['requester', 'Requester'], ['business_owner', 'Business owner'], ['reviewer', 'Security reviewer'], ['business_unit', 'Business unit']].map(([k, l]) => `
            <div class="field"><label for="d-${k}">${l}</label><input class="input sm" id="d-${k}" data-detail="${k}" value="${esc(r[k])}" placeholder="—" /></div>`).join('')}
          <div class="grid-2" style="gap:10px">
            <div class="field"><label for="d-due">Due</label><input class="input sm" type="date" id="d-due" data-detail="due_date" value="${esc(r.due_date)}" /></div>
            <div class="field"><label for="d-pri">Priority</label><select class="select sm" id="d-pri" data-detail="priority">${['low', 'medium', 'high', 'critical'].map((p) => `<option ${r.priority === p ? 'selected' : ''} value="${p}">${cap(p)}</option>`).join('')}</select></div>
          </div>
          <div class="field"><label for="d-desc">Description</label>${aiField({ id: 'd-desc', field: 'description', value: r.description, rows: 5, attrs: 'data-detail="description"' })}</div>
          <div class="field"><label for="d-stack">Tech stack</label><input class="input sm" id="d-stack" data-detail="tech_stack" value="${esc(r.tech_stack)}" /></div>
          <div class="row" style="gap:16px">
            <label class="row small" style="gap:8px;cursor:pointer"><span class="switch"><input type="checkbox" data-flag="third_party" ${r.third_party ? 'checked' : ''} id="d-third"/><span></span></span>Third party</label>
            <label class="row small" style="gap:8px;cursor:pointer"><span class="switch"><input type="checkbox" data-flag="uses_ai" ${r.uses_ai ? 'checked' : ''} id="d-ai"/><span></span></span>Uses AI</label>
          </div>
          <div class="small muted">Created ${fmtDate(r.created_at)} · updated ${timeAgo(r.updated_at)}</div>
        </div>
      </div>
      <div class="card side-card">
        <h2 class="section-title">${icon('clock')} Activity</h2>
        <div class="timeline">${r.activity.slice(0, 40).map((a) => `<div class="tl"><i class="${esc(a.action)}"></i><div>
          <div class="t"><b>${esc(a.action)}</b> · ${esc(a.detail)}</div><div class="w">${timeAgo(a.ts)}</div></div></div>`).join('') || '<p class="muted small">No activity yet</p>'}</div>
      </div>`;
    side.querySelectorAll('[data-decide]').forEach((b) => b.addEventListener('click', () => {
      const s = b.dataset.decide;
      const p = ctx.r.progress || {};
      if (s === 'approved' && p.total - p.answered) toast(`${p.total - p.answered} line items are still unanswered`, 'warn');
      if (s === 'approved' && p.risk_untreated) toast(`${p.risk_untreated} risks have no treatment or control`, 'warn');
      ctx.patch({ status: s }, `${ctx.r.ref} → ${STATUS[s].label}`);
    }));
    const dn = side.querySelector('#decision-notes');
    const dnSave = debounce(async () => {
      await api.patch(`/api/reviews/${ctx.r.id}`, { decision_notes: dn.value });
      ctx.r.decision_notes = dn.value;
      const s = side.querySelector('#dn-saved'); s.textContent = 'Saved'; s.classList.add('ok');
    }, 700);
    dn.addEventListener('input', () => { side.querySelector('#dn-saved').textContent = 'Saving…'; dnSave(); });
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
    side.querySelectorAll('[data-flag]').forEach((cb) => cb.addEventListener('change', () => ctx.patch({ [cb.dataset.flag]: cb.checked }, 'Saved')));
    wireAi(side, () => ({ review_id: ctx.r.id }));
    const saveProfile = debounce(async (pf) => {
      const fresh = await ctx.patch(pf);
      if (!fresh) return;
      const hint = side.querySelector('#pf-hint');
      if (hint) {
        hint.innerHTML = `<div class="apply-row" style="margin-top:12px">${icon('sparkles')}<div class="x">Profile changed — re-run scoping to refresh NIST questions and risk suggestions.</div><button class="btn sm" id="pf-rescope">Re-scope</button></div>`;
        hint.querySelector('svg').style.cssText = 'width:15px;height:15px;color:#c4b5fd;flex-shrink:0';
        hint.querySelector('#pf-rescope').addEventListener('click', rescope);
      }
    }, 600);
    wireProfile(side.querySelector('#side-pf'), (pf) => saveProfile(pf));
  }

  // ------------------------------------------------------------------ actions
  async function rescope() {
    const stop = scopingOverlay();
    try {
      const fresh = await api.post(`/api/reviews/${ctx.r.id}/scope`);
      stop();
      if (fresh.ai_meta?.warning) toast(fresh.ai_meta.warning, 'warn', 8000);
      else toast(`Scoped ${fresh.requirements.length} NIST questions`);
      ctx.set(fresh);
    } catch (e) { stop(); toast(e.message, 'err', 6000); }
  }

  function drawAll() { renderHead(); renderOverview(); renderTabs(); renderTab(); renderSide(); }

  // Keyboard: N = next unanswered (when not typing).
  const onKey = (e) => {
    if (e.target.closest('input, textarea, select, [contenteditable]') || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === 'n' || e.key === 'N') { e.preventDefault(); if (ctx.ui.tab !== 'items') ctx.switchTab('items'); itemsTab.nextUnanswered(ctx); }
  };
  document.addEventListener('keydown', onKey);

  drawAll();
  (ctx.r.jobs || []).forEach((j) => trackJob(j));

  return () => {
    alive = false;
    document.removeEventListener('keydown', onKey);
    cleanups.forEach((fn) => fn());
  };
}
