// Review profile editor: exposure, C1–C4 classification, data types, connected-system
// classifications and system type. These drive scoping, risk suggestions and AI prompts.
import { CLS, esc, icon } from '../ui.js';

const EXP_ICON = { internal: 'building', partner: 'link', public: 'globe' };
const LEVEL = { public: 1, internal: 2, confidential: 3, restricted: 4 };

export function effectiveClass(p) {
  return [p.data_classification || 'internal', ...(p.interacts_with || [])]
    .reduce((a, c) => (LEVEL[c] > LEVEL[a] ? c : a), 'public');
}

/** HTML for the profile editor. r = review-like object, meta = /api/meta. */
export function profileFields(r, meta, { compact = false, id = 'pf' } = {}) {
  const v = meta.profile;
  const dt = new Set(r.data_types || []);
  const iw = new Set(r.interacts_with || []);
  const st = new Set(r.system_types || []);
  const exp = r.exposure || (r.internet_facing ? 'public' : 'internal');
  const cls = r.data_classification || 'internal';
  return `<div class="pf ${compact ? 'compact' : ''}" data-pf id="${id}">
    <div class="grp"><div class="label">${icon('globe')} Exposure ${compact ? '' : '<small>who can reach it</small>'}</div>
      <div class="seg ${compact ? '' : 'lg'}" data-pf-exp role="radiogroup" aria-label="Exposure">${v.exposures.map((e) => `
        <button type="button" data-v="${e.id}" class="${exp === e.id ? 'on' : ''}" title="${esc(e.desc)}" id="${id}-exp-${e.id}">${icon(EXP_ICON[e.id])}${esc(compact ? e.label.split(' ')[0] : e.label)}</button>`).join('')}</div></div>
    <div class="grp"><div class="label">${icon('lock')} Data classification ${compact ? '' : '<small>highest data it stores or processes</small>'}</div>
      <div class="cls-cards" data-pf-cls>${v.classifications.map((c) => `
        <button type="button" class="cls-card c-${c.id} ${cls === c.id ? 'on' : ''}" data-v="${c.id}" title="${esc(c.label)} — ${esc(c.desc)}" id="${id}-cls-${c.id}">
          <b>${c.code}</b><strong>${esc(CLS[c.id].label)}</strong><small>${esc(c.desc)}</small></button>`).join('')}</div></div>
    <div class="grp"><div class="label">${icon('database')} Data types handled ${compact ? '' : '<small>select all that apply</small>'}</div>
      <div class="chips" data-pf-dt>${v.data_types.map((d) => `<span class="chip tog ${dt.has(d.id) ? 'on' : ''}" data-v="${d.id}" id="${id}-dt-${d.id}">${esc(d.label)}</span>`).join('')}</div></div>
    <div class="grp"><div class="label">${icon('link')} Connects to systems holding ${compact ? '' : '<small>integrations raise the effective classification</small>'}</div>
      <div class="chips" data-pf-iw>${v.classifications.map((c) => `<span class="chip tog c-${c.id} ${iw.has(c.id) ? 'on' : ''}" data-v="${c.id}" id="${id}-iw-${c.id}"><span class="c">${c.code}</span>${esc(CLS[c.id].label)}</span>`).join('')}</div>
      <div class="small muted" data-pf-eff style="margin-top:8px"></div></div>
    <div class="grp"><div class="label">${icon('layers')} What is it? ${compact ? '' : '<small>system type — AI can detect this from documents or code</small>'}</div>
      <div class="chips" data-pf-st>${v.system_types.map((s) => `<span class="chip tog ${st.has(s.id) ? 'on' : ''}" data-v="${s.id}" id="${id}-st-${s.id}">${esc(s.label)}</span>`).join('')}</div></div>
  </div>`;
}

export function readProfile(el) {
  const on = (sel) => [...el.querySelectorAll(`${sel} .on`)].map((b) => b.dataset.v);
  return {
    exposure: el.querySelector('[data-pf-exp] .on')?.dataset.v || 'internal',
    data_classification: el.querySelector('[data-pf-cls] .on')?.dataset.v || 'internal',
    data_types: on('[data-pf-dt]'),
    interacts_with: on('[data-pf-iw]'),
    system_types: on('[data-pf-st]'),
  };
}

function drawEff(el) {
  const p = readProfile(el);
  const eff = effectiveClass(p);
  const box = el.querySelector('[data-pf-eff]');
  if (!box) return;
  box.innerHTML = eff !== p.data_classification
    ? `${icon('alert')} Effective classification <b style="color:var(--C${LEVEL[eff]})">${CLS[eff].code} ${CLS[eff].label}</b> — it connects to more sensitive systems.`
    : `Effective classification <b style="color:var(--C${LEVEL[eff]})">${CLS[eff].code} ${CLS[eff].label}</b>`;
  const s = box.querySelector('svg');
  if (s) s.style.cssText = 'width:12px;height:12px;vertical-align:-2px;color:#fcd34d';
}

/** Toggle behaviour; onChange(profile, key) fires after each change. */
export function wireProfile(el, onChange) {
  const pf = el.matches('[data-pf]') ? el : el.querySelector('[data-pf]');
  drawEff(pf);
  const single = (sel, key) => pf.querySelector(sel).addEventListener('click', (e) => {
    const b = e.target.closest('[data-v]'); if (!b || b.classList.contains('on')) return;
    pf.querySelectorAll(`${sel} [data-v]`).forEach((x) => x.classList.toggle('on', x === b));
    drawEff(pf);
    onChange?.(readProfile(pf), key);
  });
  const multi = (sel, key) => pf.querySelector(sel).addEventListener('click', (e) => {
    const b = e.target.closest('[data-v]'); if (!b) return;
    b.classList.toggle('on');
    drawEff(pf);
    onChange?.(readProfile(pf), key);
  });
  single('[data-pf-exp]', 'exposure');
  single('[data-pf-cls]', 'data_classification');
  multi('[data-pf-dt]', 'data_types');
  multi('[data-pf-iw]', 'interacts_with');
  multi('[data-pf-st]', 'system_types');
}
