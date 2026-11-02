import { api, getMeta } from '../api.js';
import { esc, icon, toast } from '../ui.js';
import { refreshSidebar } from '../app.js';

const PROVIDERS = {
  heuristic: { name: 'Offline rules', sub: 'Keyword + intake-flag scoping. No data leaves your machine.', bg: 'linear-gradient(135deg,#475569,#1e293b)', letter: '⚙' },
  openai: { name: 'OpenAI', sub: 'GPT models, or any OpenAI-compatible endpoint', bg: 'linear-gradient(135deg,#10a37f,#0d7a5f)', letter: 'O' },
  anthropic: { name: 'Anthropic', sub: 'Claude models via the Messages API', bg: 'linear-gradient(135deg,#d97757,#a8553a)', letter: 'A' },
  gemini: { name: 'Google Gemini', sub: 'Gemini models via Generative Language API', bg: 'linear-gradient(135deg,#4285f4,#9b72cb)', letter: 'G' },
  ollama: { name: 'Ollama', sub: 'Local models — fully on-prem', bg: 'linear-gradient(135deg,#f8fafc,#94a3b8)', letter: '🦙' },
};

export async function render(root) {
  const [s, meta] = await Promise.all([api.get('/api/settings'), getMeta()]);
  let provider = s.ai_provider || 'heuristic';
  const c = meta.catalog;

  root.innerHTML = `<div class="page" style="max-width:1100px">
    <div class="page-head"><div>
      <div class="eyebrow">${icon('settings')} Configuration</div>
      <h1>Settings</h1>
      <p>Choose the AI engine used to scope reviews. Keys are stored locally in the SQLite database (or set them via environment variables / <span class="mono">.env</span>).</p>
    </div></div>

    <section class="card" style="margin-bottom:16px">
      <h2 class="section-title">${icon('sparkles')} AI provider</h2>
      <div class="prov-grid" id="prov-grid">${Object.entries(PROVIDERS).map(([k, p]) => `
        <button type="button" class="prov ${k === provider ? 'on' : ''}" data-p="${k}" id="prov-${k}">
          <div class="logo" style="background:${p.bg};${k === 'ollama' ? 'color:#0f172a' : ''}">${p.letter}</div>
          <strong>${p.name}</strong><small>${p.sub}</small></button>`).join('')}</div>
      <div id="prov-fields"></div>
      <div class="row" style="margin-top:18px">
        <button class="btn primary" id="save-settings">${icon('check')} Save</button>
        <button class="btn" id="test-settings">${icon('zap')} Test connection</button>
      </div>
      <div id="test-out"></div>
    </section>

    <section class="card">
      <h2 class="section-title">${icon('database')} Knowledge base</h2>
      <div class="counts" style="margin-bottom:16px">
        <div><b>${c.counts.functions}</b><span>CSF functions</span></div>
        <div><b>${c.counts.categories}</b><span>CSF categories</span></div>
        <div><b>${c.counts.subcategories}</b><span>CSF outcomes / questions</span></div>
        <div><b>${c.counts.controls}</b><span>SP 800-53 r${esc(c.sp80053_version)} controls</span></div>
        <div><b>${c.counts.checks}</b><span>Checkov ${esc(c.checkov_version)} checks</span></div>
      </div>
      <p class="small muted" style="margin:0 0 10px">Built ${new Date(c.built_at).toLocaleString()}. Questions live in <span class="mono">catalog/csf_questions.yaml</span> and the Checkov → 800-53 mapping rules in <span class="mono">catalog/checkov_nist_rules.yaml</span>. After editing either file, or updating the Checkov source in <span class="mono">references/</span>, rebuild:</p>
      <code class="code">python scripts/build_catalog.py            # add --refresh to re-download NIST sources</code>
    </section>
  </div>`;

  const field = (id, label, value, opts = {}) => `<div class="field"><label for="${id}">${label}</label>
    <input class="input" id="${id}" type="${opts.type || 'text'}" value="${esc(value || '')}" placeholder="${esc(opts.ph || '')}" autocomplete="off" />
    ${opts.hint ? `<span class="hint">${opts.hint}</span>` : ''}</div>`;

  const drawFields = () => {
    const el = root.querySelector('#prov-fields');
    const model = field('set-model', 'Model', provider === s.ai_provider ? s.ai_model : '', { ph: s.default_models[provider] || '', hint: `Leave blank for default: <span class="mono">${esc(s.default_models[provider] || '')}</span>` });
    const key = (k, label) => field(`set-${k}`, label, '', { type: 'password', ph: s[`${k}_set`] ? `Saved (${s[`${k}_hint`]}) — leave blank to keep` : 'Paste API key' });
    el.innerHTML = {
      heuristic: `<div class="warning" style="background:rgba(96,165,250,0.08);border-color:rgba(96,165,250,0.25);color:#bfdbfe">${icon('info')}<div>Offline mode selects requirements using baseline items plus keyword/flag triggers from <span class="mono">catalog/csf_questions.yaml</span>. Choose an AI provider for context-aware scoping, key-risk analysis and extra questions.</div></div>`,
      openai: `<div class="grid-3">${model}${key('openai_api_key', 'API key')}${field('set-openai_base_url', 'Base URL', s.openai_base_url, { hint: 'Change for Azure OpenAI proxies, OpenRouter, LM Studio, vLLM…' })}</div>`,
      anthropic: `<div class="grid-2">${model}${key('anthropic_api_key', 'API key')}</div>`,
      gemini: `<div class="grid-2">${model}${key('gemini_api_key', 'API key')}</div>`,
      ollama: `<div class="grid-2">${model}${field('set-ollama_base_url', 'Ollama URL', s.ollama_base_url)}</div>`,
    }[provider];
  };

  root.querySelector('#prov-grid').addEventListener('click', (e) => {
    const b = e.target.closest('.prov'); if (!b) return;
    provider = b.dataset.p;
    root.querySelectorAll('.prov').forEach((x) => x.classList.toggle('on', x === b));
    drawFields();
  });

  const save = async () => {
    const body = { ai_provider: provider };
    const v = (id) => root.querySelector(`#${id}`)?.value;
    if (provider !== 'heuristic') body.ai_model = v('set-model') ?? '';
    for (const k of ['openai_api_key', 'anthropic_api_key', 'gemini_api_key', 'openai_base_url', 'ollama_base_url']) {
      const val = v(`set-${k}`);
      if (val !== undefined && val !== null && (val !== '' || !k.endsWith('api_key'))) body[k] = val;
    }
    Object.assign(s, await api.put('/api/settings', body));
    await refreshSidebar();
    drawFields();
  };

  root.querySelector('#save-settings').addEventListener('click', async () => {
    try { await save(); toast('Settings saved'); } catch (e) { toast(e.message, 'err'); }
  });
  root.querySelector('#test-settings').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Testing…';
    try {
      await save();
      const res = await api.post('/api/settings/test');
      root.querySelector('#test-out').innerHTML = `<div class="test-result ${res.ok ? 'ok' : 'bad'}">${esc(res.message)}</div>`;
    } catch (err) {
      root.querySelector('#test-out').innerHTML = `<div class="test-result bad">${esc(err.message)}</div>`;
    } finally {
      btn.disabled = false; btn.innerHTML = `${icon('zap')} Test connection`;
    }
  });
  drawFields();
}
