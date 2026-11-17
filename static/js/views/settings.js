import { api, getMeta } from '../api.js';
import { confirmDialog, esc, fmtDate, icon, toast } from '../ui.js';
import { isAdmin, refreshSession, refreshSidebar, session } from '../app.js';

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
      <p>Settings for the <b>${esc(session.me.workspace?.name || '')}</b> workspace. AI keys and GitLab tokens belong to this workspace and are stored encrypted. ${isAdmin() ? '' : 'Only workspace admins can change them.'}</p>
    </div></div>

    <section class="card" style="margin-bottom:16px">
      <h2 class="section-title">${icon('sparkles')} AI provider</h2>
      <div class="prov-grid" id="prov-grid">${Object.entries(PROVIDERS).map(([k, p]) => `
        <button type="button" class="prov ${k === provider ? 'on' : ''}" data-p="${k}" id="prov-${k}">
          <div class="logo" style="background:${p.bg};${k === 'ollama' ? 'color:#0f172a' : ''}">${p.letter}</div>
          <strong>${p.name}</strong><small>${p.sub}</small></button>`).join('')}</div>
      <div id="prov-fields"></div>
      <div class="row" style="margin-top:18px">
        <button class="btn primary" id="save-settings" ${isAdmin() ? '' : 'disabled'}>${icon('check')} Save</button>
        <button class="btn" id="test-settings" ${isAdmin() ? '' : 'disabled'}>${icon('zap')} Test connection</button>
      </div>
      <div id="test-out"></div>
    </section>

    <section class="card" style="margin-bottom:16px">
      <h2 class="section-title">${icon('code')} GitLab credentials</h2>
      <p class="small muted" style="margin:0 0 12px">Used when linking a repository on this GitLab host without entering a token. Use a personal, group or project access token with <span class="mono">read_repository</span> scope.</p>
      <div class="grid-3">
        <div class="field"><label for="gl-url">GitLab URL</label><input class="input" id="gl-url" value="${esc(s.gitlab_base_url || '')}" placeholder="https://gitlab.com" /></div>
        <div class="field"><label for="gl-user">Username</label><input class="input" id="gl-user" value="${esc(s.gitlab_username || '')}" placeholder="oauth2" /><span class="hint">Any non-empty value works for access tokens</span></div>
        <div class="field"><label for="gl-token">Access token</label><input class="input" id="gl-token" type="password" autocomplete="off" placeholder="${s.gitlab_token_set ? `Saved (${esc(s.gitlab_token_hint)}) — leave blank to keep` : 'glpat-…'}" /></div>
      </div>
      <div class="row" style="margin-top:14px"><button class="btn primary" id="gl-save" ${isAdmin() ? '' : 'disabled'}>${icon('check')} Save GitLab credentials</button></div>
    </section>

    <section class="card" style="margin-bottom:16px">
      <h2 class="section-title">${icon('lock')} API keys</h2>
      <p class="small muted" style="margin:0 0 12px">Call the API with <span class="mono">Authorization: Bearer &lt;key&gt;</span> (see <a href="/docs" target="_blank" rel="noopener">/docs</a>). A key acts in this workspace with the lower of its role and yours.</p>
      <div class="row wrap" style="margin-bottom:12px">
        <input class="input sm" id="key-name" placeholder="Key name, e.g. CI pipeline" style="flex:1;min-width:200px" />
        <select class="select sm" id="key-role">${['read', 'write', 'admin'].map((r) => `<option value="${r}">${r}</option>`).join('')}</select>
        <select class="select sm" id="key-exp"><option value="">No expiry</option><option value="30">30 days</option><option value="90">90 days</option><option value="365">1 year</option></select>
        <button class="btn sm primary" id="key-create">${icon('plus')} Create key</button>
      </div>
      <div id="key-new"></div>
      <div id="key-list"></div>
    </section>

    <section class="card" style="margin-bottom:16px">
      <h2 class="section-title">${icon('user')} Workspace members</h2>
      ${isAdmin() ? `<div class="row wrap" style="margin-bottom:12px">
        <input class="input sm" id="mem-email" type="email" placeholder="Email of a registered user" style="flex:1;min-width:220px" />
        <select class="select sm" id="mem-role">${['read', 'write', 'admin'].map((r) => `<option value="${r}">${r}</option>`).join('')}</select>
        <button class="btn sm primary" id="mem-add">${icon('plus')} Add member</button></div>` : ''}
      <div id="mem-list"></div>
    </section>

    <section class="card" style="margin-bottom:16px">
      <h2 class="section-title">${icon('settings')} Account and workspaces</h2>
      <div class="grid-2">
        <div>
          <div class="label" style="margin-bottom:8px">Change password</div>
          <div class="field"><input class="input" id="pw-cur" type="password" placeholder="Current password" autocomplete="current-password" /></div>
          <div class="field" style="margin-top:8px"><input class="input" id="pw-new" type="password" placeholder="New password (min 8 characters)" autocomplete="new-password" /></div>
          <button class="btn sm" id="pw-save" style="margin-top:10px">${icon('check')} Update password</button>
        </div>
        <div>
          ${isAdmin() ? `<div class="label" style="margin-bottom:8px">Rename this workspace</div>
          <div class="row"><input class="input sm" id="ws-name" value="${esc(session.me.workspace?.name || '')}" style="flex:1" />
            <button class="btn sm" id="ws-rename">${icon('edit')} Rename</button></div>` : ''}
          <div class="label" style="margin:14px 0 8px">Create another workspace</div>
          <div class="row"><input class="input sm" id="ws-new" placeholder="Workspace name" style="flex:1" />
            <button class="btn sm" id="ws-create">${icon('plus')} Create</button></div>
        </div>
      </div>
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
  initWorkspaceSections(root, s);
}

function initWorkspaceSections(root, s) {
  const $ = (sel) => root.querySelector(sel);
  const me = session.me;

  $('#gl-save').addEventListener('click', async () => {
    const body = { gitlab_base_url: $('#gl-url').value.trim(), gitlab_username: $('#gl-user').value.trim() };
    if ($('#gl-token').value) body.gitlab_token = $('#gl-token').value;
    try {
      Object.assign(s, await api.put('/api/settings', body));
      $('#gl-token').value = '';
      $('#gl-token').placeholder = s.gitlab_token_set ? `Saved (${s.gitlab_token_hint}) — leave blank to keep` : 'glpat-…';
      toast('GitLab credentials saved');
    } catch (e) { toast(e.message, 'err'); }
  });

  const drawKeys = async () => {
    const keys = await api.get('/api/api-keys');
    $('#key-list').innerHTML = keys.length ? `<table class="table plain"><thead><tr><th>Name</th><th>Key</th><th>Role</th>
      ${isAdmin() ? '<th>Owner</th>' : ''}<th>Created</th><th>Last used</th><th>Expires</th><th></th></tr></thead><tbody>
      ${keys.map((k) => `<tr class="${k.revoked_at ? 'muted' : ''}"><td>${esc(k.name)}</td><td class="mono">sntl_${esc(k.prefix)}_…</td>
        <td><span class="badge">${esc(k.role)}</span></td>${isAdmin() ? `<td>${esc(k.email)}</td>` : ''}
        <td>${fmtDate(k.created_at)}</td><td>${k.last_used_at ? fmtDate(k.last_used_at) : '—'}</td>
        <td>${k.revoked_at ? 'Revoked' : k.expires_at ? fmtDate(k.expires_at) : 'Never'}</td>
        <td>${k.revoked_at ? '' : `<button class="btn sm danger" data-revoke="${k.id}">${icon('trash')} Revoke</button>`}</td></tr>`).join('')}
      </tbody></table>` : '<p class="small muted">No API keys yet.</p>';
  };
  $('#key-create').addEventListener('click', async () => {
    const name = $('#key-name').value.trim();
    if (!name) return toast('Give the key a name', 'err');
    try {
      const exp = $('#key-exp').value;
      const k = await api.post('/api/api-keys', { name, role: $('#key-role').value, expires_in_days: exp ? Number(exp) : null });
      $('#key-new').innerHTML = `<div class="test-result ok">Copy this key now — it will not be shown again:<br><code class="mono" style="user-select:all">${esc(k.key)}</code></div>`;
      $('#key-name').value = '';
      await drawKeys();
    } catch (e) { toast(e.message, 'err'); }
  });
  $('#key-list').addEventListener('click', async (e) => {
    const b = e.target.closest('[data-revoke]');
    if (!b || !(await confirmDialog('Revoke API key?', 'Applications using this key will lose access immediately.', 'Revoke'))) return;
    try { await api.del(`/api/api-keys/${b.dataset.revoke}`); await drawKeys(); toast('Key revoked'); } catch (err) { toast(err.message, 'err'); }
  });

  const drawMembers = async (rows) => {
    rows = rows || await api.get('/api/workspace/members');
    $('#mem-list').innerHTML = `<table class="table plain"><thead><tr><th>Name</th><th>Email</th><th>Role</th><th></th></tr></thead><tbody>
      ${rows.map((m) => `<tr><td>${esc(m.name)}</td><td>${esc(m.email)}</td><td>${isAdmin()
        ? `<select class="select sm" data-role="${m.user_id}">${['read', 'write', 'admin'].map((r) => `<option ${r === m.role ? 'selected' : ''}>${r}</option>`).join('')}</select>`
        : `<span class="badge">${esc(m.role)}</span>`}</td>
        <td>${isAdmin() && m.user_id !== me.user.id ? `<button class="btn sm danger" data-remove="${m.user_id}">${icon('trash')} Remove</button>` : ''}</td></tr>`).join('')}
      </tbody></table>`;
  };
  $('#mem-add')?.addEventListener('click', async () => {
    try {
      await drawMembers(await api.post('/api/workspace/members', { email: $('#mem-email').value.trim(), role: $('#mem-role').value }));
      $('#mem-email').value = '';
      toast('Member added');
    } catch (e) { toast(e.message, 'err'); }
  });
  $('#mem-list').addEventListener('change', async (e) => {
    const sel = e.target.closest('[data-role]');
    if (!sel) return;
    try { await drawMembers(await api.patch(`/api/workspace/members/${sel.dataset.role}`, { role: sel.value })); toast('Role updated'); }
    catch (err) { toast(err.message, 'err'); await drawMembers(); }
  });
  $('#mem-list').addEventListener('click', async (e) => {
    const b = e.target.closest('[data-remove]');
    if (!b || !(await confirmDialog('Remove member?', 'They lose access to this workspace and their API keys for it are revoked.', 'Remove'))) return;
    try { await drawMembers(await api.del(`/api/workspace/members/${b.dataset.remove}`)); } catch (err) { toast(err.message, 'err'); }
  });

  $('#pw-save').addEventListener('click', async () => {
    try {
      await api.post('/api/auth/password', { current_password: $('#pw-cur').value, new_password: $('#pw-new').value });
      $('#pw-cur').value = ''; $('#pw-new').value = '';
      toast('Password updated - other sessions were signed out');
    } catch (e) { toast(e.message, 'err'); }
  });
  $('#ws-rename')?.addEventListener('click', async () => {
    try { await api.patch('/api/workspace', { name: $('#ws-name').value.trim() }); await refreshSession(); toast('Workspace renamed'); }
    catch (e) { toast(e.message, 'err'); }
  });
  $('#ws-create').addEventListener('click', async () => {
    const name = $('#ws-new').value.trim();
    if (!name) return toast('Enter a workspace name', 'err');
    try { await api.post('/api/workspaces', { name }); location.hash = '#/'; location.reload(); }
    catch (e) { toast(e.message, 'err'); }
  });

  drawKeys().catch((e) => toast(e.message, 'err'));
  drawMembers().catch((e) => toast(e.message, 'err'));
}
