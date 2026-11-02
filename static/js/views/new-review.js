import { api, getMeta } from '../api.js';
import { esc, icon, scopingOverlay, toast } from '../ui.js';
import { refreshSidebar } from '../app.js';

const STACK_SUGGESTIONS = ['AWS', 'Azure', 'GCP', 'Kubernetes', 'Docker', 'Terraform', 'GitHub Actions', 'GitLab CI', 'OpenAPI', 'Okta', 'SaaS'];
const FLAGS = [
  { k: 'internet_facing', icon: 'globe', title: 'Internet-facing', sub: 'Reachable from the public internet or by customers' },
  { k: 'personal_data', icon: 'fingerprint', title: 'Personal / sensitive data', sub: 'PII, financial, health or credential data' },
  { k: 'third_party', icon: 'building', title: 'Third party involved', sub: 'Vendor, SaaS, outsourced or partner integration' },
  { k: 'uses_ai', icon: 'cpu', title: 'Uses AI / ML', sub: 'LLMs, ML models or AI-powered features' },
];

export async function render(root) {
  const meta = await getMeta();
  const c = meta.catalog.counts;
  const aiOn = meta.ai.provider && meta.ai.provider !== 'heuristic';
  root.innerHTML = `
  <div class="page">
    <a href="#/" class="back">${icon('left')} Back to queue</a>
    <div class="page-head">
      <div>
        <div class="eyebrow">${icon('sparkles')} Intake</div>
        <h1>Request a <span class="grad-text">security review</span></h1>
        <p>Describe the new initiative or change. The more context you give — platforms, data, integrations — the sharper the AI scoping.</p>
      </div>
    </div>
    <div class="new-grid">
      <form id="new-form" autocomplete="off">
        <section class="card form-section">
          <div class="sec-head"><div class="sec-num">1</div><div><h2>What's changing?</h2><p>The initiative, system or change under review</p></div></div>
          <div class="stack">
            <div class="field"><label for="f-title">Title</label>
              <input class="input" id="f-title" name="title" required minlength="3" placeholder="e.g. Customer self-service portal on AWS" /></div>
            <div class="field"><label>Type</label>
              <div class="seg lg" id="f-type">
                <button type="button" data-v="new" class="on" id="type-new">${icon('sparkles')} New initiative</button>
                <button type="button" data-v="change" id="type-change">${icon('refresh')} Change to existing</button>
              </div></div>
            <div class="field"><label for="f-desc">Description</label>
              <textarea class="textarea" id="f-desc" name="description" rows="7" placeholder="What is being built or changed, who uses it, what data it handles, how it's hosted and deployed, and which systems or suppliers it integrates with…"></textarea>
              <span class="hint">Tip: mention cloud services (S3, RDS, Key Vault…), identity provider, CI/CD and any SaaS vendors.</span></div>
            <div class="field"><label for="f-stack">Technology stack</label>
              <input class="input" id="f-stack" name="tech_stack" placeholder="e.g. AWS (Lambda, API Gateway, RDS), Terraform, GitHub Actions" />
              <div class="suggest" id="stack-suggest">${STACK_SUGGESTIONS.map((s) => `<button type="button" data-s="${s}">+ ${s}</button>`).join('')}</div></div>
          </div>
        </section>

        <section class="card form-section">
          <div class="sec-head"><div class="sec-num">2</div><div><h2>Risk profile</h2><p>Drives which NIST requirements are pulled in</p></div></div>
          <div class="stack">
            <div class="field"><label>Data classification</label>
              <div class="seg lg" id="f-class">
                ${['public', 'internal', 'confidential', 'restricted'].map((v) => `<button type="button" data-v="${v}" class="${v === 'internal' ? 'on' : ''}" id="class-${v}">${v[0].toUpperCase() + v.slice(1)}</button>`).join('')}
              </div></div>
            <div class="grid-2">
              ${FLAGS.map((f) => `<label class="toggle-card" id="flag-${f.k}"><input type="checkbox" name="${f.k}" />
                <span class="ic">${icon(f.icon)}</span><span><strong>${f.title}</strong><small>${f.sub}</small></span>
                <span class="check">${icon('check')}</span></label>`).join('')}
            </div>
          </div>
        </section>

        <section class="card form-section">
          <div class="sec-head"><div class="sec-num">3</div><div><h2>People & timing</h2><p>Who asked, who owns it, and when it's needed</p></div></div>
          <div class="grid-2">
            <div class="field"><label for="f-req">Requester</label><input class="input" id="f-req" name="requester" placeholder="Name of submitter" /></div>
            <div class="field"><label for="f-owner">Business owner</label><input class="input" id="f-owner" name="business_owner" placeholder="Accountable executive" /></div>
            <div class="field"><label for="f-bu">Business unit</label><input class="input" id="f-bu" name="business_unit" placeholder="e.g. Digital, Retail Banking" /></div>
            <div class="field"><label for="f-rev">Security reviewer</label><input class="input" id="f-rev" name="reviewer" placeholder="Assigned architect" /></div>
            <div class="field"><label for="f-pri">Priority</label>
              <select class="select" id="f-pri" name="priority"><option value="low">Low</option><option value="medium" selected>Medium</option><option value="high">High</option><option value="critical">Critical</option></select></div>
            <div class="field"><label for="f-due">Review due</label><input class="input" type="date" id="f-due" name="due_date" /></div>
          </div>
        </section>
      </form>

      <aside class="sticky stack">
        <div class="card glow">
          <h2 class="section-title">${icon('layers')} How the review is built</h2>
          <div class="pipeline">
            <div class="pipe-step" style="--c:#a78bfa"><div class="ic">${icon('file')}</div><div><strong>Intake</strong><small>Your description, stack and risk profile</small></div></div>
            <div class="pipe-step" style="--c:#e879f9"><div class="ic">${icon('sparkles')}</div><div><strong>AI scoping</strong><small>${aiOn ? `Using <span class="num">${esc(meta.ai.provider)}</span> to select relevant requirements` : 'Offline rules (configure an AI provider in Settings)'}</small></div></div>
            <div class="pipe-step" style="--c:#38bdf8"><div class="ic">${icon('target')}</div><div><strong>NIST CSF 2.0 questions</strong><small><span class="num">${c.subcategories}</span> outcomes across <span class="num">${c.functions}</span> functions${(meta.frameworks || []).length > 1 ? `, plus ${meta.frameworks.slice(1).map((f) => esc(f.short)).join(', ')} when the profile calls for them` : ''}</small></div></div>
            <div class="pipe-step" style="--c:#34d399"><div class="ic">${icon('shield')}</div><div><strong>SP 800-53 Rev 5 controls</strong><small><span class="num">${c.controls}</span> controls via NIST's official mappings</small></div></div>
            <div class="pipe-step" style="--c:#fbbf24"><div class="ic">${icon('code')}</div><div><strong>Checkov checks</strong><small><span class="num">${c.checks}</span> IaC policies filtered to your platforms</small></div></div>
          </div>
        </div>
        <div class="card">
          <label class="row" style="cursor:pointer;justify-content:space-between" for="f-auto">
            <span><strong style="font-size:13px">Run AI scoping on submit</strong><br><span class="small muted">Generate requirements immediately</span></span>
            <span class="switch"><input type="checkbox" id="f-auto" checked /><span></span></span>
          </label>
          <hr class="divider" />
          <button class="btn primary" style="width:100%;height:44px" id="submit-review" form="new-form" type="submit">${icon('sparkles')} Submit for review</button>
        </div>
      </aside>
    </div>
  </div>`;

  const form = root.querySelector('#new-form');
  const segVal = (id) => root.querySelector(`#${id} button.on`).dataset.v;
  root.querySelectorAll('.seg').forEach((seg) => seg.addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    seg.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === b));
  }));
  root.querySelectorAll('.toggle-card input').forEach((inp) => inp.addEventListener('change', () =>
    inp.closest('.toggle-card').classList.toggle('on', inp.checked)));
  root.querySelector('#stack-suggest').addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    const inp = root.querySelector('#f-stack');
    const cur = inp.value.split(',').map((s) => s.trim()).filter(Boolean);
    if (!cur.includes(b.dataset.s)) inp.value = [...cur, b.dataset.s].join(', ');
    if (b.dataset.s === 'SaaS') { const t = root.querySelector('#flag-third_party input'); t.checked = true; t.dispatchEvent(new Event('change')); }
    b.remove();
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const body = {
      title: fd.get('title').trim(),
      description: fd.get('description').trim(),
      tech_stack: fd.get('tech_stack').trim(),
      change_type: segVal('f-type'),
      data_classification: segVal('f-class'),
      requester: fd.get('requester').trim(),
      business_owner: fd.get('business_owner').trim(),
      business_unit: fd.get('business_unit').trim(),
      reviewer: fd.get('reviewer').trim(),
      priority: fd.get('priority'),
      due_date: fd.get('due_date') || '',
      auto_scope: root.querySelector('#f-auto').checked,
    };
    for (const f of FLAGS) body[f.k] = !!fd.get(f.k);
    const btn = root.querySelector('#submit-review');
    btn.disabled = true;
    const stop = body.auto_scope ? scopingOverlay() : () => {};
    try {
      const r = await api.post('/api/reviews', body);
      stop();
      if (r.ai_meta?.warning) toast(r.ai_meta.warning, 'warn', 7000);
      else toast(`${r.ref} created${body.auto_scope ? ` with ${r.requirements.length} requirements` : ''}`);
      refreshSidebar();
      location.hash = `#/review/${r.id}`;
    } catch (err) {
      stop();
      btn.disabled = false;
      toast(err.message, 'err', 6000);
    }
  });
}
