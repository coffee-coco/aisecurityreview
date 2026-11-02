import { api } from '../api.js';
import { STATUS, animateCount, esc, fmtDate, icon, isOverdue, riskBadge, statusBadge, timeAgo, toast, debounce } from '../ui.js';

let mode = localStorage.getItem('queueMode') || 'board';

export async function render(root) {
  root.innerHTML = `
  <div class="page">
    <div class="page-head">
      <div>
        <div class="eyebrow">${icon('shield')} Security architecture</div>
        <h1>Review <span class="grad-text">queue</span></h1>
        <p>Every new initiative and change awaiting a security design review. Drag cards between columns to move them through the workflow.</p>
      </div>
      <a href="#/new" class="btn primary" id="queue-new-btn">${icon('plus')} New review</a>
    </div>
    <div class="stats" id="stats"></div>
    <div class="toolbar">
      <div class="search">${icon('search')}<input class="input" id="queue-search" placeholder="Search title, business unit, requester…" /></div>
      <div class="spacer"></div>
      <div class="seg" id="mode-seg">
        <button data-m="board" id="mode-board">${icon('columns')} Board</button>
        <button data-m="list" id="mode-list">${icon('list')} List</button>
      </div>
    </div>
    <div id="queue-body"></div>
  </div>`;

  let reviews = [];
  let filter = '';
  let statusFilter = '';

  const load = async () => {
    const [stats, rows] = await Promise.all([
      api.get('/api/stats'),
      api.get(`/api/reviews?q=${encodeURIComponent(filter)}`),
    ]);
    reviews = rows;
    renderStats(stats);
    draw();
  };

  const renderStats = (stats) => {
    const items = [
      ...Object.entries(STATUS).map(([k, v]) => ({ k, label: v.label, color: v.color, n: stats.by_status[k] || 0 })),
      { k: 'overdue', label: 'Overdue', color: '#fb7185', n: stats.overdue },
    ];
    const el = root.querySelector('#stats');
    el.innerHTML = items.map((s) => `
      <div class="stat ${statusFilter === s.k ? 'active' : ''}" style="--c:${s.color}" data-k="${s.k}" id="stat-${s.k}">
        <div class="lbl"><span class="d"></span>${s.label}</div>
        <div class="val" data-n="${s.n}">0</div>
      </div>`).join('');
    el.querySelectorAll('.val').forEach((v) => animateCount(v, +v.dataset.n));
    el.querySelectorAll('.stat').forEach((s) => s.addEventListener('click', () => {
      statusFilter = statusFilter === s.dataset.k ? '' : s.dataset.k;
      el.querySelectorAll('.stat').forEach((x) => x.classList.toggle('active', x.dataset.k === statusFilter));
      draw();
    }));
  };

  const visible = () => reviews.filter((r) =>
    !statusFilter || (statusFilter === 'overdue' ? isOverdue(r) : r.status === statusFilter));

  const card = (r) => {
    const pct = r.req_total ? Math.round((r.req_done / r.req_total) * 100) : 0;
    return `
    <a class="rcard" href="#/review/${r.id}" draggable="true" data-id="${r.id}" id="rcard-${r.id}">
      <div class="top"><span class="ref">${r.ref}</span>
        <span class="badge" style="height:19px;font-size:10.5px">${r.change_type === 'new' ? 'New' : 'Change'}</span>
        <span class="pri pri-${esc(r.priority)}" title="${esc(r.priority)} priority"></span></div>
      <h3>${esc(r.title)}</h3>
      <div class="meta">${esc([r.business_unit, r.requester].filter(Boolean).join(' · ') || 'No owner set')}</div>
      <div class="badges">${riskBadge(r.risk_rating)}${r.technologies.slice(0, 3).map((t) => `<span class="badge">${esc(t)}</span>`).join('')}${r.technologies.length > 3 ? `<span class="badge">+${r.technologies.length - 3}</span>` : ''}</div>
      <div class="progress" title="${r.req_done}/${r.req_total} requirements assessed"><i style="width:${pct}%"></i></div>
      <div class="foot">
        <span>${icon('check')}${r.req_done}/${r.req_total}</span>
        ${r.req_gaps ? `<span class="gaps">${icon('alert')}${r.req_gaps} gap${r.req_gaps === 1 ? '' : 's'}</span>` : ''}
        ${r.checks_failed ? `<span class="gaps">${icon('code')}${r.checks_failed} failed</span>` : ''}
        <span class="spacer"></span>
        ${r.due_date ? `<span class="${isOverdue(r) ? 'late' : ''}">${icon('calendar')}${fmtDate(r.due_date)}</span>` : `<span>${timeAgo(r.updated_at)}</span>`}
      </div>
    </a>`;
  };

  const draw = () => {
    root.querySelectorAll('#mode-seg button').forEach((b) => b.classList.toggle('on', b.dataset.m === mode));
    const body = root.querySelector('#queue-body');
    const rows = visible();
    if (!reviews.length && !filter) {
      body.innerHTML = `<div class="card empty"><div class="ic">${icon('sparkles')}</div>
        <h3>No security reviews yet</h3>
        <p>Submit a new initiative or change and the AI will scope it against NIST CSF 2.0,<br>map SP 800-53 controls and attach the relevant Checkov checks.</p>
        <a href="#/new" class="btn primary" style="margin-top:14px" id="empty-new-btn">${icon('plus')} Start a review</a></div>`;
      return;
    }
    if (mode === 'list') {
      body.innerHTML = `<div class="card" style="padding:6px 4px"><table class="table"><thead><tr>
        <th>Ref</th><th>Title</th><th>Status</th><th>Risk</th><th>Progress</th><th>Owner</th><th>Due</th></tr></thead><tbody>
        ${rows.map((r) => `<tr data-id="${r.id}">
          <td class="mono muted">${r.ref}</td>
          <td><strong>${esc(r.title)}</strong><div class="small muted">${r.change_type === 'new' ? 'New initiative' : 'Change'} · ${esc(r.business_unit || '—')}</div></td>
          <td>${statusBadge(r.status)}</td><td>${riskBadge(r.risk_rating)}</td>
          <td style="min-width:140px"><div class="progress"><i style="width:${r.req_total ? (r.req_done / r.req_total) * 100 : 0}%"></i></div><div class="small muted" style="margin-top:4px">${r.req_done}/${r.req_total}${r.req_gaps ? ` · <span style="color:#fdba74">${r.req_gaps} gap${r.req_gaps === 1 ? '' : 's'}</span>` : ''}</div></td>
          <td class="small">${esc(r.business_owner || r.requester || '—')}</td>
          <td class="small ${isOverdue(r) ? '' : 'muted'}" style="${isOverdue(r) ? 'color:#fda4af' : ''}">${r.due_date ? fmtDate(r.due_date) : '—'}</td>
        </tr>`).join('') || `<tr><td colspan="7" class="muted" style="text-align:center;padding:30px">No matching reviews</td></tr>`}
        </tbody></table></div>`;
      body.querySelectorAll('tr[data-id]').forEach((tr) => tr.addEventListener('click', () => { location.hash = `#/review/${tr.dataset.id}`; }));
      return;
    }
    body.innerHTML = `<div class="board">${Object.entries(STATUS).map(([k, v]) => {
      const col = rows.filter((r) => r.status === k);
      return `<div class="col" data-status="${k}" style="--c:${v.color}" id="col-${k}">
        <div class="col-head"><span class="d"></span>${v.label}<span class="n">${col.length}</span></div>
        <div class="col-body">${col.map(card).join('') || '<div class="empty-col">Drop reviews here</div>'}</div></div>`;
    }).join('')}</div>`;
    wireDnD(body);
  };

  const wireDnD = (body) => {
    body.querySelectorAll('.rcard').forEach((c) => {
      c.addEventListener('dragstart', (e) => { e.dataTransfer.setData('text/plain', c.dataset.id); c.classList.add('dragging'); });
      c.addEventListener('dragend', () => c.classList.remove('dragging'));
    });
    body.querySelectorAll('.col').forEach((col) => {
      col.addEventListener('dragover', (e) => { e.preventDefault(); col.classList.add('drop'); });
      col.addEventListener('dragleave', (e) => { if (!col.contains(e.relatedTarget)) col.classList.remove('drop'); });
      col.addEventListener('drop', async (e) => {
        e.preventDefault();
        col.classList.remove('drop');
        const id = +e.dataTransfer.getData('text/plain');
        const r = reviews.find((x) => x.id === id);
        if (!r || r.status === col.dataset.status) return;
        const prev = r.status;
        r.status = col.dataset.status;
        draw();
        try {
          await api.patch(`/api/reviews/${id}`, { status: r.status });
          toast(`${r.ref} moved to ${STATUS[r.status].label}`);
          renderStats(await api.get('/api/stats'));
        } catch (err) {
          r.status = prev; draw(); toast(err.message, 'err');
        }
      });
    });
  };

  root.querySelectorAll('#mode-seg button').forEach((b) => b.addEventListener('click', () => {
    mode = b.dataset.m; localStorage.setItem('queueMode', mode); draw();
  }));
  root.querySelector('#queue-search').addEventListener('input', debounce((e) => { filter = e.target.value; load(); }, 250));

  await load();
}
