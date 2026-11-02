// AI writing assistant attached to any text field: "Improve wording" restructures the user's own
// text, "Draft with AI" writes from the review context. Both are deterministic (temperature 0 +
// cache) with Gemini, and fall back to offline rules when no provider is configured.
import { api } from './api.js';
import { esc, icon, toast } from './ui.js';

let uid = 0;

/** HTML for a textarea / input with the ✨ AI button. */
export function aiField({ id, field, value = '', rows = 3, placeholder = '', input = false, aiField: aiKey, attrs = '' }) {
  const fid = id || `ai-${field}-${++uid}`;
  const key = aiKey || field;
  const ctl = input
    ? `<input class="input" id="${fid}" data-field="${esc(field)}" value="${esc(value)}" placeholder="${esc(placeholder)}" ${attrs} />`
    : `<textarea class="textarea" id="${fid}" data-field="${esc(field)}" rows="${rows}" placeholder="${esc(placeholder)}" ${attrs}>${esc(value)}</textarea>`;
  return `<div class="ai-wrap"><div class="ai-field" data-ai="${esc(key)}">${ctl}
    <button type="button" class="ai-btn" title="AI writing assistant" aria-label="AI writing assistant" id="${fid}-ai">${icon('sparkles')}</button></div>
    <div class="ai-note" hidden></div></div>`;
}

const undoStack = new WeakMap();

function closeMenus(except) {
  document.querySelectorAll('.ai-field .menu').forEach((m) => { if (m !== except) m.remove(); });
}
document.addEventListener('click', (e) => { if (!e.target.closest('.ai-field')) closeMenus(); });

/**
 * Wire every .ai-field inside container. ctxFn(fieldEl) -> {review_id, item_id?, mitigation_id?}.
 * Changing the value dispatches an `input` event so existing autosave handlers run.
 */
export function wireAi(container, ctxFn) {
  container.addEventListener('click', async (e) => {
    const btn = e.target.closest('.ai-btn');
    const choice = e.target.closest('[data-ai-mode]');
    if (!btn && !choice) return;
    const wrap = (btn || choice).closest('.ai-field');
    if (!wrap || !container.contains(wrap)) return;
    e.preventDefault();
    e.stopPropagation();
    const ctl = wrap.querySelector('textarea, input');
    if (btn) {
      const open = wrap.querySelector('.menu');
      closeMenus();
      if (open) return;
      const has = ctl.value.trim().length > 0;
      const canUndo = (undoStack.get(ctl) || []).length > 0;
      const m = document.createElement('div');
      m.className = 'menu right';
      m.innerHTML = `
        <button data-ai-mode="improve" ${has ? '' : 'disabled style="opacity:.45;cursor:not-allowed"'}>${icon('wand')}<span>Improve wording<small>${has ? 'Restructures your text — keeps your facts' : 'Write something first'}</small></span></button>
        <button data-ai-mode="draft">${icon('sparkles')}<span>${has ? 'Rewrite from context' : 'Draft with AI'}<small>Uses the review profile, design and linked controls</small></span></button>
        ${canUndo ? `<hr /><button data-ai-mode="undo">${icon('undo')}<span>Undo last AI change</span></button>` : ''}`;
      wrap.appendChild(m);
      return;
    }
    const mode = choice.dataset.aiMode;
    if (choice.disabled) return;
    closeMenus();
    if (mode === 'undo') return undo(ctl, wrap);
    await run(ctl, wrap, mode, ctxFn(ctl));
  });
}

function setValue(ctl, v) {
  ctl.value = v;
  ctl.dispatchEvent(new Event('input', { bubbles: true }));
  ctl.dispatchEvent(new Event('change', { bubbles: true }));
}

function undo(ctl, wrap) {
  const stack = undoStack.get(ctl) || [];
  if (!stack.length) return;
  setValue(ctl, stack.pop());
  const note = wrap.parentElement.querySelector('.ai-note');
  if (note) { note.hidden = !stack.length; if (!stack.length) note.innerHTML = ''; }
}

async function run(ctl, wrap, mode, ctx) {
  wrap.classList.add('busy');
  ctl.readOnly = true;
  try {
    const res = await api.post('/api/ai/write', { ...ctx, field: wrap.dataset.ai, text: ctl.value, mode });
    const stack = undoStack.get(ctl) || [];
    stack.push(ctl.value);
    undoStack.set(ctl, stack.slice(-10));
    setValue(ctl, res.text);
    const note = wrap.parentElement.querySelector('.ai-note');
    if (note) {
      note.hidden = false;
      note.innerHTML = `${icon('sparkles')}<span>${res.mode === 'improve' ? 'Reworded' : 'Drafted'} by <b>${esc(res.source === 'ai' ? res.provider : 'offline rules')}</b>${res.cached ? ' · cached' : ''}</span><button type="button" data-undo>Undo</button>`;
      note.querySelector('svg').style.cssText = 'width:12px;height:12px;color:#c4b5fd';
      note.querySelector('[data-undo]').addEventListener('click', () => undo(ctl, wrap));
    }
    if (res.warning) toast(res.warning, 'warn', 6000);
  } catch (e) {
    toast(e.message, 'err');
  } finally {
    wrap.classList.remove('busy');
    ctl.readOnly = false;
  }
}
