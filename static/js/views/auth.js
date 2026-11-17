import { api } from '../api.js';
import { esc, icon } from '../ui.js';

// Full-screen sign-in, registration and email verification. Calls onSignedIn(me) once a session exists.
export function renderAuth(root, { config, onSignedIn }) {
  let mode = 'login';
  let pendingEmail = '';
  let notice = '';

  const brand = `<div class="auth-brand">
      <span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24"><defs><linearGradient id="abm" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#8b5cf6"/><stop offset="1" stop-color="#22d3ee"/></linearGradient></defs><path fill="url(#abm)" d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3z"/><path d="m8.5 12 2.5 2.5 4.5-5" fill="none" stroke="#0b0f19" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
      <span class="brand-text"><strong>Sentinel</strong><small>AI Security Review</small></span></div>`;

  const field = (id, label, type = 'text', opts = {}) => `<div class="field"><label for="${id}">${label}</label>
    <input class="input" id="${id}" name="${id}" type="${type}" value="${esc(opts.value || '')}" autocomplete="${opts.ac || 'off'}"
      ${opts.required === false ? '' : 'required'} ${opts.min ? `minlength="${opts.min}"` : ''} ${opts.extra || ''} /></div>`;

  const forms = {
    login: () => `<h1>Sign in</h1>
      ${config.demo ? `<div class="auth-hint">${icon('info')}<span>Demo login: <b class="mono">demo</b> / <b class="mono">demo</b></span></div>` : ''}
      <form id="auth-form" class="auth-form">
        ${field('login', 'Email or username', 'text', { ac: 'username' })}
        ${field('password', 'Password', 'password', { ac: 'current-password' })}
        <button class="btn primary" type="submit">${icon('lock')} Sign in</button>
      </form>
      ${config.registration ? `<p class="auth-switch">New here? <a href="#" data-mode="register">Create an account</a></p>` : ''}`,
    register: () => `<h1>Create an account</h1>
      <p class="muted small">You get your own workspace. A verification code is printed to the server console.</p>
      <form id="auth-form" class="auth-form">
        ${field('name', 'Name', 'text', { ac: 'name', required: false })}
        ${field('email', 'Email', 'email', { ac: 'email' })}
        ${field('password', 'Password (min 8 characters)', 'password', { ac: 'new-password', min: 8 })}
        ${field('workspace_name', 'Workspace name', 'text', { required: false })}
        <button class="btn primary" type="submit">${icon('user')} Register</button>
      </form>
      <p class="auth-switch">Already registered? <a href="#" data-mode="login">Sign in</a> · <a href="#" data-mode="verify">Enter a code</a></p>`,
    verify: () => `<h1>Verify your email</h1>
      <p class="muted small">Enter the 6-digit code printed in the server console (<span class="mono">docker compose logs api</span>).</p>
      <form id="auth-form" class="auth-form">
        ${field('email', 'Email', 'email', { ac: 'email', value: pendingEmail })}
        ${field('code', 'Verification code', 'text', { ac: 'one-time-code', min: 6, extra: 'maxlength="6" inputmode="numeric" pattern="[0-9]{6}"' })}
        <button class="btn primary" type="submit">${icon('check')} Verify and sign in</button>
      </form>
      <p class="auth-switch"><a href="#" id="resend">Print a new code</a> · <a href="#" data-mode="login">Back to sign in</a></p>`,
  };

  const draw = () => {
    root.innerHTML = `<div class="auth-wrap"><div class="card auth-card">${brand}
      ${notice ? `<div class="auth-notice">${esc(notice)}</div>` : ''}
      <div id="auth-error" class="auth-error" hidden></div>
      ${forms[mode]()}</div></div>`;
    root.querySelector('input')?.focus();
  };

  const showError = (msg) => {
    const el = root.querySelector('#auth-error');
    el.textContent = msg;
    el.hidden = false;
  };

  root.onclick = async (e) => {
    const link = e.target.closest('[data-mode]');
    if (link) {
      e.preventDefault();
      mode = link.dataset.mode;
      notice = '';
      draw();
      return;
    }
    if (e.target.closest('#resend')) {
      e.preventDefault();
      const email = root.querySelector('#email')?.value.trim();
      if (!email) return showError('Enter your email first');
      try {
        await api.post('/api/auth/resend', { email });
        pendingEmail = email;
        notice = 'If that account is awaiting verification, a new code was printed to the server console.';
        draw();
      } catch (err) { showError(err.message); }
    }
  };

  root.onsubmit = async (e) => {
    e.preventDefault();
    const btn = root.querySelector('button[type="submit"]');
    const v = Object.fromEntries(new FormData(e.target).entries());
    btn.disabled = true;
    try {
      if (mode === 'login') {
        onSignedIn(await api.post('/api/auth/login', { login: v.login.trim(), password: v.password }));
      } else if (mode === 'register') {
        await api.post('/api/auth/register', { email: v.email.trim(), password: v.password, name: v.name.trim(),
          workspace_name: v.workspace_name.trim() });
        pendingEmail = v.email.trim();
        mode = 'verify';
        notice = 'Account created. Your verification code was printed to the server console.';
        draw();
      } else {
        onSignedIn(await api.post('/api/auth/verify', { email: v.email.trim(), code: v.code.trim() }));
      }
    } catch (err) {
      if (mode === 'login' && /not verified/i.test(err.message)) {
        pendingEmail = v.login.trim();
        mode = 'verify';
        notice = 'Your email is not verified yet. Enter the code from the server console, or print a new one.';
        draw();
        return;
      }
      showError(err.message);
      btn.disabled = false;
    }
  };

  draw();
}
