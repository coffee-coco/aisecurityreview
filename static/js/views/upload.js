// Drag-and-drop upload zone shared by documents, code and the New review form.
import { esc, icon } from '../ui.js';

export const DOC_ACCEPT = '.pdf,.docx,.pptx,.vsdx,.drawio,.svg,.txt,.md,.markdown,.json,.yaml,.yml,.csv,.html,.htm,.xml,.puml,.mmd,.rtf,.png,.jpg,.jpeg,.gif,.webp,.bmp';
export const CODE_ACCEPT = '.zip,.tar,.tgz,.gz,.py,.js,.mjs,.cjs,.ts,.tsx,.jsx,.java,.kt,.go,.rb,.php,.cs,.rs,.swift,.scala,.c,.cc,.cpp,.h,.hpp,.sql,.sh,.ps1,.tf,.tfvars,.hcl,.yaml,.yml,.json,.toml,.ini,.cfg,.env,.xml,.gradle,.properties,.dockerfile,.bicep,.vue,.svelte,.html,.css,.txt,.md,Dockerfile';

export function dropzone({ id, accept, title, sub, iconName = 'upload', sm = false, multiple = true }) {
  return `<label class="dropzone ${sm ? 'sm' : ''}" id="${id}" for="${id}-input">
    <input type="file" id="${id}-input" ${multiple ? 'multiple' : ''} accept="${esc(accept)}" />
    <div class="ic">${icon(iconName)}</div><strong>${esc(title)}</strong><small>${sub}</small>
    <div class="file-pills" data-pills></div></label>`;
}

/** onFiles(File[]) is called on drop or pick. */
export function wireDrop(zone, onFiles) {
  const input = zone.querySelector('input[type=file]');
  input.addEventListener('change', () => { if (input.files.length) onFiles([...input.files]); input.value = ''; });
  ['dragenter', 'dragover'].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove('drag'); }));
  zone.addEventListener('drop', (e) => { const f = [...(e.dataTransfer?.files || [])]; if (f.length) onFiles(f); });
}

export const fmtSize = (n) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n > 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`);
