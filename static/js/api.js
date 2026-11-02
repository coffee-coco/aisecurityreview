// Thin fetch wrapper for the FastAPI backend.
async function request(method, url, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  if (res.status === 204) return null;
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('application/json') ? await res.json() : await res.text();
  if (!res.ok) {
    let msg = typeof data === 'string' ? data : data?.detail;
    if (Array.isArray(msg)) msg = msg.map((d) => `${d.loc?.slice(-1)[0]}: ${d.msg}`).join(', ');
    throw new Error(msg || `Request failed (${res.status})`);
  }
  return data;
}

export const api = {
  get: (u) => request('GET', u),
  post: (u, b) => request('POST', u, b ?? {}),
  put: (u, b) => request('PUT', u, b),
  patch: (u, b) => request('PATCH', u, b),
  del: (u) => request('DELETE', u),
};

/** Multipart upload (FormData) - the browser sets the multipart boundary header. */
export async function upload(url, formData) {
  const res = await fetch(url, { method: 'POST', body: formData });
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('application/json') ? await res.json() : await res.text();
  if (!res.ok) {
    let msg = typeof data === 'string' ? data : data?.detail;
    if (Array.isArray(msg)) msg = msg.map((d) => `${d.loc?.slice(-1)[0]}: ${d.msg}`).join(', ');
    throw new Error(msg || `Upload failed (${res.status})`);
  }
  return data;
}

/** Poll a background job until it finishes. onProgress(job) is called on every tick. */
export function pollJob(id, onProgress, ms = 700) {
  return new Promise((resolve, reject) => {
    let stopped = false;
    const tick = async () => {
      if (stopped) return;
      try {
        const j = await api.get(`/api/jobs/${id}`);
        onProgress?.(j);
        if (j.status === 'done') return resolve(j);
        if (j.status === 'error') return reject(new Error(j.error || 'Job failed'));
      } catch (e) { return reject(e); }
      setTimeout(tick, ms);
    };
    tick();
  });
}

// Cached metadata (catalog versions, providers, statuses).
let metaPromise = null;
export function getMeta(force = false) {
  if (!metaPromise || force) metaPromise = api.get('/api/meta');
  return metaPromise;
}
let treePromise = null;
export function getTree() {
  if (!treePromise) treePromise = api.get('/api/catalog/tree');
  return treePromise;
}
