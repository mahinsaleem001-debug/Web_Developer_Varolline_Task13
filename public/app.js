// Vault front-end. No framework, no inline scripts/styles (the CSP forbids them).
// All user-controlled text (file names, emails) is written with textContent, never innerHTML.

const $ = (id) => document.getElementById(id);
const ALLOWED = {
  'image/jpeg': ['jpg', 'jpeg'],
  'image/png': ['png'],
  'image/webp': ['webp'],
  'image/gif': ['gif'],
  'application/pdf': ['pdf'],
  'text/plain': ['txt'],
};
const MAX_PARALLEL = 3;

const state = { csrf: '', cursor: null, mode: 'login', maxBytes: 10 * 1024 * 1024, viewing: null };

/* ------------------------------ helpers ------------------------------ */

async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['X-CSRF-Token'] = state.csrf;
  const res = await fetch(path, { method, headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) });
  if (res.status === 204) return null;
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON error */ }
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/api/auth/')) showAuth();
    const err = new Error(data?.error?.message || `Request failed (${res.status})`);
    err.code = data?.error?.code;
    err.status = res.status;
    throw err;
  }
  return data;
}

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  node.append(...children);
  return node;
}

function toast(message, bad = false) {
  const t = el('div', { class: bad ? 'toast bad' : 'toast', text: message });
  $('toasts').append(t);
  setTimeout(() => t.remove(), 4500);
}

const fmtSize = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1048576).toFixed(1)} MB`);
const fmtDate = (ms) => new Date(ms).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });

/* ------------------------------ auth ------------------------------ */

function showAuth() {
  $('app-view').hidden = true;
  $('userbar').hidden = true;
  $('auth-view').hidden = false;
}

function showApp(user) {
  $('auth-view').hidden = true;
  $('app-view').hidden = false;
  $('userbar').hidden = false;
  $('user-email').textContent = user.email;
  $('max-mb').textContent = String(Math.round(state.maxBytes / 1048576));
  loadGallery(true);
}

function setMode(mode) {
  state.mode = mode;
  const reg = mode === 'register';
  $('tab-login').setAttribute('aria-selected', String(!reg));
  $('tab-register').setAttribute('aria-selected', String(reg));
  $('auth-submit').textContent = reg ? 'Create account' : 'Sign in';
  $('pw-hint').hidden = !reg;
  $('password').autocomplete = reg ? 'new-password' : 'current-password';
  $('auth-error').hidden = true;
}

$('tab-login').addEventListener('click', () => setMode('login'));
$('tab-register').addEventListener('click', () => setMode('register'));

$('auth-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('auth-error');
  err.hidden = true;
  $('auth-submit').disabled = true;
  try {
    const data = await api(`/api/auth/${state.mode}`, { method: 'POST', body: { email: $('email').value, password: $('password').value } });
    state.csrf = data.csrfToken;
    $('password').value = '';
    showApp(data.user);
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  } finally {
    $('auth-submit').disabled = false;
  }
});

$('logout').addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST' }); } catch { /* ignore */ }
  state.csrf = '';
  $('gallery').replaceChildren();
  $('queue').replaceChildren();
  showAuth();
});

/* ------------------------------ upload ------------------------------ */

const dz = $('dropzone');
const input = $('file-input');
dz.addEventListener('click', () => input.click());
dz.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
for (const ev of ['dragenter', 'dragover']) dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('over'); });
for (const ev of ['dragleave', 'drop']) dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('over'); });
dz.addEventListener('drop', (e) => enqueue([...e.dataTransfer.files]));
input.addEventListener('change', () => { enqueue([...input.files]); input.value = ''; });

const pending = [];
let running = 0;

function enqueue(files) {
  for (const file of files) {
    const row = el('li', {},
      el('span', { class: 'name', text: file.name }),
      el('span', { class: 'state', text: 'Waiting...' }),
      el('progress', { max: '100', value: '0', 'aria-label': `Upload progress for ${file.name}` }),
    );
    $('queue').prepend(row);
    pending.push({ file, row });
  }
  pump();
}

function pump() {
  while (running < MAX_PARALLEL && pending.length) {
    const job = pending.shift();
    running++;
    uploadOne(job).finally(() => { running--; pump(); });
  }
}

function precheck(file) {
  // Convenience only. The server enforces every one of these rules again.
  const ext = file.name.includes('.') ? file.name.split('.').pop().toLowerCase() : '';
  if (!ALLOWED[file.type]) return 'This file type is not allowed';
  if (!ALLOWED[file.type].includes(ext)) return 'The file extension does not match its type';
  if (file.size === 0) return 'The file is empty';
  if (file.size > state.maxBytes) return `Larger than ${Math.round(state.maxBytes / 1048576)} MB`;
  return null;
}

async function uploadOne({ file, row }) {
  const stateEl = row.querySelector('.state');
  const bar = row.querySelector('progress');
  const fail = (msg) => { stateEl.textContent = msg; stateEl.className = 'state bad'; bar.hidden = true; };

  const problem = precheck(file);
  if (problem) return fail(problem);

  try {
    stateEl.textContent = 'Preparing...';
    const slot = await api('/api/uploads', { method: 'POST', body: { name: file.name, type: file.type, size: file.size } });

    stateEl.textContent = 'Uploading...';
    await putToStorage(slot.url, slot.headers, file, (pct) => { bar.value = pct; });

    stateEl.textContent = 'Checking and creating thumbnail...';
    bar.removeAttribute('value'); // indeterminate
    const { file: saved } = await api(`/api/uploads/${slot.uploadId}/complete`, { method: 'POST' });

    stateEl.textContent = 'Done';
    stateEl.className = 'state ok';
    bar.hidden = true;
    $('empty').hidden = true;
    $('gallery').prepend(tile(saved));
    refreshUsage();
    setTimeout(() => row.remove(), 6000);
  } catch (ex) {
    fail(ex.message);
  }
}

/** Direct browser -> object storage upload using the signed URL (XHR gives progress events). */
function putToStorage(url, headers, file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', url);
    for (const [k, v] of Object.entries(headers)) xhr.setRequestHeader(k, v);
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100)); };
    xhr.onload = () => (xhr.status >= 200 && xhr.status < 300 ? resolve() : reject(new Error(`Storage rejected the upload (${xhr.status})`)));
    xhr.onerror = () => reject(new Error('Network error while uploading'));
    xhr.send(file);
  });
}

/* ------------------------------ gallery ------------------------------ */

function tile(f) {
  const li = el('li', { class: 'tile', 'data-id': f.id });
  const media = f.thumbUrl
    ? el('img', { class: 'thumb', src: f.thumbUrl, alt: '', loading: 'lazy', width: '320', height: '320' })
    : el('div', { class: 'doc', 'aria-hidden': 'true', text: f.mime === 'application/pdf' ? 'PDF' : 'TXT' });
  const open = el('button', { class: 'open', type: 'button', 'aria-label': `Open ${f.name}`, onclick: () => openViewer(f) },
    media,
    el('div', { class: 'info' },
      el('div', { class: 'fname', text: f.name }),
      el('div', { class: 'fmeta', text: `${fmtSize(f.size)} - ${fmtDate(f.createdAt)}` }),
    ),
  );
  const del = el('button', { class: 'del', type: 'button', 'aria-label': `Delete ${f.name}`, text: 'Delete', onclick: () => askDelete(f) });
  li.append(open, del);
  return li;
}

async function loadGallery(reset) {
  if (reset) { state.cursor = null; $('gallery').replaceChildren(); }
  try {
    const q = new URLSearchParams({ limit: '24' });
    if (state.cursor) q.set('cursor', state.cursor);
    const data = await api(`/api/files?${q}`);
    $('gallery').append(...data.files.map(tile));
    state.cursor = data.nextCursor;
    $('more').hidden = !data.nextCursor;
    $('empty').hidden = data.usage.files > 0;
    showUsage(data.usage);
  } catch (ex) {
    if (ex.status !== 401) toast(ex.message, true);
  }
}

function showUsage(u) {
  $('usage').textContent = `${u.files} of ${u.maxFiles} files - ${fmtSize(u.bytes)} of ${fmtSize(u.maxBytes)} used`;
}

async function refreshUsage() {
  try { showUsage((await api('/api/files?limit=1')).usage); } catch { /* ignore */ }
}

$('more').addEventListener('click', () => loadGallery(false));

/* ------------------------------ viewer ------------------------------ */

const viewer = $('viewer');

async function openViewer(f) {
  state.viewing = f;
  $('viewer-title').textContent = f.name;
  $('viewer-meta').textContent = `${f.mime} - ${fmtSize(f.size)}${f.width ? ` - ${f.width} x ${f.height}` : ''}`;
  const body = $('viewer-body');
  body.replaceChildren(el('p', { class: 'muted', text: 'Loading...' }));
  viewer.showModal();
  try {
    if (f.kind === 'image') {
      const { url } = await api(`/api/files/${f.id}/download?inline=1`);
      body.replaceChildren(el('img', { src: url, alt: f.name }));
    } else {
      body.replaceChildren(el('p', { class: 'muted', text: 'Documents are not previewed in the browser. Use Download to open it.' }));
    }
  } catch (ex) {
    body.replaceChildren(el('p', { class: 'error', text: ex.message }));
  }
}

$('viewer-close').addEventListener('click', () => viewer.close());
viewer.addEventListener('click', (e) => { if (e.target === viewer) viewer.close(); });

$('viewer-download').addEventListener('click', async () => {
  const f = state.viewing;
  if (!f) return;
  try {
    const { url } = await api(`/api/files/${f.id}/download`);
    // The signed URL forces Content-Disposition: attachment, so the browser downloads it.
    const a = el('a', { href: url, rel: 'noopener', download: f.name });
    document.body.append(a);
    a.click();
    a.remove();
  } catch (ex) {
    toast(ex.message, true);
  }
});

$('viewer-delete').addEventListener('click', () => { if (state.viewing) askDelete(state.viewing); });

/* ------------------------------ delete ------------------------------ */

const confirmDlg = $('confirm');
let toDelete = null;

function askDelete(f) {
  toDelete = f;
  $('confirm-text').textContent = `"${f.name}" will be removed from storage. This cannot be undone.`;
  confirmDlg.showModal();
}

$('confirm-cancel').addEventListener('click', () => confirmDlg.close());
$('confirm-ok').addEventListener('click', async () => {
  const f = toDelete;
  if (!f) return;
  $('confirm-ok').disabled = true;
  try {
    await api(`/api/files/${f.id}`, { method: 'DELETE' });
    document.querySelector(`.tile[data-id="${CSS.escape(f.id)}"]`)?.remove();
    confirmDlg.close();
    if (viewer.open) viewer.close();
    toast('File deleted');
    refreshUsage();
    if (!$('gallery').children.length) loadGallery(true);
  } catch (ex) {
    toast(ex.message, true);
  } finally {
    $('confirm-ok').disabled = false;
    toDelete = null;
  }
});

/* ------------------------------ boot ------------------------------ */

(async function boot() {
  setMode('login');
  try {
    const me = await api('/api/auth/me');
    if (me.user) {
      state.csrf = me.csrfToken;
      showApp(me.user);
    } else {
      showAuth();
    }
  } catch {
    showAuth();
  }
})();
