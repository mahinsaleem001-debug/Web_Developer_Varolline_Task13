import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import sharp from 'sharp';
import { loadConfig } from '../src/config.js';
import { openDb } from '../src/db.js';
import { createStorage } from '../src/storage.js';
import { createApp } from '../src/app.js';
import { startLocalS3 } from '../src/local-s3.js';

const freePort = () =>
  new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

/** Boots the real app against a real (local) S3-compatible server. */
export async function startHarness(overrides = {}) {
  const appPort = await freePort();
  const s3Port = await freePort();
  const appOrigin = `http://localhost:${appPort}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'upload-test-'));
  const s3 = await startLocalS3({ port: s3Port, directory: path.join(dir, 's3'), bucket: 'uploads', appOrigin });

  const config = loadConfig({
    port: appPort,
    appOrigin,
    dbPath: ':memory:',
    s3: { endpoint: s3.endpoint, accessKeyId: s3.accessKeyId, secretAccessKey: s3.secretAccessKey, forcePathStyle: true, bucket: 'uploads', region: 'us-east-1' },
    rateLimit: { auth: { windowMs: 60_000, limit: 10_000 }, uploads: { windowMs: 60_000, limit: 10_000 } },
    ...overrides,
  });
  const db = openDb(':memory:');
  const storage = createStorage(config);
  const silent = { error() {}, log() {}, warn() {} };
  const { app, expireStaleUploads } = createApp({ config, db, storage, log: silent });
  const server = await new Promise((resolve) => {
    const srv = app.listen(appPort, '127.0.0.1', () => resolve(srv));
  });

  return {
    config, db, storage, expireStaleUploads, appOrigin,
    base: `http://127.0.0.1:${appPort}`,
    async close() {
      await new Promise((r) => server.close(r));
      await s3.close();
      db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** A tiny HTTP client with a cookie jar and CSRF handling, like a browser session. */
export class Client {
  constructor(h) {
    this.h = h;
    this.cookie = '';
    this.csrf = '';
    this.user = null;
  }

  async raw(method, url, { body, headers = {}, csrf = true, origin } = {}) {
    const h = { ...headers };
    if (this.cookie) h.Cookie = this.cookie;
    if (csrf && this.csrf && method !== 'GET') h['X-CSRF-Token'] = this.csrf;
    if (origin) h.Origin = origin;
    let payload = body;
    if (body && !(body instanceof Buffer) && typeof body === 'object') {
      payload = JSON.stringify(body);
      h['Content-Type'] = 'application/json';
    }
    const res = await fetch(url.startsWith('http') ? url : this.h.base + url, { method, headers: h, body: payload, redirect: 'manual' });
    const set = res.headers.getSetCookie?.() ?? [];
    for (const c of set) {
      const [pair] = c.split(';');
      if (pair.endsWith('=') || /Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(c)) this.cookie = '';
      else this.cookie = pair;
    }
    return res;
  }

  async json(method, url, opts) {
    const res = await this.raw(method, url, opts);
    let data = null;
    try { data = await res.clone().json(); } catch { /* none */ }
    return { status: res.status, data, res };
  }

  async register(email, password = 'correct-horse-battery') {
    const r = await this.json('POST', '/api/auth/register', { body: { email, password } });
    if (r.status !== 201) throw new Error(`register failed: ${r.status} ${JSON.stringify(r.data)}`);
    this.csrf = r.data.csrfToken;
    this.user = r.data.user;
    return r;
  }

  /** The whole upload flow, as the browser does it. Returns each step so tests can assert on any of them. */
  async upload(buffer, name, type, { declaredSize = buffer.length, putBody = buffer } = {}) {
    const init = await this.json('POST', '/api/uploads', { body: { name, type, size: declaredSize } });
    if (init.status !== 201) return { init };
    const put = await fetch(init.data.url, { method: 'PUT', headers: init.data.headers, body: putBody });
    const complete = await this.json('POST', `/api/uploads/${init.data.uploadId}/complete`);
    return { init, put, complete, file: complete.data?.file };
  }
}

/* ------------------------------ fixtures ------------------------------ */

export const solid = (w, h, color = '#d33') => ({ create: { width: w, height: h, channels: 3, background: color } });

export const makePng = (w = 200, h = 120) => sharp(solid(w, h)).png().toBuffer();
export const makeJpeg = (w = 200, h = 120) => sharp(solid(w, h)).jpeg().toBuffer();
export const makeWebp = (w = 200, h = 120) => sharp(solid(w, h)).webp().toBuffer();

export const makeJpegWithExif = () =>
  sharp(solid(160, 100)).jpeg().withExif({ IFD0: { Copyright: 'SECRET-COPYRIGHT-MARKER', Artist: 'SECRET-ARTIST' } }).toBuffer();

export async function makeAnimatedGif(frames = 3, w = 60, h = 40) {
  const colors = ['#f00', '#0f0', '#00f', '#ff0', '#0ff'];
  const parts = await Promise.all(Array.from({ length: frames }, (_, i) => sharp(solid(w, h, colors[i % colors.length])).raw().toBuffer()));
  return sharp(Buffer.concat(parts), { raw: { width: w, height: h * frames, channels: 3, pageHeight: h } }).gif({ loop: 0, delay: new Array(frames).fill(100) }).toBuffer();
}

export const makePdf = (extra = '') =>
  Buffer.from(
    `%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R${extra}>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n`,
    'latin1',
  );
