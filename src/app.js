import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';

import { HttpError, UploadRejected, notFound } from './errors.js';
import { hashPassword, verifyPassword, burnPasswordCheck, createSessions, requireAuth, csrfProtect } from './auth.js';
import { validateDeclaration, inspect, sanitizeName, sha256Hex, createLimiter } from './validate.js';

const PUBLIC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;

/** Origin the browser talks to for signed URLs (needed for the CSP). */
function s3Origin(s3) {
  if (s3.endpoint) return new URL(s3.endpoint).origin;
  return `https://${s3.bucket}.s3.${s3.region}.amazonaws.com`;
}

export function createApp({ config, db, storage, log = console }) {
  const app = express();
  const sessions = createSessions(db, config);
  const processLimit = createLimiter(3);
  const origin = s3Origin(config.s3);

  app.disable('x-powered-by');
  if (config.trustProxy) app.set('trust proxy', 1);

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'none'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', origin],
          connectSrc: ["'self'", origin],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          ...(config.isProd ? { upgradeInsecureRequests: [] } : {}),
        },
      },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );
  app.use(express.json({ limit: '10kb' })); // API bodies are tiny; file bytes never pass through here
  app.use(sessions.load);
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  app.use('/api', csrfProtect(config.appOrigin));

  const limiter = (opts) =>
    rateLimit({ ...opts, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: { code: 'rate_limited', message: 'Too many requests, slow down' } } });
  const authLimiter = limiter(config.rateLimit.auth);
  const uploadLimiter = limiter(config.rateLimit.uploads);

  /* ---------------------------- prepared statements ---------------------------- */
  const q = {
    userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
    insertUser: db.prepare('INSERT INTO users (id, email, password_hash, created_at) VALUES (?,?,?,?)'),

    countFiles: db.prepare('SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS bytes FROM files WHERE user_id = ?'),
    countPending: db.prepare("SELECT COUNT(*) AS n FROM uploads WHERE user_id = ? AND status = 'pending' AND expires_at > ?"),
    insertUpload: db.prepare(
      `INSERT INTO uploads (id, user_id, original_name, declared_type, declared_size, quarantine_key, status, expires_at, created_at)
       VALUES (?,?,?,?,?,?, 'pending', ?, ?)`,
    ),
    // Ownership is part of the WHERE clause: another user's id simply matches nothing.
    getUpload: db.prepare('SELECT * FROM uploads WHERE id = ? AND user_id = ?'),
    claimUpload: db.prepare("UPDATE uploads SET status = 'processing' WHERE id = ? AND user_id = ? AND status = 'pending' AND expires_at > ?"),
    setUploadStatus: db.prepare('UPDATE uploads SET status = ? WHERE id = ?'),
    staleUploads: db.prepare("SELECT * FROM uploads WHERE status IN ('pending','processing') AND expires_at < ?"),

    insertFile: db.prepare(
      `INSERT INTO files (id, user_id, original_name, kind, mime, size, width, height, sha256, storage_key, thumb_key, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    ),
    getFile: db.prepare('SELECT * FROM files WHERE id = ? AND user_id = ?'),
    listFirst: db.prepare('SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?'),
    listAfter: db.prepare(
      'SELECT * FROM files WHERE user_id = ? AND (created_at < ? OR (created_at = ? AND id < ?)) ORDER BY created_at DESC, id DESC LIMIT ?',
    ),
    deleteFile: db.prepare('DELETE FROM files WHERE id = ? AND user_id = ?'),
  };

  /* ------------------------------ helpers ------------------------------ */
  const param = (req, name) => {
    const v = req.params[name];
    if (!UUID.test(v)) throw notFound(); // malformed ids look exactly like missing ones
    return v;
  };

  const publicFile = async (row) => ({
    id: row.id,
    name: row.original_name,
    kind: row.kind,
    mime: row.mime,
    size: row.size,
    width: row.width,
    height: row.height,
    createdAt: row.created_at,
    thumbUrl: row.thumb_key
      ? await storage.signedDownload({
          key: row.thumb_key,
          contentType: 'image/webp',
          filename: 'thumbnail.webp',
          inline: true,
          expiresIn: config.ttl.thumbSeconds,
        })
      : null,
  });

  /* ------------------------------- auth ------------------------------- */
  const readCreds = (body) => {
    const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body?.password === 'string' ? body.password : '';
    return { email, password };
  };

  app.post('/api/auth/register', authLimiter, async (req, res) => {
    const { email, password } = readCreds(req.body);
    if (!EMAIL.test(email)) throw new HttpError(400, 'bad_email', 'Enter a valid email address');
    if (password.length < 10 || password.length > 128) throw new HttpError(400, 'bad_password', 'Password must be 10 to 128 characters');
    if (q.userByEmail.get(email)) throw new HttpError(409, 'email_taken', 'An account with this email already exists');

    const id = crypto.randomUUID();
    q.insertUser.run(id, email, await hashPassword(password), Date.now());
    const csrfToken = sessions.start(res, id);
    res.status(201).json({ user: { id, email }, csrfToken });
  });

  app.post('/api/auth/login', authLimiter, async (req, res) => {
    const { email, password } = readCreds(req.body);
    const user = q.userByEmail.get(email);
    const ok = user ? await verifyPassword(password, user.password_hash) : (await burnPasswordCheck(password), false);
    if (!ok) throw new HttpError(401, 'bad_credentials', 'Incorrect email or password'); // same message for both cases
    const csrfToken = sessions.start(res, user.id);
    res.json({ user: { id: user.id, email: user.email }, csrfToken });
  });

  app.post('/api/auth/logout', (req, res) => {
    sessions.end(req, res);
    res.status(204).end();
  });

  // Anonymous visitors get a normal 200 with user: null, so the page can check "am I signed in?" without console noise.
  app.get('/api/auth/me', (req, res) =>
    res.json(req.user ? { user: req.user, csrfToken: req.csrfToken } : { user: null, csrfToken: null }),
  );

  /* ------------------------ step 1: ask for an upload slot ------------------------ */
  app.post('/api/uploads', requireAuth, uploadLimiter, async (req, res) => {
    const { limits, ttl } = config;
    const meta = validateDeclaration(
      { name: req.body?.name, type: req.body?.type, size: req.body?.size },
      limits,
    );

    const usage = q.countFiles.get(req.user.id);
    if (usage.n >= limits.maxFilesPerUser) throw new HttpError(409, 'quota_files', 'File limit reached. Delete something first.');
    if (usage.bytes + req.body.size > limits.maxBytesPerUser) throw new HttpError(409, 'quota_storage', 'Storage quota exceeded. Delete something first.');
    if (q.countPending.get(req.user.id, Date.now()).n >= limits.maxPendingPerUser) {
      throw new HttpError(429, 'too_many_pending', 'Too many uploads in progress');
    }

    const uploadId = crypto.randomUUID();
    const key = storage.keys.quarantine(req.user.id, uploadId);
    const now = Date.now();
    q.insertUpload.run(uploadId, req.user.id, meta.name, meta.type, req.body.size, key, now + ttl.pendingUploadMs, now);

    // The signature binds method, key, Content-Type and Content-Length, and expires in minutes.
    const url = await storage.signedUpload({ key, contentType: meta.type, contentLength: req.body.size });
    res.status(201).json({ uploadId, url, headers: { 'Content-Type': meta.type }, expiresIn: ttl.putSeconds });
  });

  /* ------- step 2: after the browser PUT, validate the bytes and publish the file ------- */
  app.post('/api/uploads/:id/complete', requireAuth, uploadLimiter, async (req, res) => {
    const id = param(req, 'id');
    const upload = q.getUpload.get(id, req.user.id);
    if (!upload) throw notFound();
    if (upload.status !== 'pending') throw new HttpError(409, 'not_pending', 'This upload was already processed or has expired');
    if (!q.claimUpload.run(id, req.user.id, Date.now()).changes) throw new HttpError(409, 'not_pending', 'This upload was already processed or has expired');

    const { limits, thumbnailSize } = config;
    try {
      // Never trust what is in the bucket: read it with a hard byte cap and validate the bytes.
      const raw = await storage.readCapped(upload.quarantine_key, limits.maxFileBytes);
      if (!raw) throw new UploadRejected('missing_object', 'The file was not uploaded. Please try again.');
      if (raw.length !== upload.declared_size) throw new UploadRejected('size_mismatch', 'The uploaded size does not match what was declared.');

      const result = await processLimit(() => inspect(raw, upload.declared_type, limits, thumbnailSize));

      const usage = q.countFiles.get(req.user.id);
      if (usage.bytes + result.body.length > limits.maxBytesPerUser) throw new HttpError(409, 'quota_storage', 'Storage quota exceeded');

      const fileId = crypto.randomUUID();
      const storageKey = storage.keys.file(req.user.id, fileId);
      const thumbKey = result.thumb ? storage.keys.thumb(req.user.id, fileId) : null;

      await storage.put({ key: storageKey, body: result.body, contentType: result.mime });
      if (thumbKey) await storage.put({ key: thumbKey, body: result.thumb, contentType: 'image/webp' });

      const now = Date.now();
      try {
        q.insertFile.run(fileId, req.user.id, upload.original_name, result.kind, result.mime, result.body.length, result.width, result.height, sha256Hex(result.body), storageKey, thumbKey, now);
      } catch (err) {
        await Promise.allSettled([storage.remove(storageKey), thumbKey && storage.remove(thumbKey)]);
        throw err;
      }
      q.setUploadStatus.run('done', id);
      await storage.remove(upload.quarantine_key).catch(() => {});

      res.status(201).json({ file: await publicFile(q.getFile.get(fileId, req.user.id)) });
    } catch (err) {
      // Whatever went wrong, the untrusted object must not stay in the bucket.
      q.setUploadStatus.run(err instanceof UploadRejected || err instanceof HttpError ? 'rejected' : 'expired', id);
      await storage.remove(upload.quarantine_key).catch(() => {});
      throw err;
    }
  });

  /* ------------------------------- gallery ------------------------------- */
  app.get('/api/files', requireAuth, async (req, res) => {
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 24, 1), 60);
    let rows;
    const cursor = typeof req.query.cursor === 'string' ? req.query.cursor.match(/^(\d{1,15})_([0-9a-f-]{36})$/) : null;
    if (cursor) rows = q.listAfter.all(req.user.id, Number(cursor[1]), Number(cursor[1]), cursor[2], limit + 1);
    else rows = q.listFirst.all(req.user.id, limit + 1);

    const more = rows.length > limit;
    if (more) rows.pop();
    const usage = q.countFiles.get(req.user.id);
    res.json({
      files: await Promise.all(rows.map(publicFile)),
      nextCursor: more ? `${rows.at(-1).created_at}_${rows.at(-1).id}` : null,
      usage: { files: usage.n, bytes: usage.bytes, maxFiles: config.limits.maxFilesPerUser, maxBytes: config.limits.maxBytesPerUser },
    });
  });

  /** Returns a short-lived signed URL. Ownership is checked before anything is signed. */
  app.get('/api/files/:id/download', requireAuth, async (req, res) => {
    const row = q.getFile.get(param(req, 'id'), req.user.id);
    if (!row) throw notFound();
    const inline = req.query.inline === '1' && row.kind === 'image'; // documents are never rendered inline
    const url = await storage.signedDownload({
      key: row.storage_key,
      contentType: row.mime,
      filename: row.original_name,
      inline,
      expiresIn: config.ttl.getSeconds,
    });
    res.json({ url, expiresIn: config.ttl.getSeconds });
  });

  app.delete('/api/files/:id', requireAuth, async (req, res) => {
    const row = q.getFile.get(param(req, 'id'), req.user.id);
    if (!row) throw notFound();
    await Promise.all([storage.remove(row.storage_key), row.thumb_key && storage.remove(row.thumb_key)]);
    q.deleteFile.run(row.id, req.user.id);
    res.status(204).end();
  });

  /* ------------------------------ static UI ------------------------------ */
  app.use(
    express.static(PUBLIC_DIR, {
      index: 'index.html',
      dotfiles: 'ignore',
      maxAge: config.isProd ? '1h' : 0,
      setHeaders: (res) => res.set('X-Content-Type-Options', 'nosniff'),
    }),
  );

  app.use('/api', (_req, _res, next) => next(notFound()));

  /* ------------------------------ errors ------------------------------ */
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    if (err instanceof HttpError) {
      return res.status(err.status).json({ error: { code: err.code, message: err.message } });
    }
    if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: { code: 'bad_json', message: 'Invalid JSON body' } });
    if (err?.type === 'entity.too.large') return res.status(413).json({ error: { code: 'too_large', message: 'Request body too large' } });
    log.error(`[${req.method} ${req.path}]`, err); // details stay in the server log only
    res.status(500).json({ error: { code: 'internal', message: 'Something went wrong' } });
  });

  /* --------------------- background clean-up of abandoned uploads --------------------- */
  async function expireStaleUploads() {
    const rows = q.staleUploads.all(Date.now());
    for (const row of rows) {
      await storage.remove(row.quarantine_key).catch(() => {});
      q.setUploadStatus.run('expired', row.id);
    }
    sessions.purgeExpired();
    return rows.length;
  }

  return { app, expireStaleUploads };
}
