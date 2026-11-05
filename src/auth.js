import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { HttpError } from './errors.js';

const scrypt = promisify(crypto.scrypt);
const COOKIE = 'sid';
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

/* ---------- passwords: scrypt with a per-user salt ---------- */

export async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
}

export async function verifyPassword(password, stored) {
  const [scheme, saltHex, keyHex] = String(stored).split('$');
  if (scheme !== 'scrypt' || !saltHex || !keyHex) return false;
  const expected = Buffer.from(keyHex, 'hex');
  const actual = await scrypt(password, Buffer.from(saltHex, 'hex'), expected.length, { N: 16384, r: 8, p: 1 });
  return crypto.timingSafeEqual(actual, expected);
}

// Used so that "unknown email" costs the same time as "wrong password".
let dummyHash;
export async function burnPasswordCheck(password) {
  dummyHash ??= await hashPassword('dummy-password-for-timing');
  await verifyPassword(password, dummyHash);
}

/* ---------- sessions: random token in an HttpOnly cookie, only its hash stored ---------- */

export function createSessions(db, cfg) {
  const insert = db.prepare('INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, created_at) VALUES (?,?,?,?,?)');
  const find = db.prepare(
    `SELECT s.token_hash, s.csrf_token, s.expires_at, u.id AS user_id, u.email
       FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`,
  );
  const del = db.prepare('DELETE FROM sessions WHERE token_hash = ?');
  const purge = db.prepare('DELETE FROM sessions WHERE expires_at < ?');

  const cookieOptions = () => ({
    httpOnly: true,
    secure: cfg.cookieSecure,
    sameSite: 'lax',
    path: '/',
    maxAge: cfg.sessionTtlMs,
  });

  return {
    start(res, userId) {
      const token = crypto.randomBytes(32).toString('base64url');
      const csrf = crypto.randomBytes(24).toString('base64url');
      const now = Date.now();
      insert.run(sha256(token), userId, csrf, now + cfg.sessionTtlMs, now);
      res.cookie(COOKIE, token, cookieOptions());
      return csrf;
    },
    end(req, res) {
      const token = readCookie(req, COOKIE);
      if (token) del.run(sha256(token));
      res.clearCookie(COOKIE, { ...cookieOptions(), maxAge: undefined });
    },
    purgeExpired: () => purge.run(Date.now()),

    /** Express middleware: loads req.user or leaves it undefined. */
    load(req, _res, next) {
      const token = readCookie(req, COOKIE);
      if (token) {
        const row = find.get(sha256(token));
        if (row && row.expires_at > Date.now()) {
          req.user = { id: row.user_id, email: row.email };
          req.csrfToken = row.csrf_token;
        } else if (row) {
          del.run(row.token_hash);
        }
      }
      next();
    },
  };
}

/** Reject anonymous requests. */
export function requireAuth(req, _res, next) {
  if (!req.user) return next(new HttpError(401, 'unauthenticated', 'Please sign in'));
  next();
}

/**
 * CSRF protection for state-changing requests: the double-submit token must match the one
 * bound to the session (sent in a header by our own JS), and the Origin header, when present,
 * must be our own origin. SameSite=Lax cookies are a third layer.
 */
export function csrfProtect(appOrigin) {
  return (req, _res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const origin = req.get('origin');
    if (origin && origin !== appOrigin) return next(new HttpError(403, 'bad_origin', 'Cross-origin request blocked'));
    if (req.user) {
      const sent = req.get('x-csrf-token') || '';
      const a = Buffer.from(sent);
      const b = Buffer.from(req.csrfToken || '');
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return next(new HttpError(403, 'bad_csrf', 'Missing or invalid CSRF token'));
      }
    }
    next();
  };
}

function readCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
