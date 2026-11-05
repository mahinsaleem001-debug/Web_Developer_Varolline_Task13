import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,           -- SHA-256 of the cookie value, never the value itself
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

-- A signed upload slot. The object lands in quarantine/ until it has been validated.
CREATE TABLE IF NOT EXISTS uploads (
  id             TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_name  TEXT NOT NULL,
  declared_type  TEXT NOT NULL,
  declared_size  INTEGER NOT NULL,
  quarantine_key TEXT NOT NULL,
  status         TEXT NOT NULL CHECK (status IN ('pending','processing','done','rejected','expired')),
  expires_at     INTEGER NOT NULL,
  created_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_uploads_user_status ON uploads(user_id, status);

-- Validated, sanitised files. Every query on this table filters by user_id.
CREATE TABLE IF NOT EXISTS files (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_name TEXT NOT NULL,
  kind          TEXT NOT NULL CHECK (kind IN ('image','document')),
  mime          TEXT NOT NULL,
  size          INTEGER NOT NULL,
  width         INTEGER,
  height        INTEGER,
  sha256        TEXT NOT NULL,
  storage_key   TEXT NOT NULL,
  thumb_key     TEXT,
  created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_user_created ON files(user_id, created_at DESC, id);
`;

export function openDb(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);
  return db;
}
