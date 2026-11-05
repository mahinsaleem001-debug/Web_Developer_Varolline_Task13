# Vault: Secure File Upload and Media Pipeline

A web app where users sign in, upload images and documents straight to **S3-compatible object storage using signed URLs**, get **validated and sanitised files with generated thumbnails**, and manage them in a **gallery with deletion**. Built to resist malicious uploads and to keep every user's files private.

* **Stack:** Node.js 20+, Express 5, SQLite (better-sqlite3), sharp (libvips), AWS SDK v3 (works with AWS S3, MinIO, Cloudflare R2, etc.), plain HTML/CSS/JS front end (no build step).
* **Tests:** 51 automated tests (49 pass, 2 intentionally skipped, see [SECURITY.md](SECURITY.md) section 6.3), plus a real-browser end-to-end run.
* **Security write-up:** [SECURITY.md](SECURITY.md)

## Features

| Requirement | How it is done |
| --- | --- |
| Upload validation: type, size, content | Allow-list + extension check + magic-byte detection + size caps + full decode/re-encode, PDF active-content scan, UTF-8 check for text |
| Cloud object storage with signed URLs | Browser PUTs directly to a presigned URL (5 min, bound to key, type and length). Downloads use presigned GET URLs (2 min), created only after an ownership check |
| Thumbnail generation | 320 px WebP thumbnail for every image (animated GIFs use the first frame) |
| Gallery view with deletion | Responsive grid, lazy-loaded thumbnails, viewer dialog, cursor pagination, confirm-and-delete (removes object, thumbnail and database row) |
| Protection against malicious uploads | Quarantine, re-encoding, bomb limits, quotas, rate limits, strict CSP. See [SECURITY.md](SECURITY.md) |
| No access to other users' files | Ownership in every SQL `WHERE`, uniform 404, server-generated owner-prefixed keys, session-bound CSRF |

## Quick start (Windows, macOS, Linux)

Requires **Node.js 20 or newer**. No Docker and no AWS account needed for local use: `npm run dev` starts an in-process S3-compatible server.

```bash
npm install
npm run dev
```

Open **http://localhost:3000**, create an account, and drop some files in.

```bash
npm test          # full automated test suite (about 1 minute)
```

To use another port: `PORT=4000 npm run dev` (macOS/Linux) or `$env:PORT=4000; npm run dev` (PowerShell).

## How an upload works

1. `POST /api/uploads` with `{name, type, size}`. The server validates the claim, checks quotas, and returns a **signed PUT URL** for `quarantine/<user>/<uploadId>`.
2. The browser `PUT`s the file **directly to object storage** and shows real progress.
3. `POST /api/uploads/:id/complete`. The server reads the quarantined bytes (with a hard size cap), validates and **re-encodes** them, creates the thumbnail, stores both under `files/` and `thumbs/`, deletes the quarantine object, and returns the file record.
4. The gallery asks `GET /api/files` for the list (with signed thumbnail URLs). Opening or downloading a file calls `GET /api/files/:id/download`, which returns a short-lived signed URL.

## API

All routes are JSON. State-changing routes need the `X-CSRF-Token` header (returned by login/register/`me`).

| Method and path | Purpose |
| --- | --- |
| `POST /api/auth/register`, `POST /api/auth/login` | Create account / sign in (rate limited) |
| `POST /api/auth/logout`, `GET /api/auth/me` | Sign out / current user (`user: null` if anonymous) |
| `POST /api/uploads` | Start an upload, returns a signed PUT URL |
| `POST /api/uploads/:id/complete` | Validate, sanitise, thumbnail and publish |
| `GET /api/files?limit=&cursor=` | Gallery page (newest first) with signed thumbnail URLs and usage |
| `GET /api/files/:id/download[?inline=1]` | Short-lived signed download URL (inline only for images) |
| `DELETE /api/files/:id` | Delete object, thumbnail and record |

Errors look like `{"error":{"code":"content_mismatch","message":"..."}}`.

## Configuration

Copy `.env.example` to `.env` (or set environment variables).

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT`, `APP_ORIGIN` | `3000`, `http://localhost:PORT` | Listen port and the public origin (used for CSRF/CORS) |
| `S3_ENDPOINT` | empty (AWS) | Set for MinIO, R2 or other S3-compatible services |
| `S3_REGION`, `S3_BUCKET` | `us-east-1`, `uploads` | Region and bucket |
| `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | empty | Credentials (or use the default AWS credential chain / IAM role) |
| `S3_FORCE_PATH_STYLE` | true when endpoint set | Needed for MinIO |
| `MAX_FILE_MB` | `10` | Max size per file |
| `MAX_IMAGE_PIXELS`, `MAX_IMAGE_DIMENSION` | `30000000`, `12000` | Decompression-bomb limits |
| `MAX_FILES_PER_USER`, `MAX_USER_MB` | `200`, `500` | Per-user quotas |
| `COOKIE_SECURE`, `TRUST_PROXY` | true in production, false | Set both correctly behind HTTPS and a proxy |
| `DB_PATH` | `./data/app.db` | SQLite file |
| `NODE_ENV` | | `production` turns on secure cookies and `upgrade-insecure-requests` in the CSP |

### Using real S3 (or MinIO / R2)

1. Create a **private** bucket (Block Public Access on).
2. Add CORS so the browser may upload directly:

   ```json
   [{ "AllowedOrigins": ["https://your-app.example"], "AllowedMethods": ["PUT", "GET"], "AllowedHeaders": ["*"], "MaxAgeSeconds": 600 }]
   ```
3. Give the app an IAM identity limited to the bucket (`s3:PutObject`, `s3:GetObject`, `s3:DeleteObject`).
4. Optional lifecycle rule: expire `quarantine/` objects after 1 day.
5. Set `S3_BUCKET`, `S3_REGION`, credentials, `APP_ORIGIN=https://your-app.example`, `COOKIE_SECURE=true`, `NODE_ENV=production`, then `npm start`.

## Project structure

```
src/server.js        entry point (config, DB, storage, cleanup timer)
src/dev.js           dev entry: starts a local S3-compatible server
src/app.js           Express app: headers, auth, upload, gallery, delete routes
src/validate.js      validation + sanitising pipeline (images, PDF, text)
src/storage.js       S3 wrapper: signed PUT/GET, capped reads, delete
src/auth.js          scrypt passwords, hashed sessions, CSRF
src/db.js            SQLite schema (users, sessions, uploads, files)
src/config.js        environment configuration
src/local-s3.js      in-process S3 server for development and tests
public/              front end (index.html, app.js, styles.css)
test/                security and behaviour tests (real app + real S3 protocol)
SECURITY.md          security explanation
```

## Tests

`npm test` boots the real app against an S3-compatible server and attacks it. It covers: the full happy path, thumbnails, pagination, deletion from storage; HTML/SVG/EXE disguised as images; type confusion; truncated images; size lies and oversize bodies; decompression bombs; PDF scripts (including `#xx` escape evasion); EXIF stripping; PNG with an appended script; file-name tricks; double completion; abandoned upload cleanup; anonymous access; user A reaching user B's files, slots and cursors; malformed ids and SQL-looking ids; CSRF and cross-origin requests; cookie flags; session invalidation; login error uniformity; CSP headers; quotas and rate limits.

## Known limitations

See [SECURITY.md](SECURITY.md) section 6. In short: no antivirus scanner, PDF scanning is heuristic, presigned-signature enforcement depends on your S3 provider and should be spot-checked manually, and SQLite / in-memory rate limiting suit a single instance.
