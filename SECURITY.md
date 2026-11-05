# Security explanation

This document explains how the app protects against **malicious uploads** and **unauthorized access to other users' files**, why each control exists, which test proves it, and what is deliberately *not* covered.

## 1. Threat model

| # | Attacker goal | Example |
| --- | --- | --- |
| T1 | Get code executed in other users' browsers (stored XSS) | Upload `evil.svg`, or HTML renamed to `.png`, then have it served from our origin |
| T2 | Get code executed on the server | Image or PDF crafted to exploit a parser, PHP/JS payload appended to a valid image |
| T3 | Exhaust server, storage or memory | Decompression bomb, huge file, endless uploads, thousands of open upload slots |
| T4 | Read, change or delete another user's files | Guess or enumerate file ids (IDOR), reuse someone else's upload slot |
| T5 | Abuse a logged-in user's browser | CSRF: a hostile page makes the browser delete files |
| T6 | Leak private data inside files | GPS coordinates and camera serial numbers in EXIF |
| T7 | Steal or guess accounts | Credential stuffing, session theft, user enumeration |

## 2. Upload pipeline: nothing is trusted until the server has read the bytes

```
 Browser                      API server                         Object storage (private bucket)
    |  1. POST /api/uploads  ---->|  validate name, type, size, quotas
    |  <---- signed PUT URL ------|  (URL is bound to key, Content-Type, Content-Length; 5 min)
    |  2. PUT bytes -------------------------------------------->  quarantine/<user>/<uploadId>
    |  3. POST .../complete ----->|  read bytes with a hard cap  <--  (untrusted)
    |                             |  magic-byte check, decode, re-encode, thumbnail
    |                             |  write files/<user>/<id> + thumbs/<user>/<id>.webp
    |                             |  delete quarantine object
    |  <---- file record ---------|
```

Bytes go **straight from the browser to storage** (the API server never proxies large uploads), but the result of that upload is never used directly. The server fetches the quarantined object, validates it, and publishes a **new, sanitised object**. Anything that fails is deleted from the bucket and the slot is marked `rejected`.

**Important design decision:** we do not rely on S3 to enforce the signed `Content-Length` or `Content-Type`. Real S3 does, but S3-compatible servers differ (the local emulator used for tests does not enforce them), and a signature only restricts the *first* PUT. The server therefore re-checks size and content on its own bytes.

## 3. Controls against malicious uploads

| Control | Where | Stops | Proven by test |
| --- | --- | --- | --- |
| **Strict allow-list** of types (JPEG, PNG, WebP, GIF, PDF, TXT). SVG, HTML, JS, archives, executables and Office files (macros) are refused. | `validate.js` `ALLOWED` | T1, T2 | "disallowed MIME types never get an upload slot" |
| **Extension must match the declared type** (blocks `evil.exe`, `photo.png.exe`, no extension) | `validateDeclaration` | T1 | "extension must match the declared type" |
| **Magic-byte detection** (`file-type`) on the real bytes; must equal the declared type | `inspectImage` | T1 (HTML or SVG renamed to `.png`, JPEG declared as PNG, EXE as image) | "HTML disguised as a PNG...", "JPEG declared as PNG", "executable renamed" |
| **Size limit enforced three times**: declared size, signed `Content-Length`, and a streamed hard cap while reading (aborts early) | `validateDeclaration`, `storage.readCapped` | T3 | "declaring a tiny size but uploading far more... (413)", "different size than declared" |
| **Decompression-bomb protection**: pixel limit (`limitInputPixels`, default 30 MP), max dimension (12,000 px), max animation frames (100), checked from the header before decoding | `inspectImage` | T3 | "decompression bomb", "absurd single dimension" |
| **Full decode + re-encode** of every image. Stored pixels are brand new, so trailing payloads, polyglots, embedded scripts and metadata do not survive. GIF is converted to WebP. | `inspectImage` | T1, T2 (polyglot: a valid PNG with `<script>` / `<?php` appended) | "polyglot...", "EXIF / GPS metadata is stripped" |
| **EXIF / GPS removal** as a side effect of re-encoding | `inspectImage` | T6 | "EXIF / GPS metadata is stripped" |
| **PDF active-content scan** (`/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA`, `/SubmitForm`, `/ImportData`), including `#xx` name-escape evasion such as `/#4aavaScript` | `inspectPdf` | T1 | "PDF with JavaScript / OpenAction / Launch / embedded files..." |
| **Text files** must be valid UTF-8 with no NUL bytes | `inspectText` | T1 | "binary data or invalid UTF-8..." |
| **Safe file names**: control characters, bidi overrides, path separators and leading dots removed; length capped. Names are display-only and are **never** used in storage keys (keys are server-generated UUIDs). | `sanitizeName`, `storage.keys` | path traversal, T1 | "file names are sanitised" |
| **Quarantine + cleanup**: failed or abandoned uploads are deleted; a background job purges expired slots | `complete`, `expireStaleUploads` | T3 | "abandoned uploads are purged" |
| **Quotas**: files per user, bytes per user, open upload slots per user | `POST /api/uploads` | T3 | quota tests |
| **Rate limits**: login/registration and upload endpoints | `express-rate-limit` | T3, T7 | "login attempts are rate limited" |
| **Single use slots**: `pending -> processing` is claimed atomically, so a slot cannot be completed twice or concurrently | `claimUpload` | races, T3 | "an upload slot cannot be completed twice" |
| **Bounded concurrency** for image decoding (3 at a time) | `createLimiter` | T3 (memory) | by design |

### Serving files safely

* Files are only reachable through **short-lived signed GET URLs** (documents 2 minutes, thumbnails 15 minutes) created *after* an ownership check. The bucket is private and has Block Public Access enabled.
* The signature forces the response headers: `Content-Type` is the **server-validated** type, and documents are always `Content-Disposition: attachment`. Only re-encoded *images* may be shown inline.
* Objects are stored with `Content-Disposition: attachment` as a second layer.
* Files live on the **storage origin**, not on the app origin, so even a bug in validation could not run script with access to the app's cookies.
* The page itself has a strict **CSP** (`default-src 'none'`, scripts and styles from `'self'` only, no inline code, `frame-ancestors 'none'`, `object-src 'none'`); `X-Content-Type-Options: nosniff`; `Referrer-Policy: no-referrer`. The UI builds all DOM with `textContent`, never `innerHTML`, so file names cannot inject markup.

## 4. Controls against unauthorized access (IDOR)

* **Ownership is part of every query**, not a separate check that could be forgotten: `SELECT ... WHERE id = ? AND user_id = ?`, `DELETE ... WHERE id = ? AND user_id = ?`. Another user's id matches no row.
* **No existence oracle**: another user's file, a non-existent file and a malformed id all return the *same* `404` body (not `403`).
* The user id comes from the **server-side session**, never from the request body, query or URL.
* **Storage keys are namespaced by owner** (`files/<userId>/...`) and are generated by the server; users never supply keys. Signed URLs are created only for keys read from the caller's own database row.
* **Upload slots are owned too**: another user cannot call `complete` on your slot (404).
* File ids and upload ids are random UUIDv4 and are validated against a strict pattern before use. Pagination cursors are validated and always combined with `user_id`.
* Every endpoint except register, login and logout requires a session (401 otherwise).

Tests: "anonymous requests are refused on every endpoint", "Bob cannot download, delete or see Alice's file", "Bob cannot complete Alice's upload slot", "malformed ids and injection attempts", "every file object lives under its owner's prefix", "the cursor parameter cannot be used...".

## 5. Accounts and sessions

* Passwords: **scrypt** (N=16384, r=8, p=1) with a 16-byte random salt per user; 10 to 128 characters; compared with `timingSafeEqual`.
* Login returns the **same error and similar timing** for unknown email and wrong password (a dummy hash is computed).
* Session token: 32 random bytes in an `HttpOnly`, `SameSite=Lax` cookie (`Secure` in production). Only the **SHA-256 hash** of the token is stored, so a leaked database cannot be replayed. Logout deletes the session server-side; sessions expire.
* **CSRF** (T5): every state-changing request needs an `X-CSRF-Token` bound to the session, must come from our own `Origin` when the header is present, and cookies are `SameSite=Lax`. A token from another user's session is rejected.
* JSON bodies are limited to 10 KB; file bytes never pass through the API.
* Internal errors return a generic `500`; stack traces stay in the server log.

## 6. What this does NOT cover (be honest about the limits)

1. **No antivirus.** Re-encoding neutralises image payloads, but PDFs and text pass through unchanged. For hostile environments add ClamAV (or a cloud scanner) at the `inspect()` step.
2. **PDF scanning is a heuristic.** It reads raw bytes, so a keyword hidden inside a compressed object stream is not seen. This is why PDFs are always delivered as downloads from the storage origin and never rendered inline.
3. **Presigned-URL signature enforcement is done by S3, not by this code**, and the automated tests cannot prove it, because the local emulator (s3rver) accepts unsigned and tampered requests. Two tests are marked `skip` for that reason. Before going live, run one manual check against your real bucket: fetch a signed URL, change one character of the signature, and confirm you get `403`.
4. **Image library risk.** Decoding relies on `sharp`/libvips. Keep it updated (`npm audit`, Dependabot); decoding runs with pixel and size limits, but a parser bug is still possible. Running the app as an unprivileged user in a container limits the damage.
5. **Single-node design.** SQLite and the in-memory rate limiter are per process. For several instances use PostgreSQL and a shared limiter store (Redis).
6. **Not included:** email verification, password reset, MFA, account lockout beyond rate limiting, audit logging, per-file sharing links, server-side encryption configuration (enable SSE-S3 or SSE-KMS on the bucket).
7. **Registration reveals whether an email is taken** (needed for a usable sign-up form). Login does not.

## 7. Production checklist

* Serve only over HTTPS: `APP_ORIGIN=https://...`, `COOKIE_SECURE=true`, `TRUST_PROXY=true` behind a proxy.
* Bucket: Block Public Access **on**, no public ACLs or policy, default encryption on, CORS limited to `PUT`/`GET` from your app origin only.
* IAM user/role limited to this bucket with `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject` (and `s3:ListBucket` is not required).
* Lifecycle rule: expire objects under `quarantine/` after 1 day (belt and braces for crashes between upload and cleanup).
* Keep dependencies updated and run `npm test` in CI.
