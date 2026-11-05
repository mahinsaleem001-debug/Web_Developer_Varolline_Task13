import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import sharp from 'sharp';
import {
  startHarness, Client, solid, makePng, makeJpeg, makeWebp, makeJpegWithExif, makeAnimatedGif, makePdf,
} from './helpers.js';

let h;
let alice;
let bob;

before(async () => {
  h = await startHarness({ limits: { maxFileBytes: 400 * 1024 } });
  alice = new Client(h);
  bob = new Client(h);
  await alice.register('alice@example.com');
  await bob.register('bob@example.com');
});
after(() => h.close());

const objectExists = (key) => h.storage.exists(key);
const fetchStored = async (client, fileId) => {
  const { data } = await client.json('GET', `/api/files/${fileId}/download`);
  const res = await fetch(data.url);
  return { res, bytes: Buffer.from(await res.arrayBuffer()) };
};

describe('happy path: upload, thumbnail, gallery, delete', () => {
  test('a PNG is validated, re-encoded, thumbnailed and listed', async () => {
    const { init, put, complete, file } = await alice.upload(await makePng(300, 200), 'photo.png', 'image/png');
    assert.equal(init.status, 201);
    assert.equal(put.status, 200);
    assert.equal(complete.status, 201);
    assert.equal(file.kind, 'image');
    assert.equal(file.width, 300);
    assert.equal(file.height, 200);
    assert.match(file.thumbUrl, /X-Amz-Signature=/);

    const thumb = Buffer.from(await (await fetch(file.thumbUrl)).arrayBuffer());
    const meta = await sharp(thumb).metadata();
    assert.equal(meta.format, 'webp');
    assert.ok(meta.width <= 320 && meta.height <= 320);
  });

  test('upload goes through quarantine and the quarantine object is removed afterwards', async () => {
    const { init, file } = await alice.upload(await makeJpeg(), 'a.jpg', 'image/jpeg');
    const row = h.db.prepare('SELECT * FROM uploads WHERE id = ?').get(init.data.uploadId);
    assert.equal(row.status, 'done');
    assert.equal(await objectExists(row.quarantine_key), false);
    assert.ok(file.id);
  });

  test('WebP, animated GIF (converted to WebP), PDF and TXT are accepted', async () => {
    const webp = await alice.upload(await makeWebp(), 'x.webp', 'image/webp');
    assert.equal(webp.complete.status, 201);

    const gif = await alice.upload(await makeAnimatedGif(), 'anim.gif', 'image/gif');
    assert.equal(gif.complete.status, 201, JSON.stringify(gif.complete.data));
    assert.equal(gif.file.mime, 'image/webp');

    const pdf = await alice.upload(makePdf(), 'doc.pdf', 'application/pdf');
    assert.equal(pdf.complete.status, 201);
    assert.equal(pdf.file.thumbUrl, null);

    const txt = await alice.upload(Buffer.from('hello, wörld\n'), 'notes.txt', 'text/plain');
    assert.equal(txt.complete.status, 201);
  });

  test('gallery lists files newest first and paginates with a cursor', async () => {
    const c = new Client(h);
    await c.register('pager@example.com');
    for (let i = 0; i < 5; i++) await c.upload(await makePng(40 + i, 40), `p${i}.png`, 'image/png');
    const first = await c.json('GET', '/api/files?limit=2');
    assert.equal(first.data.files.length, 2);
    assert.ok(first.data.nextCursor);
    const second = await c.json('GET', `/api/files?limit=2&cursor=${first.data.nextCursor}`);
    assert.equal(second.data.files.length, 2);
    const ids = new Set([...first.data.files, ...second.data.files].map((f) => f.id));
    assert.equal(ids.size, 4, 'pages must not overlap');
    assert.equal(first.data.usage.files, 5);
  });

  test('delete removes the file, its thumbnail and the database row', async () => {
    const { file } = await alice.upload(await makePng(), 'gone.png', 'image/png');
    const row = h.db.prepare('SELECT * FROM files WHERE id = ?').get(file.id);
    assert.equal(await objectExists(row.storage_key), true);
    assert.equal(await objectExists(row.thumb_key), true);

    const del = await alice.json('DELETE', `/api/files/${file.id}`);
    assert.equal(del.status, 204);
    assert.equal(await objectExists(row.storage_key), false);
    assert.equal(await objectExists(row.thumb_key), false);
    assert.equal(h.db.prepare('SELECT COUNT(*) n FROM files WHERE id = ?').get(file.id).n, 0);
    assert.equal((await alice.json('GET', `/api/files/${file.id}/download`)).status, 404);
  });
});

describe('malicious uploads are rejected', () => {
  test('disallowed MIME types never get an upload slot (HTML, SVG, EXE, ZIP, Office)', async () => {
    for (const [name, type] of [
      ['page.html', 'text/html'],
      ['logo.svg', 'image/svg+xml'],
      ['setup.exe', 'application/x-msdownload'],
      ['bundle.zip', 'application/zip'],
      ['macro.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
      ['x.js', 'text/javascript'],
    ]) {
      const r = await alice.json('POST', '/api/uploads', { body: { name, type, size: 100 } });
      assert.equal(r.status, 422, `${type} should be rejected`);
      assert.equal(r.data.error.code, 'unsupported_type');
    }
  });

  test('extension must match the declared type (double extensions, wrong extension)', async () => {
    for (const [name, type] of [
      ['evil.exe', 'image/png'],
      ['photo.png.exe', 'image/png'],
      ['photo.png', 'application/pdf'],
      ['noextension', 'image/png'],
      ['.png', 'image/png'],
    ]) {
      const r = await alice.json('POST', '/api/uploads', { body: { name, type, size: 100 } });
      assert.equal(r.status, 422, `${name} as ${type}`);
      assert.equal(r.data.error.code, 'extension_mismatch');
    }
  });

  test('size is validated: zero, negative, fractional, non-numeric and oversized declarations', async () => {
    for (const size of [0, -5, 1.5, '100', null, h.config.limits.maxFileBytes + 1]) {
      const r = await alice.json('POST', '/api/uploads', { body: { name: 'a.png', type: 'image/png', size } });
      assert.equal(r.status, 422, `size ${JSON.stringify(size)}`);
    }
  });

  test('HTML disguised as a PNG fails the magic-byte check and is purged from storage', async () => {
    const html = Buffer.from('<html><script>alert(document.cookie)</script></html>');
    const { init, complete } = await alice.upload(html, 'cute.png', 'image/png');
    assert.equal(complete.status, 422);
    assert.equal(complete.data.error.code, 'content_mismatch');
    const row = h.db.prepare('SELECT * FROM uploads WHERE id = ?').get(init.data.uploadId);
    assert.equal(row.status, 'rejected');
    assert.equal(await objectExists(row.quarantine_key), false, 'rejected bytes must not stay in the bucket');
  });

  test('SVG with script uploaded as image/png is rejected', async () => {
    const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
    const { complete } = await alice.upload(svg, 'a.png', 'image/png');
    assert.equal(complete.status, 422);
  });

  test('a real JPEG declared as PNG is rejected (type confusion)', async () => {
    const { complete } = await alice.upload(await makeJpeg(), 'a.png', 'image/png');
    assert.equal(complete.status, 422);
    assert.equal(complete.data.error.code, 'content_mismatch');
  });

  test('an executable renamed to .png is rejected', async () => {
    const mz = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(300, 1)]);
    const { complete } = await alice.upload(mz, 'photo.png', 'image/png');
    assert.equal(complete.status, 422);
  });

  test('a truncated / corrupt PNG is rejected', async () => {
    const png = await makePng(500, 500);
    const { complete } = await alice.upload(png.subarray(0, Math.floor(png.length / 2)), 'broken.png', 'image/png');
    assert.equal(complete.status, 422);
    assert.equal(complete.data.error.code, 'corrupt_image');
  });

  test('uploading a different size than declared is rejected', async () => {
    const real = await makePng(100, 100);
    const { complete } = await alice.upload(real, 'a.png', 'image/png', { declaredSize: real.length + 50 });
    assert.equal(complete.status, 422);
    assert.equal(complete.data.error.code, 'size_mismatch');
  });

  test('declaring a tiny size but uploading far more is stopped by the byte cap (413)', async () => {
    const big = Buffer.alloc(h.config.limits.maxFileBytes + 200 * 1024, 7);
    const { complete, init } = await alice.upload(big, 'a.png', 'image/png', { declaredSize: 100 });
    assert.equal(complete.status, 413);
    const row = h.db.prepare('SELECT * FROM uploads WHERE id = ?').get(init.data.uploadId);
    assert.equal(await objectExists(row.quarantine_key), false);
  });

  test('decompression bomb: an image with too many pixels is rejected without being decoded', async () => {
    // 6000 x 6000 = 36 MP, over the 30 MP limit, but tiny on the wire because it is one flat colour.
    const bomb = await sharp(solid(6000, 6000)).png({ compressionLevel: 9 }).toBuffer();
    assert.ok(bomb.length < h.config.limits.maxFileBytes, `fixture must fit the size limit (${bomb.length})`);
    const { complete } = await alice.upload(bomb, 'bomb.png', 'image/png');
    assert.equal(complete.status, 422);
    assert.match(complete.data.error.code, /corrupt_image|dimensions/);
  });

  test('absurd single dimension is rejected', async () => {
    const strip = await sharp(solid(13000, 4)).png().toBuffer();
    const { complete } = await alice.upload(strip, 'strip.png', 'image/png');
    assert.equal(complete.status, 422);
    assert.equal(complete.data.error.code, 'dimensions');
  });

  test('PDF with JavaScript / OpenAction / Launch / embedded files is rejected, a clean PDF is accepted', async () => {
    for (const extra of ['/OpenAction 4 0 R', '/Names<</JavaScript 5 0 R>>', '/AA<</O 6 0 R>>', '/S/Launch', '/Type/EmbeddedFile', '/#4aavaScript 5 0 R']) {
      const { complete } = await alice.upload(makePdf(extra), 'doc.pdf', 'application/pdf');
      assert.equal(complete.status, 422, `PDF containing ${extra}`);
      assert.equal(complete.data.error.code, 'active_content');
    }
    assert.equal((await alice.upload(makePdf('/Lang(en)'), 'ok.pdf', 'application/pdf')).complete.status, 201);
  });

  test('a PDF-looking text file and a truncated PDF are rejected', async () => {
    assert.equal((await alice.upload(Buffer.from('hello'), 'x.pdf', 'application/pdf')).complete.status, 422);
    assert.equal((await alice.upload(Buffer.from('%PDF-1.4\n1 0 obj<<>>endobj\n'), 'x.pdf', 'application/pdf')).complete.status, 422);
  });

  test('binary data or invalid UTF-8 in a .txt file is rejected', async () => {
    assert.equal((await alice.upload(Buffer.from([0x68, 0x69, 0x00, 0x01]), 'a.txt', 'text/plain')).complete.status, 422);
    assert.equal((await alice.upload(Buffer.from([0xff, 0xfe, 0xfd, 0x41]), 'b.txt', 'text/plain')).complete.status, 422);
  });

  test('EXIF / GPS metadata is stripped because the image is re-encoded', async () => {
    const src = await makeJpegWithExif();
    assert.ok(src.includes(Buffer.from('SECRET-COPYRIGHT-MARKER')), 'fixture should contain the marker');
    const { file, complete } = await alice.upload(src, 'geo.jpg', 'image/jpeg');
    assert.equal(complete.status, 201);
    const { bytes } = await fetchStored(alice, file.id);
    assert.equal(bytes.includes(Buffer.from('SECRET-COPYRIGHT-MARKER')), false);
    assert.equal(bytes.includes(Buffer.from('SECRET-ARTIST')), false);
    assert.equal((await sharp(bytes).metadata()).exif, undefined);
  });

  test('polyglot: a valid PNG with a script appended stores only clean re-encoded pixels', async () => {
    const payload = Buffer.from('<script>alert("pwned")</script><?php system($_GET["c"]); ?>');
    const polyglot = Buffer.concat([await makePng(), payload]);
    const { file, complete } = await alice.upload(polyglot, 'poly.png', 'image/png');
    assert.equal(complete.status, 201);
    const { bytes } = await fetchStored(alice, file.id);
    assert.equal(bytes.includes(Buffer.from('<script>')), false);
    assert.equal(bytes.includes(Buffer.from('<?php')), false);
    assert.equal((await sharp(bytes).metadata()).format, 'png');
  });

  test('file names are sanitised: no path traversal, control characters or bidi tricks', async () => {
    const { file } = await alice.upload(await makePng(), '../../etc/pass\u0000wd‮gnp.png', 'image/png');
    assert.ok(file, 'upload should succeed with a sanitised name');
    assert.doesNotMatch(file.name, /[\\/\u0000‮]/);
    assert.ok(file.name.endsWith('.png'));
    const row = h.db.prepare('SELECT * FROM files WHERE id = ?').get(file.id);
    assert.doesNotMatch(row.storage_key, /etc|passwd|\.\./);
    assert.match(row.storage_key, /^files\/[0-9a-f-]{36}\/[0-9a-f-]{36}$/);
  });

  test('an upload slot cannot be completed twice', async () => {
    const png = await makePng();
    const { init, complete } = await alice.upload(png, 'a.png', 'image/png');
    assert.equal(complete.status, 201);
    const again = await alice.json('POST', `/api/uploads/${init.data.uploadId}/complete`);
    assert.equal(again.status, 409);
  });

  test('completing without uploading anything fails cleanly', async () => {
    const init = await alice.json('POST', '/api/uploads', { body: { name: 'a.png', type: 'image/png', size: 100 } });
    const r = await alice.json('POST', `/api/uploads/${init.data.uploadId}/complete`);
    assert.equal(r.status, 422);
    assert.equal(r.data.error.code, 'missing_object');
  });

  test('abandoned uploads are purged from quarantine by the cleanup job', async () => {
    const png = await makePng();
    const init = await alice.json('POST', '/api/uploads', { body: { name: 'a.png', type: 'image/png', size: png.length } });
    await fetch(init.data.url, { method: 'PUT', headers: init.data.headers, body: png });
    const row = h.db.prepare('SELECT * FROM uploads WHERE id = ?').get(init.data.uploadId);
    assert.equal(await objectExists(row.quarantine_key), true);

    h.db.prepare('UPDATE uploads SET expires_at = ? WHERE id = ?').run(Date.now() - 1000, row.id);
    assert.ok((await h.expireStaleUploads()) >= 1);
    assert.equal(await objectExists(row.quarantine_key), false);
    const late = await alice.json('POST', `/api/uploads/${row.id}/complete`);
    assert.equal(late.status, 409, 'an expired slot cannot be completed');
  });
});

describe('access control: users cannot touch each other’s files', () => {
  let aliceFile;
  let aliceUploadId;
  before(async () => {
    const r = await alice.upload(await makePng(80, 80), 'private.png', 'image/png');
    aliceFile = r.file;
    aliceUploadId = r.init.data.uploadId;
  });

  test('/api/auth/me reports no user for anonymous visitors', async () => {
    assert.equal((await new Client(h).json('GET', '/api/auth/me')).data.user, null);
  });

  test('anonymous requests are refused on every endpoint', async () => {
    const anon = new Client(h);
    for (const [method, url] of [
      ['GET', '/api/files'],
      ['GET', `/api/files/${aliceFile.id}/download`],
      ['DELETE', `/api/files/${aliceFile.id}`],
      ['POST', '/api/uploads'],
      ['POST', `/api/uploads/${aliceUploadId}/complete`],
    ]) {
      const r = await anon.json(method, url, { body: method === 'POST' ? {} : undefined, csrf: false });
      assert.equal(r.status, 401, `${method} ${url}`);
    }
  });

  test('Bob cannot download, delete or see Alice’s file (404, same as a missing id)', async () => {
    const dl = await bob.json('GET', `/api/files/${aliceFile.id}/download`);
    assert.equal(dl.status, 404);
    const del = await bob.json('DELETE', `/api/files/${aliceFile.id}`);
    assert.equal(del.status, 404);
    const missing = await bob.json('GET', '/api/files/00000000-0000-4000-8000-000000000000/download');
    assert.equal(missing.status, 404);
    assert.deepEqual(dl.data, missing.data, 'no difference between "not yours" and "does not exist"');

    const list = await bob.json('GET', '/api/files');
    assert.equal(list.data.files.some((f) => f.id === aliceFile.id), false);
    assert.equal((await alice.json('GET', `/api/files/${aliceFile.id}/download`)).status, 200, 'still there for Alice');
  });

  test('Bob cannot complete Alice’s upload slot', async () => {
    const png = await makePng();
    const init = await alice.json('POST', '/api/uploads', { body: { name: 'a.png', type: 'image/png', size: png.length } });
    await fetch(init.data.url, { method: 'PUT', headers: init.data.headers, body: png });
    const hijack = await bob.json('POST', `/api/uploads/${init.data.uploadId}/complete`);
    assert.equal(hijack.status, 404);
    assert.equal((await alice.json('POST', `/api/uploads/${init.data.uploadId}/complete`)).status, 201, 'Alice can still finish it');
  });

  test('malformed ids and injection attempts behave like missing files', async () => {
    for (const id of ['abc', '1', "'; DROP TABLE files;--", '..%2F..%2Fetc%2Fpasswd', '%00']) {
      const r = await alice.json('GET', `/api/files/${id}/download`);
      assert.equal(r.status, 404, id);
    }
    assert.ok(h.db.prepare('SELECT COUNT(*) n FROM files').get().n > 0, 'table still exists');
  });

  test('every file object lives under its owner’s prefix', async () => {
    const rows = h.db.prepare('SELECT user_id, storage_key, thumb_key FROM files').all();
    for (const r of rows) {
      assert.ok(r.storage_key.startsWith(`files/${r.user_id}/`));
      if (r.thumb_key) assert.ok(r.thumb_key.startsWith(`thumbs/${r.user_id}/`));
    }
  });

  test('the cursor parameter cannot be used to read other users’ rows', async () => {
    const r = await bob.json('GET', `/api/files?cursor=${Date.now() + 99999}_${aliceFile.id}`);
    assert.equal(r.status, 200);
    assert.equal(r.data.files.some((f) => f.owner || f.id === aliceFile.id), false);
  });
});

describe('signed URLs', () => {
  test('every URL the API hands out is signed and short-lived', async () => {
    const png = await makePng();
    const init = await alice.json('POST', '/api/uploads', { body: { name: 'a.png', type: 'image/png', size: png.length } });
    const up = new URL(init.data.url);
    assert.equal(up.searchParams.get('X-Amz-Algorithm'), 'AWS4-HMAC-SHA256');
    assert.ok(Number(up.searchParams.get('X-Amz-Expires')) <= 300);
    assert.match(up.searchParams.get('X-Amz-SignedHeaders'), /content-length/);
    assert.match(up.searchParams.get('X-Amz-SignedHeaders'), /content-type/);

    const list = await alice.json('GET', '/api/files');
    for (const f of list.data.files.filter((x) => x.thumbUrl)) {
      assert.match(f.thumbUrl, /X-Amz-Signature=[0-9a-f]{64}/);
      assert.ok(Number(new URL(f.thumbUrl).searchParams.get('X-Amz-Expires')) <= 900);
    }
    const dl = await alice.json('GET', `/api/files/${list.data.files[0].id}/download`);
    assert.ok(Number(new URL(dl.data.url).searchParams.get('X-Amz-Expires')) <= 120);
  });

  test('downloads force Content-Disposition and the stored content type', async () => {
    const pdf = await alice.upload(makePdf(), 'report.pdf', 'application/pdf');
    const { data } = await alice.json('GET', `/api/files/${pdf.file.id}/download?inline=1`);
    const res = await fetch(data.url);
    assert.match(res.headers.get('content-disposition'), /^attachment;/, 'documents are never rendered inline');
    assert.equal(res.headers.get('content-type'), 'application/pdf');
    await res.arrayBuffer();
  });

  test('a signed URL for one object cannot be re-pointed at another key', { skip: 'needs an S3 server that enforces presigned signatures (AWS S3, MinIO, R2). The local emulator s3rver does not, so this cannot be proven here.' }, async () => {
    const a = await alice.upload(await makePng(50, 50), 'a.png', 'image/png');
    const b = await bob.upload(await makePng(60, 60), 'b.png', 'image/png');
    const rowB = h.db.prepare('SELECT storage_key FROM files WHERE id = ?').get(b.file.id);
    const { data } = await alice.json('GET', `/api/files/${a.file.id}/download`);
    const tampered = new URL(data.url);
    tampered.pathname = `/uploads/${rowB.storage_key}`;
    const res = await fetch(tampered);
    assert.equal(res.status, 403, 'signature must not validate for a different key');
    await res.arrayBuffer();
  });

  test('a tampered signature is refused', { skip: 'needs an S3 server that enforces presigned signatures (AWS S3, MinIO, R2). The local emulator s3rver does not, so this cannot be proven here.' }, async () => {
    const f = await alice.upload(await makePng(), 'a.png', 'image/png');
    const { data } = await alice.json('GET', `/api/files/${f.file.id}/download`);
    const res = await fetch(data.url.replace(/X-Amz-Signature=[0-9a-f]{6}/, 'X-Amz-Signature=000000'));
    assert.equal(res.status, 403);
    await res.arrayBuffer();
  });
});

describe('sessions, CSRF and headers', () => {
  test('state-changing requests need a valid CSRF token', async () => {
    const f = await alice.upload(await makePng(), 'a.png', 'image/png');
    const none = await alice.json('DELETE', `/api/files/${f.file.id}`, { csrf: false });
    assert.equal(none.status, 403);
    assert.equal(none.data.error.code, 'bad_csrf');
    const wrong = await alice.json('DELETE', `/api/files/${f.file.id}`, { csrf: false, headers: { 'X-CSRF-Token': 'nope' } });
    assert.equal(wrong.status, 403);
    // Bob's valid token must not work on Alice's session either
    const crossToken = await alice.json('DELETE', `/api/files/${f.file.id}`, { csrf: false, headers: { 'X-CSRF-Token': bob.csrf } });
    assert.equal(crossToken.status, 403);
    assert.equal((await alice.json('DELETE', `/api/files/${f.file.id}`)).status, 204);
  });

  test('requests from a foreign Origin are blocked even with a valid token', async () => {
    const f = await alice.upload(await makePng(), 'a.png', 'image/png');
    const r = await alice.json('DELETE', `/api/files/${f.file.id}`, { origin: 'https://evil.example' });
    assert.equal(r.status, 403);
    assert.equal(r.data.error.code, 'bad_origin');
    const ok = await alice.json('DELETE', `/api/files/${f.file.id}`, { origin: h.appOrigin });
    assert.equal(ok.status, 204);
  });

  test('the session cookie is HttpOnly and SameSite=Lax, and the raw token is not stored', async () => {
    const c = new Client(h);
    const r = await c.json('POST', '/api/auth/register', { body: { email: 'cookie@example.com', password: 'another-long-password' } });
    const cookie = r.res.headers.getSetCookie().find((x) => x.startsWith('sid='));
    assert.match(cookie, /HttpOnly/i);
    assert.match(cookie, /SameSite=Lax/i);
    const token = cookie.split(';')[0].slice(4);
    const stored = h.db.prepare('SELECT token_hash FROM sessions').all().map((s) => s.token_hash);
    assert.equal(stored.includes(token), false, 'only a hash of the token may be stored');
  });

  test('logout invalidates the session server-side', async () => {
    const c = new Client(h);
    await c.register('logout@example.com');
    const stolen = c.cookie;
    assert.equal((await c.json('GET', '/api/auth/me')).data.user.email, 'logout@example.com');
    await c.json('POST', '/api/auth/logout');
    const replay = new Client(h);
    replay.cookie = stolen;
    assert.equal((await replay.json('GET', '/api/auth/me')).data.user, null, 'the old cookie must be dead');
    assert.equal((await replay.json('GET', '/api/files')).status, 401);
  });

  test('login errors do not reveal whether an email exists; passwords are hashed', async () => {
    const a = await new Client(h).json('POST', '/api/auth/login', { body: { email: 'alice@example.com', password: 'wrong-password-123' } });
    const b = await new Client(h).json('POST', '/api/auth/login', { body: { email: 'nobody@example.com', password: 'wrong-password-123' } });
    assert.equal(a.status, 401);
    assert.equal(b.status, 401);
    assert.deepEqual(a.data, b.data);
    const hash = h.db.prepare('SELECT password_hash FROM users WHERE email = ?').get('alice@example.com').password_hash;
    assert.match(hash, /^scrypt\$[0-9a-f]{32}\$[0-9a-f]{128}$/);
    assert.equal(hash.includes('correct-horse'), false);
  });

  test('weak or malformed credentials are refused', async () => {
    const c = new Client(h);
    for (const body of [{ email: 'bad', password: 'long-enough-password' }, { email: 'x@y.com', password: 'short' }, { email: 'x@y.com' }, {}, { email: ['a@b.com'], password: 'long-enough-password' }]) {
      const r = await c.json('POST', '/api/auth/register', { body });
      assert.equal(r.status, 400, JSON.stringify(body));
    }
  });

  test('security headers and a strict CSP are set', async () => {
    const res = await fetch(h.base + '/');
    assert.equal(res.status, 200);
    const csp = res.headers.get('content-security-policy');
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /script-src 'self'/);
    assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /object-src 'none'/);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-powered-by'), null);
    await res.arrayBuffer();
  });

  test('API responses are never cached and internal errors do not leak details', async () => {
    const r = await alice.json('GET', '/api/files');
    assert.equal(r.res.headers.get('cache-control'), 'no-store');
    const bad = await alice.raw('POST', '/api/uploads', { body: Buffer.from('{not json'), headers: { 'Content-Type': 'application/json' } });
    assert.equal(bad.status, 400);
    assert.doesNotMatch(await bad.text(), /at .*\.js|node_modules|SyntaxError/);
  });

  test('oversized JSON bodies are rejected', async () => {
    const r = await alice.json('POST', '/api/uploads', { body: { name: 'a'.repeat(50_000), type: 'image/png', size: 5 } });
    assert.equal(r.status, 413);
  });
});

describe('quotas and rate limits', () => {
  test('per-user file-count quota is enforced', async () => {
    const q = await startHarness({ limits: { maxFilesPerUser: 2 } });
    try {
      const c = new Client(q);
      await c.register('quota@example.com');
      const png = await makePng();
      assert.equal((await c.upload(png, '1.png', 'image/png')).complete.status, 201);
      assert.equal((await c.upload(png, '2.png', 'image/png')).complete.status, 201);
      const third = await c.json('POST', '/api/uploads', { body: { name: '3.png', type: 'image/png', size: png.length } });
      assert.equal(third.status, 409);
      assert.equal(third.data.error.code, 'quota_files');
    } finally {
      await q.close();
    }
  });

  test('per-user storage quota is enforced', async () => {
    const q = await startHarness({ limits: { maxBytesPerUser: 20 * 1024 } });
    try {
      const c = new Client(q);
      await c.register('bytes@example.com');
      const big = await sharp({ create: { width: 400, height: 400, channels: 3, noise: { type: 'gaussian', mean: 128, sigma: 60 } } }).jpeg({ quality: 90 }).toBuffer();
      const r = await c.upload(big, 'big.jpg', 'image/jpeg');
      assert.ok([409, 201].includes(r.init.status));
      const second = await c.json('POST', '/api/uploads', { body: { name: 'b.jpg', type: 'image/jpeg', size: big.length } });
      assert.equal(second.status, 409);
      assert.equal(second.data.error.code, 'quota_storage');
    } finally {
      await q.close();
    }
  });

  test('login attempts are rate limited', async () => {
    const q = await startHarness({ rateLimit: { auth: { windowMs: 60_000, limit: 3 }, uploads: { windowMs: 60_000, limit: 100 } } });
    try {
      const c = new Client(q);
      const codes = [];
      for (let i = 0; i < 5; i++) codes.push((await c.json('POST', '/api/auth/login', { body: { email: 'a@b.com', password: 'whatever-password' } })).status);
      assert.deepEqual(codes, [401, 401, 401, 429, 429]);
    } finally {
      await q.close();
    }
  });

  test('upload slots are rate limited', async () => {
    const q = await startHarness({ rateLimit: { auth: { windowMs: 60_000, limit: 100 }, uploads: { windowMs: 60_000, limit: 4 } } });
    try {
      const c = new Client(q);
      await c.register('rl@example.com');
      const codes = [];
      for (let i = 0; i < 6; i++) codes.push((await c.json('POST', '/api/uploads', { body: { name: 'a.png', type: 'image/png', size: 100 } })).status);
      assert.equal(codes.filter((s) => s === 429).length, 2);
    } finally {
      await q.close();
    }
  });

  test('a user cannot hold unlimited open upload slots', async () => {
    const c = new Client(h);
    await c.register('slots@example.com');
    const codes = [];
    for (let i = 0; i < h.config.limits.maxPendingPerUser + 3; i++) {
      codes.push((await c.json('POST', '/api/uploads', { body: { name: 'a.png', type: 'image/png', size: 100 } })).status);
    }
    assert.equal(codes.filter((s) => s === 201).length, h.config.limits.maxPendingPerUser);
    assert.equal(codes.at(-1), 429);
  });
});
