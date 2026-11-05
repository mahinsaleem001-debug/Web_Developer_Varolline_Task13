import crypto from 'node:crypto';
import { fileTypeFromBuffer } from 'file-type';
import sharp from 'sharp';
import { UploadRejected } from './errors.js';

sharp.cache(false); // do not keep decoded untrusted images around
sharp.concurrency(2);

/**
 * Allow-list. Everything not listed here is rejected, including SVG (can carry script),
 * HTML, archives, executables and Office files (macros).
 *   ext  -> accepted file extensions
 *   kind -> how the file is handled
 */
export const ALLOWED = {
  'image/jpeg': { kind: 'image', ext: ['jpg', 'jpeg'] },
  'image/png': { kind: 'image', ext: ['png'] },
  'image/webp': { kind: 'image', ext: ['webp'] },
  'image/gif': { kind: 'image', ext: ['gif'] },
  'application/pdf': { kind: 'document', ext: ['pdf'] },
  'text/plain': { kind: 'document', ext: ['txt'] },
};

/** Characters we never keep in a stored file name (path separators, control chars, bidi tricks). */
export function sanitizeName(raw) {
  let name = String(raw ?? '')
    .normalize('NFC')
    .replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g, '')
    .replace(/[\\/:*?"<>|]+/g, '_')
    .replace(/^\.+/, '')
    .trim();
  if (name.length > 120) {
    const dot = name.lastIndexOf('.');
    const ext = dot > 0 && name.length - dot <= 8 ? name.slice(dot) : '';
    name = name.slice(0, 120 - ext.length) + ext;
  }
  return name || 'file';
}

const extensionOf = (name) => {
  const dot = name.lastIndexOf('.');
  return dot > 0 ? name.slice(dot + 1).toLowerCase() : '';
};

/**
 * First line of defence, before any bytes are uploaded. This only checks what the client
 * *claims*; the real checks happen in inspect() on the bytes themselves.
 */
export function validateDeclaration({ name, type, size }, limits) {
  const clean = sanitizeName(name);
  const rule = ALLOWED[type];
  if (!rule) throw new UploadRejected('unsupported_type', 'This file type is not allowed. Use JPEG, PNG, WebP, GIF, PDF or TXT.');
  if (!rule.ext.includes(extensionOf(clean))) {
    throw new UploadRejected('extension_mismatch', `The file extension does not match its type (${type}).`);
  }
  if (!Number.isInteger(size) || size <= 0) throw new UploadRejected('empty_file', 'The file is empty.');
  if (size > limits.maxFileBytes) {
    throw new UploadRejected('too_large', `The file is larger than ${Math.floor(limits.maxFileBytes / 1024 / 1024)} MB.`);
  }
  return { name: clean, type, kind: rule.kind };
}

/* ------------------------------------------------------------------ *
 * Second line of defence: look at the actual bytes.
 * Returns the *sanitised* file to store, never the untrusted original.
 * ------------------------------------------------------------------ */

export async function inspect(buffer, declaredType, limits, thumbnailSize) {
  const rule = ALLOWED[declaredType];
  if (!rule) throw new UploadRejected('unsupported_type', 'This file type is not allowed.');

  if (rule.kind === 'image') return inspectImage(buffer, declaredType, limits, thumbnailSize);
  if (declaredType === 'application/pdf') return inspectPdf(buffer, declaredType);
  return inspectText(buffer, declaredType);
}

async function inspectImage(buffer, declaredType, limits, thumbnailSize) {
  // 1. Magic bytes must say it is the image type the client declared.
  const detected = await fileTypeFromBuffer(buffer);
  if (!detected || detected.mime !== declaredType) {
    throw new UploadRejected('content_mismatch', 'The file content does not match its declared image type.');
  }

  try {
    const input = { limitInputPixels: limits.maxPixels, failOn: 'error', animated: declaredType === 'image/gif' || declaredType === 'image/webp' };
    const meta = await sharp(buffer, input).metadata();

    // 2. Reject decompression bombs and absurd shapes before decoding anything.
    const frameHeight = meta.pageHeight || meta.height;
    if (!meta.width || !frameHeight) throw new UploadRejected('corrupt_image', 'The image is corrupt or unreadable.');
    if (meta.width > limits.maxDimension || frameHeight > limits.maxDimension) {
      throw new UploadRejected('dimensions', `Image dimensions are larger than ${limits.maxDimension} px.`);
    }
    if ((meta.pages || 1) > limits.maxFrames) throw new UploadRejected('too_many_frames', 'The animation has too many frames.');

    // 3. Fully decode and RE-ENCODE. The stored file is brand new pixels, so EXIF/GPS data,
    //    embedded scripts, trailing payloads and polyglot tricks do not survive.
    let pipeline = sharp(buffer, input).rotate(); // apply EXIF orientation, then metadata is dropped
    let mime;
    if (declaredType === 'image/jpeg') {
      pipeline = pipeline.jpeg({ quality: 88, mozjpeg: true });
      mime = 'image/jpeg';
    } else if (declaredType === 'image/png') {
      pipeline = pipeline.png({ compressionLevel: 9 });
      mime = 'image/png';
    } else {
      // WebP stays WebP; GIF is converted to (animated) WebP, which is safer and smaller.
      pipeline = pipeline.webp({ quality: 88 });
      mime = 'image/webp';
    }
    const { data, info } = await pipeline.toBuffer({ resolveWithObject: true });

    // 4. Thumbnail from the first frame only.
    const thumb = await sharp(buffer, { limitInputPixels: limits.maxPixels, failOn: 'error' })
      .rotate()
      .resize(thumbnailSize, thumbnailSize, { fit: 'cover', position: 'attention' })
      .webp({ quality: 76 })
      .toBuffer();

    return {
      kind: 'image',
      mime,
      body: data,
      width: info.width,
      height: info.pageHeight || info.height,
      thumb,
    };
  } catch (err) {
    if (err instanceof UploadRejected) throw err;
    throw new UploadRejected('corrupt_image', 'The image is corrupt, unsupported or too large to process.');
  }
}

// PDF features that can run code or reach outside the file. This is a heuristic scan of the
// raw bytes (objects inside compressed streams are not visible), so PDFs are also always
// delivered as a download and never rendered inline by our origin.
const PDF_ACTIVE_CONTENT = [
  '/JavaScript', '/JS', '/OpenAction', '/AA', '/Launch', '/EmbeddedFile', '/RichMedia', '/XFA', '/SubmitForm', '/ImportData',
];

function inspectPdf(buffer, declaredType) {
  const head = buffer.subarray(0, 1024).toString('latin1');
  if (!head.includes('%PDF-')) throw new UploadRejected('content_mismatch', 'The file is not a valid PDF.');
  const tail = buffer.subarray(Math.max(0, buffer.length - 2048)).toString('latin1');
  if (!tail.includes('%%EOF')) throw new UploadRejected('corrupt_document', 'The PDF is truncated or corrupt.');

  // PDF names may hide characters as #xx hex escapes ("/#4aavaScript" is "/JavaScript"),
  // so decode those first, otherwise a trivial escape would slip past the scan.
  const text = buffer
    .toString('latin1')
    .replace(/#([0-9a-fA-F]{2})/g, (_m, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
  for (const token of PDF_ACTIVE_CONTENT) {
    // Match the whole name token ("/JS" must not match "/JSON").
    if (new RegExp(token + '(?![A-Za-z0-9])').test(text)) {
      throw new UploadRejected('active_content', 'PDFs with scripts, embedded files or launch actions are not allowed.');
    }
  }
  return { kind: 'document', mime: declaredType, body: buffer, width: null, height: null, thumb: null };
}

function inspectText(buffer, declaredType) {
  if (buffer.includes(0)) throw new UploadRejected('content_mismatch', 'The file is not plain text.');
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    throw new UploadRejected('content_mismatch', 'The text file must be valid UTF-8.');
  }
  return { kind: 'document', mime: declaredType, body: buffer, width: null, height: null, thumb: null };
}

export const sha256Hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

/** Tiny semaphore so a burst of uploads cannot decode many large images at once. */
export function createLimiter(max) {
  let active = 0;
  const queue = [];
  const next = () => {
    if (active >= max || !queue.length) return;
    active++;
    const { fn, resolve, reject } = queue.shift();
    fn().then(resolve, reject).finally(() => {
      active--;
      next();
    });
  };
  return (fn) => new Promise((resolve, reject) => {
    queue.push({ fn, resolve, reject });
    next();
  });
}
