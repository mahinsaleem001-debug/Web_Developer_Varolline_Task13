import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
  CreateBucketCommand,
  PutBucketCorsCommand,
  PutPublicAccessBlockCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { HttpError } from './errors.js';

/**
 * Thin wrapper around an S3-compatible bucket (AWS S3, MinIO, Cloudflare R2, s3rver...).
 *
 * Key layout (all keys are server-generated UUIDs, never user input):
 *   quarantine/<userId>/<uploadId>   raw bytes straight from the browser (untrusted)
 *   files/<userId>/<fileId>          sanitised, re-encoded original
 *   thumbs/<userId>/<fileId>.webp    generated thumbnail
 *
 * The bucket itself stays private: the browser only ever receives short-lived signed URLs.
 */
export function createStorage(cfg) {
  const { s3, ttl } = cfg;
  const client = new S3Client({
    region: s3.region,
    endpoint: s3.endpoint,
    forcePathStyle: s3.forcePathStyle,
    credentials: s3.accessKeyId ? { accessKeyId: s3.accessKeyId, secretAccessKey: s3.secretAccessKey } : undefined,
    // Newer SDKs add CRC checksums to PUTs by default; that breaks browser uploads to signed URLs.
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
  });
  const Bucket = s3.bucket;

  return {
    keys: {
      quarantine: (userId, uploadId) => `quarantine/${userId}/${uploadId}`,
      file: (userId, fileId) => `files/${userId}/${fileId}`,
      thumb: (userId, fileId) => `thumbs/${userId}/${fileId}.webp`,
    },

    /** Signed URL the browser uses to PUT the raw file directly into quarantine. */
    signedUpload({ key, contentType, contentLength }) {
      return getSignedUrl(
        client,
        new PutObjectCommand({ Bucket, Key: key, ContentType: contentType, ContentLength: contentLength }),
        { expiresIn: ttl.putSeconds, signableHeaders: new Set(['content-type', 'content-length']) },
      );
    },

    /** Signed URL for reading a stored object. The response headers are forced by the signature. */
    signedDownload({ key, contentType, filename, inline, expiresIn }) {
      return getSignedUrl(
        client,
        new GetObjectCommand({
          Bucket,
          Key: key,
          ResponseContentType: contentType,
          ResponseContentDisposition: contentDisposition(filename, inline),
          ResponseCacheControl: 'private, max-age=300',
        }),
        { expiresIn },
      );
    },

    /**
     * Read an object fully into memory, aborting as soon as it exceeds `maxBytes`.
     * Returns null when the object does not exist.
     */
    async readCapped(key, maxBytes) {
      let res;
      try {
        res = await client.send(new GetObjectCommand({ Bucket, Key: key }));
      } catch (err) {
        if (err?.name === 'NoSuchKey' || err?.$metadata?.httpStatusCode === 404) return null;
        throw err;
      }
      if (res.ContentLength && res.ContentLength > maxBytes) {
        res.Body.destroy?.();
        throw new HttpError(413, 'too_large', 'File is larger than the allowed size');
      }
      const chunks = [];
      let total = 0;
      for await (const chunk of res.Body) {
        total += chunk.length;
        if (total > maxBytes) {
          res.Body.destroy?.();
          throw new HttpError(413, 'too_large', 'File is larger than the allowed size');
        }
        chunks.push(chunk);
      }
      return Buffer.concat(chunks, total);
    },

    put({ key, body, contentType }) {
      return client.send(
        new PutObjectCommand({
          Bucket,
          Key: key,
          Body: body,
          ContentType: contentType,
          CacheControl: 'private, max-age=300',
          // Defence in depth for browsers that might sniff content
          ContentDisposition: 'attachment',
        }),
      );
    },

    /** S3 delete is idempotent: deleting a missing key is not an error. */
    remove(key) {
      return client.send(new DeleteObjectCommand({ Bucket, Key: key }));
    },

    async exists(key) {
      try {
        await client.send(new HeadObjectCommand({ Bucket, Key: key }));
        return true;
      } catch (err) {
        if (err?.$metadata?.httpStatusCode === 404 || err?.name === 'NotFound') return false;
        throw err;
      }
    },

    /** Dev / test helper: create the bucket and allow browser PUTs from the app origin. */
    async ensureBucket(appOrigin) {
      try {
        await client.send(new CreateBucketCommand({ Bucket }));
      } catch (err) {
        if (!['BucketAlreadyOwnedByYou', 'BucketAlreadyExists'].includes(err?.name)) throw err;
      }
      await client.send(
        new PutBucketCorsCommand({
          Bucket,
          CORSConfiguration: {
            CORSRules: [{ AllowedOrigins: [appOrigin], AllowedMethods: ['PUT', 'GET'], AllowedHeaders: ['*'], MaxAgeSeconds: 600 }],
          },
        }),
      );
      try {
        await client.send(
          new PutPublicAccessBlockCommand({
            Bucket,
            PublicAccessBlockConfiguration: {
              BlockPublicAcls: true,
              IgnorePublicAcls: true,
              BlockPublicPolicy: true,
              RestrictPublicBuckets: true,
            },
          }),
        );
      } catch {
        /* not supported by every S3-compatible server */
      }
    },
  };
}

/** Content-Disposition with an ASCII fallback and an RFC 5987 UTF-8 filename. */
export function contentDisposition(filename, inline = false) {
  const type = inline ? 'inline' : 'attachment';
  const ascii = filename.replace(/[^\x20-\x7e]/g, '_').replace(/["\\;]/g, '_');
  return `${type}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename).replace(/['()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())}`;
}
