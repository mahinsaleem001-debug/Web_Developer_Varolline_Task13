import fs from 'node:fs';
import S3rver from 's3rver';

/**
 * In-process S3-compatible server for local development and tests (no Docker needed).
 * NOTE: s3rver does not enforce signed Content-Length / Content-Type or bucket policies.
 * Real S3, MinIO and R2 do, and this app does not rely on that either: it re-validates
 * every uploaded byte on the server.
 */
export async function startLocalS3({ port = 4568, directory = './data/s3', bucket = 'uploads', appOrigin }) {
  fs.mkdirSync(directory, { recursive: true });
  const cors = `<CORSConfiguration><CORSRule>
    <AllowedOrigin>${appOrigin}</AllowedOrigin>
    <AllowedMethod>PUT</AllowedMethod><AllowedMethod>GET</AllowedMethod>
    <AllowedHeader>*</AllowedHeader><MaxAgeSeconds>600</MaxAgeSeconds>
  </CORSRule></CORSConfiguration>`;
  const server = new S3rver({
    port,
    address: '127.0.0.1',
    silent: true,
    directory,
    allowMismatchedSignatures: false,
    configureBuckets: [{ name: bucket, configs: [cors] }],
  });
  await server.run();
  return {
    endpoint: `http://127.0.0.1:${port}`,
    accessKeyId: 'S3RVER',
    secretAccessKey: 'S3RVER',
    close: () => server.close(),
  };
}
