import { loadConfig } from './config.js';
import { openDb } from './db.js';
import { createStorage } from './storage.js';
import { createApp } from './app.js';
import { startLocalS3 } from './local-s3.js';

const config = loadConfig();

// With LOCAL_S3=1 (the default in `npm run dev`) an S3-compatible server is started in-process.
let localS3;
if (process.env.LOCAL_S3 === '1') {
  localS3 = await startLocalS3({ port: Number(process.env.LOCAL_S3_PORT || 4568), appOrigin: config.appOrigin, bucket: config.s3.bucket });
  Object.assign(config.s3, {
    endpoint: localS3.endpoint,
    accessKeyId: localS3.accessKeyId,
    secretAccessKey: localS3.secretAccessKey,
    forcePathStyle: true,
  });
  console.log(`Local S3 at ${localS3.endpoint} (bucket "${config.s3.bucket}")`);
}

if (config.isProd && (!config.cookieSecure || !config.appOrigin.startsWith('https://'))) {
  console.warn('WARNING: production should run behind HTTPS (APP_ORIGIN=https://..., COOKIE_SECURE=true).');
}

const db = openDb(config.dbPath);
const storage = createStorage(config);
if (!config.isProd || process.env.ENSURE_BUCKET === '1') await storage.ensureBucket(config.appOrigin);

const { app, expireStaleUploads } = createApp({ config, db, storage });
const server = app.listen(config.port, () => console.log(`Upload app running at ${config.appOrigin}`));

const timer = setInterval(() => expireStaleUploads().catch((e) => console.error('cleanup failed', e)), 5 * 60 * 1000);
timer.unref();

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    clearInterval(timer);
    server.close();
    await localS3?.close();
    db.close();
    process.exit(0);
  });
}
