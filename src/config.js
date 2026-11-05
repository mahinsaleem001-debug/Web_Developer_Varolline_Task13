import 'dotenv/config';

const MB = 1024 * 1024;
const int = (v, d) => {
  const n = Number.parseInt(v ?? '', 10);
  return Number.isFinite(n) ? n : d;
};
const bool = (v, d) => (v === undefined || v === '' ? d : ['1', 'true', 'yes'].includes(String(v).toLowerCase()));

function merge(base, extra) {
  const out = { ...base };
  for (const [k, v] of Object.entries(extra || {})) {
    out[k] = v && typeof v === 'object' && !Array.isArray(v) ? merge(base[k] || {}, v) : v;
  }
  return out;
}

/** Read configuration from the environment. `overrides` is used by tests. */
export function loadConfig(overrides = {}) {
  const env = process.env;
  const isProd = env.NODE_ENV === 'production';
  const port = int(env.PORT, 3000);

  const config = {
    isProd,
    port,
    appOrigin: env.APP_ORIGIN || `http://localhost:${port}`,
    dbPath: env.DB_PATH || './data/app.db',
    trustProxy: bool(env.TRUST_PROXY, false),
    cookieSecure: bool(env.COOKIE_SECURE, isProd),
    sessionTtlMs: int(env.SESSION_TTL_HOURS, 24 * 7) * 3600 * 1000,
    s3: {
      endpoint: env.S3_ENDPOINT || undefined, // leave empty for AWS S3
      region: env.S3_REGION || 'us-east-1',
      bucket: env.S3_BUCKET || 'uploads',
      accessKeyId: env.S3_ACCESS_KEY_ID || '',
      secretAccessKey: env.S3_SECRET_ACCESS_KEY || '',
      forcePathStyle: bool(env.S3_FORCE_PATH_STYLE, Boolean(env.S3_ENDPOINT)),
    },
    limits: {
      maxFileBytes: int(env.MAX_FILE_MB, 10) * MB,
      maxPixels: int(env.MAX_IMAGE_PIXELS, 30_000_000),
      maxDimension: int(env.MAX_IMAGE_DIMENSION, 12_000),
      maxFrames: 100,
      maxFilesPerUser: int(env.MAX_FILES_PER_USER, 200),
      maxBytesPerUser: int(env.MAX_USER_MB, 500) * MB,
      maxPendingPerUser: 20,
    },
    ttl: {
      putSeconds: 300, // signed upload URL lifetime
      getSeconds: 120, // signed download URL lifetime (documents)
      thumbSeconds: 900, // signed thumbnail URL lifetime (gallery stays open a while)
      pendingUploadMs: 15 * 60 * 1000, // quarantine objects older than this are purged
    },
    thumbnailSize: 320,
    rateLimit: {
      auth: { windowMs: 15 * 60 * 1000, limit: 20 },
      uploads: { windowMs: 10 * 60 * 1000, limit: 120 },
    },
  };
  return merge(config, overrides);
}
