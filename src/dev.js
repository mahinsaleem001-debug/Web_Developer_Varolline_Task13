// Cross-platform dev entry point (works in PowerShell, cmd, bash): starts the app with a local S3 server.
process.env.LOCAL_S3 = '1';
await import('./server.js');
