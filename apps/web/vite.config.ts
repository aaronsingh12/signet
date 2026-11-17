import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';
import { defineConfig, loadEnv } from 'vite';

// The console talks only to the public control API (BP 2 principle 10), proxied in dev so the
// session cookie and the OIDC callback share the console's origin.
export default defineConfig(({ mode }) => {
  const envDir = fileURLToPath(new URL('../../', import.meta.url));
  const settings = loadEnv(mode, envDir, 'SIGNET_');
  const port = Number(settings.SIGNET_WEB_PORT ?? '5174');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('SIGNET_WEB_PORT must be an integer between 1 and 65535 in the root .env');
  return {
    envDir,
    plugins: [react()],
    server: {
      host: '127.0.0.1',
      port,
      strictPort: true,
      allowedHosts: settings.SIGNET_PUBLIC_URL ? [new URL(settings.SIGNET_PUBLIC_URL).hostname] : [],
      proxy: {
        '^/api/(chat|tags)(?:/|$)': { target: 'http://localhost:8100', changeOrigin: false },
        '/api': { target: 'http://localhost:4100', changeOrigin: false },
        '/v1': { target: 'http://localhost:8100', changeOrigin: false },
        '/healthz': { target: 'http://localhost:4100', changeOrigin: false },
      },
    },
  };
});
