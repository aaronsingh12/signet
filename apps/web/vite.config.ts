import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The console talks only to the public control API (BP 2 principle 10), proxied in dev so the
// session cookie and the OIDC callback share the console's origin.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    strictPort: true,
    proxy: { '/api': { target: 'http://localhost:4100', changeOrigin: false } },
  },
});
