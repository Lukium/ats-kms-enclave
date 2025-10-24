import { defineConfig } from 'vite';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: path.resolve(__dirname, './phase-1/iframe-isolation'),
  publicDir: false,
  build: {
    outDir: 'dist-parent',
    emptyOutDir: true,
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '../src'),
    },
  },
  server: {
    port: 5176,
    strictPort: true, // Fail if port is already in use
    fs: {
      // Allow serving files from repository root (needed for src/ access)
      allow: [path.resolve(__dirname, '..')],
    },
    headers: {
      // CSP for Parent PWA
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self'",
        "frame-src http://localhost:5177", // Allow KMS iframe
        "connect-src 'self'",
        "style-src 'self' 'unsafe-inline'", // TODO: Remove unsafe-inline in production
      ].join('; '),
    },
  },
});
