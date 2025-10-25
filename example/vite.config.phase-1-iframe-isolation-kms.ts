import { defineConfig } from 'vite';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: path.resolve(__dirname, './phase-1/iframe-isolation'),
  publicDir: false,
  build: {
    outDir: 'dist-kms',
    emptyOutDir: true,
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '../src/v2'),
    },
  },
  worker: {
    format: 'es',
    rollupOptions: {
      output: {
        entryFileNames: 'worker.js',
      },
    },
  },
  server: {
    port: 5177,
    strictPort: true, // Fail if port is already in use
    cors: {
      origin: 'http://localhost:5176', // Allow parent PWA to embed iframe
      credentials: false, // No credentials needed for iframe embedding
    },
    fs: {
      // Allow serving files from repository root (needed for src/ access)
      allow: [path.resolve(__dirname, '..')],
    },
    headers: {
      // CSP for KMS Iframe
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self'",
        "frame-ancestors http://localhost:5176", // Only allow parent to embed
        "connect-src 'self'", // Zero network access except self
        "worker-src 'self'",
        "style-src 'self' 'unsafe-inline'", // TODO: Remove unsafe-inline in production
      ].join('; '),
      // Prevent MIME type sniffing
      'X-Content-Type-Options': 'nosniff',
      // Prevent clickjacking (redundant with frame-ancestors but defense in depth)
      'X-Frame-Options': 'ALLOW-FROM http://localhost:5176',
    },
  },
});
