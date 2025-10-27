import { defineConfig } from 'vite';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: path.resolve(__dirname, './phase-1/full'),
  publicDir: false,
  build: {
    outDir: 'dist-full-kms',
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
    port: 5174,
    strictPort: true,
    cors: {
      origin: 'http://localhost:5173',
      credentials: false,
    },
    fs: {
      allow: [path.resolve(__dirname, '..')],
    },
    headers: {
      // CSP for KMS Iframe (matches integration tests structure)
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self'",
        "frame-ancestors http://localhost:5173", // Only allow parent on 5173
        "connect-src 'self'", // Zero network access except self
        "worker-src 'self'",
        "style-src 'self' 'unsafe-inline'", // TODO: Remove unsafe-inline in production
      ].join('; '),
      // Prevent MIME type sniffing
      'X-Content-Type-Options': 'nosniff',
      // Prevent clickjacking (redundant with frame-ancestors but defense in depth)
      'X-Frame-Options': 'ALLOW-FROM http://localhost:5173',
    },
  },
});
