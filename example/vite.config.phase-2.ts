import { defineConfig } from 'vite';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [
    {
      name: 'full-reload',
      handleHotUpdate({ server }) {
        // Force full reload instead of HMR to prevent duplicate worker instances
        server.ws.send({ type: 'full-reload' });
        return [];
      },
    },
  ],
  root: path.resolve(__dirname, './phase-2'),
  publicDir: false,
  build: {
    outDir: 'dist-parent',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    strictPort: true,
    fs: {
      allow: [path.resolve(__dirname, '..')],
    },
    headers: {
      // CSP for Parent PWA (matches integration tests structure)
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self'",
        "frame-src https://kms.ats.run", // Allow KMS iframe from production
        "connect-src 'self' ws://localhost:5173", // Allow Vite HMR
        "worker-src 'self' blob:", // Allow Vite HMR workers
        "style-src 'self' 'unsafe-inline'", // TODO: Remove unsafe-inline in production
      ].join('; '),

      // Cross-Origin Policies - Must match KMS popup for compatible browsing context
      // This allows popup messaging while maintaining SharedArrayBuffer isolation
      'Cross-Origin-Opener-Policy': 'same-origin-allow-popups',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
});
