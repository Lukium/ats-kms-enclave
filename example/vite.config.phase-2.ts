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
    host: true, // Allow external access
    allowedHosts: [
      'localhost',
      'phase2-demo.allthe.services',
    ],
    fs: {
      allow: [path.resolve(__dirname, '..')],
    },
    headers: {
      // CSP for Parent PWA (supports both localhost and CF tunnel)
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self'",
        "frame-src https://kms.ats.run", // Allow KMS iframe from production
        "connect-src 'self' ws://localhost:5173 wss://phase2-demo.allthe.services https://fcm.googleapis.com https://updates.push.services.mozilla.com https://*.notify.windows.com https://*.push.apple.com", // Allow Vite HMR and push services
        "worker-src 'self' blob:", // Allow Vite HMR workers
        "style-src 'self' 'unsafe-inline'", // TODO: Remove unsafe-inline in production
      ].join('; '),
      // Permissions Policy for WebAuthn and other sensitive APIs
      'Permissions-Policy': [
        'publickey-credentials-get=(self "https://kms.ats.run")',
        'publickey-credentials-create=(self "https://kms.ats.run")',
      ].join(', '),
      // Prevent MIME type sniffing
      'X-Content-Type-Options': 'nosniff',
    },
  },
});
