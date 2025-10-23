import { defineConfig } from 'vite';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: path.resolve(__dirname, './phase-0'),
  publicDir: false,
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '../src'),
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
    fs: {
      // Allow serving files from repository root (needed for src/ access)
      allow: [path.resolve(__dirname, '..')],
    },
  },
});
