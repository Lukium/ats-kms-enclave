import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  root: './example',
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
      // Allow serving files from parent directory (src/)
      allow: ['..'],
    },
  },
});
