#!/usr/bin/env node
/**
 * Build script for ATS KMS Enclave
 *
 * Phase 1: Single-file module build
 * Phase 2: Deterministic builds with content-addressed filenames
 */

import * as esbuild from 'esbuild';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const args = process.argv.slice(2);
const isDev = args.includes('--dev');
const isReproducible = args.includes('--reproducible');

console.log('📦 Building ATS KMS Enclave...');
console.log(`   Mode: ${isDev ? 'development' : isReproducible ? 'reproducible' : 'production'}`);

// Create dist directory
const distDir = path.join(__dirname, '../dist');
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

// Build configuration (V2 only)
const buildConfig = {
  entryPoints: [path.join(__dirname, '../src/v2/worker.ts')],
  bundle: true,
  outfile: path.join(distDir, 'worker.js'),
  format: 'esm',
  target: 'es2020',
  minify: !isDev,
  sourcemap: isDev,
  platform: 'browser',
  treeShaking: true,
  legalComments: 'none',
  charset: 'utf8',
  logLevel: 'info',
};

// Phase 2 will add:
// - SOURCE_DATE_EPOCH for deterministic timestamps
// - Content-addressed filenames (worker-[hash].js)
// - SRI hash generation
// - Manifest generation

async function build() {
  try {
    console.log('');
    console.log('🔨 Bundling worker...');

    const result = await esbuild.build(buildConfig);

    // Get output file size
    const stats = fs.statSync(path.join(distDir, 'worker.js'));
    const sizeKB = (stats.size / 1024).toFixed(2);

    console.log('');
    console.log('✅ Build complete');
    console.log(`   Output: dist/worker.js (${sizeKB} KB)`);
    console.log('');

    if (isReproducible) {
      console.log('⚠️  Note: Reproducible builds coming in Phase 2');
      console.log('   (deterministic timestamps, content-addressed filenames, SRI hashes)');
      console.log('');
    }

    process.exit(0);
  } catch (error) {
    console.error('❌ Build failed:', error);
    process.exit(1);
  }
}

build();
