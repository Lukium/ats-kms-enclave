#!/usr/bin/env node
/**
 * Build script for ATS KMS Enclave
 *
 * Phase 0: Minimal placeholder build
 * Future phases will implement deterministic builds with content-addressed filenames
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const args = process.argv.slice(2);
const isDev = args.includes('--dev');
const isReproducible = args.includes('--reproducible');

console.log('📦 Building ATS KMS Enclave...');
console.log(`   Mode: ${isDev ? 'development' : isReproducible ? 'reproducible' : 'unknown'}`);

// Create dist directory
const distDir = path.join(__dirname, '../dist');
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

// Phase 0: Just create a placeholder file
const placeholder = `/**
 * ATS KMS Enclave - Phase 0 Build Artifact
 *
 * This is a placeholder for Phase 0.
 * Real builds will be implemented in Phase 2 (Verifiable Builds).
 *
 * Build mode: ${isDev ? 'development' : isReproducible ? 'reproducible' : 'unknown'}
 * Build time: ${new Date().toISOString()}
 */

console.log('ATS KMS Enclave - Phase 0');
console.log('Real build artifacts coming in Phase 2');
`;

fs.writeFileSync(path.join(distDir, 'kms.js'), placeholder);

console.log('✅ Build complete');
console.log(`   Output: dist/kms.js`);
console.log('');
console.log('⚠️  Note: Phase 0 uses in-browser development via Vite');
console.log('   Real builds with deterministic artifacts coming in Phase 2');

process.exit(0);
