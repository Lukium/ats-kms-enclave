#!/usr/bin/env ts-node
/**
 * Build script for KMS Enclave (Phase 2.1: Deterministic Builds)
 *
 * Produces a single bundled JavaScript file containing the entire enclave:
 * - worker.ts (entry point - runs in dedicated Worker)
 * - client.ts (iframe-side bridge that loads the worker)
 * - All infrastructure: unlock.ts, audit.ts, storage.ts, storage-types.ts,
 *   crypto-utils.ts, error-utils.ts, rpc-validation.ts, webauthn-types.ts, types.ts
 *
 * NOTE: kms-user.ts is NOT included - it lives in the parent PWA and communicates
 * with the enclave iframe via postMessage.
 *
 * Configuration ensures deterministic output:
 * - Fixed SOURCE_DATE_EPOCH for timestamps
 * - Sorted file inputs
 * - No legal comments or sourcemaps
 * - Minified but reproducible
 */

import * as esbuild from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { createHash } from 'crypto';
import { fileURLToPath } from 'url';

// ESM equivalents for __filename and __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Determinism: Use fixed timestamp for all builds
const SOURCE_DATE_EPOCH = process.env.SOURCE_DATE_EPOCH || '1609459200'; // 2021-01-01 00:00:00 UTC

const rootDir = join(__dirname, '..');
const srcDir = join(rootDir, 'src');
const distDir = join(rootDir, 'dist');

/**
 * Build the KMS enclave worker bundle
 */
async function buildEnclaveWorker(): Promise<{ outputPath: string; hash: string; filename: string }> {
  console.log('📦 Building KMS Enclave Worker...');

  // Ensure dist directory exists
  mkdirSync(join(distDir, 'enclave'), { recursive: true });

  // First build to temporary location to get hash
  const tempPath = join(distDir, 'enclave/kms-worker.temp.js');

  const result = await esbuild.build({
    entryPoints: [join(srcDir, 'v2/worker.ts')],
    bundle: true,
    outfile: tempPath,
    format: 'esm',
    target: 'es2022',
    platform: 'browser',
    minify: true,
    sourcemap: false,
    treeShaking: true,

    // Determinism settings
    logLevel: 'warning',
    logOverride: {
      'unsupported-feature': 'silent',
    },
    legalComments: 'none',  // No comment headers with timestamps
    charset: 'utf8',

    // Inject fixed build time for determinism
    define: {
      'process.env.BUILD_TIME': JSON.stringify(SOURCE_DATE_EPOCH),
      'process.env.KMS_VERSION': JSON.stringify('2.0.0'),
    },

    // External dependencies (none - we bundle everything)
    external: [],

    // Metadata for verification
    metafile: true,
  });

  // Generate SHA-256 hash
  const content = readFileSync(tempPath);
  const hash = createHash('sha256').update(content).digest('hex');

  // Use first 8 chars of hash for filename (like git)
  const shortHash = hash.substring(0, 8);
  const filename = `kms-worker.${shortHash}.js`;
  const outputPath = join(distDir, 'enclave', filename);

  // Rename to content-addressed filename
  writeFileSync(outputPath, content);

  // Remove temp file
  const fs = await import('fs');
  fs.unlinkSync(tempPath);

  console.log(`✅ Built: ${outputPath}`);
  console.log(`📊 Size: ${(content.length / 1024).toFixed(2)} KB`);
  console.log(`🔒 SHA-256: ${hash}`);
  console.log(`📝 Filename: ${filename}`);

  // Write metafile for analysis (also content-addressed)
  if (result.metafile) {
    const metafilePath = join(distDir, `enclave/kms-worker.${shortHash}.meta.json`);
    writeFileSync(metafilePath, JSON.stringify(result.metafile, null, 2));
    console.log(`📄 Metafile: ${metafilePath}`);
  }

  return { outputPath, hash, filename };
}

/**
 * Generate the CSS file for the enclave
 */
function generateEnclaveCSS(): void {
  const css = `body {
  margin: 0;
  padding: 20px;
  font-family: system-ui, -apple-system, sans-serif;
  background: #1a1a1a;
  color: #e0e0e0;
}

.enclave-status {
  max-width: 600px;
  margin: 0 auto;
  padding: 30px;
  background: #2a2a2a;
  border-radius: 8px;
  border: 1px solid #3a3a3a;
}

.header {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 20px;
  padding-bottom: 20px;
  border-bottom: 1px solid #3a3a3a;
}

.logo {
  width: 48px;
  height: 48px;
  max-width: 48px;
  max-height: 48px;
  object-fit: contain;
}

h1 {
  margin: 0;
  font-size: 24px;
  color: #4CAF50;
  font-weight: 600;
}

.hash {
  font-family: 'Monaco', 'Menlo', monospace;
  font-size: 12px;
  background: #1a1a1a;
  padding: 10px;
  border-radius: 4px;
  word-break: break-all;
  color: #888;
  margin: 10px 0;
}

.status {
  color: #4CAF50;
  font-weight: 600;
}

.description {
  font-size: 14px;
  color: #888;
  margin-top: 20px;
}
`;

  const cssPath = join(distDir, 'enclave/enclave.css');
  writeFileSync(cssPath, css, 'utf-8');
  console.log(`✅ Generated: ${cssPath}`);
}

/**
 * Generate the client bootstrap script for the enclave
 */
function generateEnclaveClient(workerFilename: string): void {
  const client = `// Bootstrap: Load the KMS worker and establish parent communication
const worker = new Worker('./${workerFilename}', {
  type: 'module',
  name: 'kms-enclave-worker'
});

// Track worker readiness
let workerReady = false;

// Forward messages from parent to worker
window.addEventListener('message', (event) => {
  // TODO: Add origin validation in production
  // if (event.origin !== 'https://ats.run') return;

  if (!workerReady) {
    console.warn('[KMS Enclave] Worker not ready, queueing message');
    // Could implement message queue here if needed
    return;
  }

  console.log('[KMS Enclave] → Worker:', event.data.method || event.data.type);
  worker.postMessage(event.data);
});

// Forward messages from worker to parent
worker.addEventListener('message', (event) => {
  console.log('[KMS Enclave] ← Worker:', event.data);
  window.parent.postMessage(event.data, '*'); // TODO: Specify target origin in production
});

// Handle worker errors
worker.addEventListener('error', (event) => {
  console.error('[KMS Enclave] Worker error:', event);
  window.parent.postMessage({
    type: 'error',
    error: 'Worker crashed: ' + event.message
  }, '*');
});

// Mark worker as ready
worker.addEventListener('message', function readyHandler(event) {
  if (event.data.type === 'ready') {
    workerReady = true;
    worker.removeEventListener('message', readyHandler);
    console.log('[KMS Enclave] Worker ready');
  }
}, { once: false });

// Signal to parent that iframe is loaded
window.parent.postMessage({ type: 'iframe-ready' }, '*');
`;

  const clientPath = join(distDir, 'enclave/enclave-client.js');
  writeFileSync(clientPath, client, 'utf-8');
  console.log(`✅ Generated: ${clientPath}`);
}

/**
 * Generate the HTML wrapper for the enclave
 */
function generateEnclaveHTML(workerHash: string): void {
  console.log('\n📝 Generating KMS Enclave HTML...');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AllTheServices KMS Enclave</title>
  <meta name="description" content="AllTheServices Key Management System Enclave">
  <link rel="icon" type="image/png" href="favicon.png">
  <link rel="stylesheet" href="enclave.css">
</head>
<body>
  <div class="enclave-status">
    <div class="header">
      <img src="logo.png" alt="AllTheServices" class="logo">
      <h1>AllTheServices KMS Enclave</h1>
    </div>
    <p><span class="status">Active</span> - Worker loaded and ready</p>
    <div>
      <strong>Worker Hash:</strong>
      <div class="hash">${workerHash}</div>
    </div>
    <p class="description">
      This iframe runs in a sandboxed cross-origin context.
      All cryptographic operations are isolated from the parent PWA.
    </p>
  </div>
  <script type="module" src="enclave-client.js"></script>
</body>
</html>`;

  const htmlPath = join(distDir, 'enclave/index.html');
  writeFileSync(htmlPath, html, 'utf-8');

  console.log(`✅ Generated: ${htmlPath}`);
}

/**
 * Main build process
 */
async function main() {
  console.log('🚀 KMS Enclave Build - Phase 2.1: Deterministic Builds\n');
  console.log(`SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH}\n`);

  try {
    // Build the worker bundle
    const { hash, filename } = await buildEnclaveWorker();

    // Generate CSS, client script, and HTML
    generateEnclaveCSS();
    generateEnclaveClient(filename);
    generateEnclaveHTML(hash);

    // Write build manifest
    const manifest = {
      version: '2.0.0',
      buildTime: SOURCE_DATE_EPOCH,
      files: {
        worker: {
          path: `enclave/${filename}`,
          filename: filename,
          hash: hash,
          algorithm: 'sha256'
        },
        html: {
          path: 'enclave/index.html'
        }
      }
    };

    const manifestPath = join(distDir, 'enclave/manifest.json');
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
    console.log(`\n📋 Build manifest: ${manifestPath}`);

    console.log('\n✅ Enclave build complete!');
    console.log(`\nOutputs:`);
    console.log(`  - ${join(distDir, `enclave/${filename}`)}`);
    console.log(`  - ${join(distDir, 'enclave/index.html')}`);
    console.log(`  - ${join(distDir, 'enclave/manifest.json')}`);

    // Copy to Cloudflare Pages directory for deployment
    const cfPagesDir = join(rootDir, 'placeholders/cf-pages');
    console.log(`\n📤 Copying to Cloudflare Pages directory...`);

    // Copy the worker JS file
    const cfWorkerPath = join(cfPagesDir, filename);
    writeFileSync(cfWorkerPath, readFileSync(join(distDir, `enclave/${filename}`)));
    console.log(`  ✅ ${cfWorkerPath}`);

    // Copy CSS file
    const cfCssPath = join(cfPagesDir, 'enclave.css');
    writeFileSync(cfCssPath, readFileSync(join(distDir, 'enclave/enclave.css')));
    console.log(`  ✅ ${cfCssPath}`);

    // Copy client JS file
    const cfClientPath = join(cfPagesDir, 'enclave-client.js');
    writeFileSync(cfClientPath, readFileSync(join(distDir, 'enclave/enclave-client.js')));
    console.log(`  ✅ ${cfClientPath}`);

    // Copy index.html
    const cfHtmlPath = join(cfPagesDir, 'index.html');
    writeFileSync(cfHtmlPath, readFileSync(join(distDir, 'enclave/index.html')));
    console.log(`  ✅ ${cfHtmlPath}`);

    // Update the .well-known/kms-manifest.json with real data
    const cfManifestPath = join(cfPagesDir, '.well-known/kms-manifest.json');
    const cfManifest = {
      schema: 1,
      current: {
        version: '2.0.0',
        artifact: filename,
        sha256: hash,
        sri: `sha256-${Buffer.from(hash, 'hex').toString('base64')}`,
        timestamp: new Date().toISOString(),
        build: {
          reproducible: true,
          environment: 'production',
          SOURCE_DATE_EPOCH: SOURCE_DATE_EPOCH
        }
      },
      allowed: [hash], // Current version is allowed
      deprecated: [],
      comment: `Phase 2: Deterministic builds with content-addressed artifacts`
    };
    writeFileSync(cfManifestPath, JSON.stringify(cfManifest, null, 2));
    console.log(`  ✅ ${cfManifestPath}`);

    console.log(`\n🚀 Ready for deployment to kms.ats.run!`);

  } catch (error) {
    console.error('❌ Build failed:', error);
    process.exit(1);
  }
}

// Run if called directly (ESM check)
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { buildEnclaveWorker, generateEnclaveHTML };
