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
 * Compute SRI (Subresource Integrity) hash for a file
 * Uses SHA-384 as recommended by W3C for SRI
 * @param content File content buffer
 * @returns SRI hash string in format "sha384-..."
 */
function computeSRIHash(content: Buffer): string {
  const hash = createHash('sha384').update(content).digest('base64');
  return `sha384-${hash}`;
}

/**
 * Build the KMS enclave worker bundle
 */
async function buildEnclaveWorker(): Promise<{ outputPath: string; hash: string; filename: string; sri: string }> {
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

  // Generate SHA-256 hash for content addressing
  const content = readFileSync(tempPath);
  const hash = createHash('sha256').update(content).digest('hex');

  // Generate SHA-384 SRI hash
  const sri = computeSRIHash(content);

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
  console.log(`🔒 SRI: ${sri}`);
  console.log(`📝 Filename: ${filename}`);

  // Write metafile for analysis (also content-addressed)
  if (result.metafile) {
    const metafilePath = join(distDir, `enclave/kms-worker.${shortHash}.meta.json`);
    writeFileSync(metafilePath, JSON.stringify(result.metafile, null, 2));
    console.log(`📄 Metafile: ${metafilePath}`);
  }

  return { outputPath, hash, filename, sri };
}

/**
 * Generate the CSS file for the enclave
 * Includes both iframe status styles and modal UI styles
 * @returns SRI hash for the CSS file
 */
function generateEnclaveCSS(): string {
  const css = `/* ============================================
   Base Styles
   ============================================ */

body {
  margin: 0;
  padding: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
  background: #1a1a1a;
  color: #e0e0e0;
}

/* ============================================
   Iframe Status Display
   ============================================ */

.enclave-status {
  max-width: 600px;
  margin: 40px auto;
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

.verification-badge {
  margin: 16px 0;
  text-align: center;
}

.verification-badge a {
  display: inline-block;
  transition: opacity 0.2s;
}

.verification-badge a:hover {
  opacity: 0.8;
}

.verification-badge img {
  max-width: 100%;
  height: auto;
}

/* ============================================
   KMS Modal Styles (for popup windows)
   ============================================ */

.kms-modal {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 9999;
  display: flex;
  align-items: center;
  justify-content: center;
  animation: kms-modal-fade-in 0.2s ease-out;
}

@keyframes kms-modal-fade-in {
  from { opacity: 0; }
  to { opacity: 1; }
}

.kms-modal-backdrop {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.75);
  backdrop-filter: blur(4px);
}

.kms-modal-content {
  position: relative;
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
  border: 1px solid #333;
  border-radius: 12px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
  width: 90%;
  max-width: 450px;
  padding: 0;
  animation: kms-modal-slide-up 0.3s ease-out;
}

@keyframes kms-modal-slide-up {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.kms-modal-header {
  padding: 2rem 2rem 1rem 2rem;
  border-bottom: 1px solid #333;
}

.kms-modal-header h3 {
  margin: 0 0 0.5rem 0;
  font-size: 1.5rem;
  color: #fff;
  font-weight: 600;
}

.kms-modal-subtitle {
  margin: 0;
  font-size: 0.875rem;
  color: #888;
}

.kms-modal-body {
  padding: 2rem;
}

.kms-auth-option {
  margin-bottom: 1.5rem;
}

.kms-auth-option form {
  margin: 0;
  padding: 0;
}

/* Hidden username field for password managers */
.kms-hidden-username {
  display: none !important;
  visibility: hidden;
  position: absolute;
  left: -9999px;
}

.kms-auth-btn {
  width: 100%;
  padding: 1rem;
  border: none;
  border-radius: 8px;
  font-size: 1rem;
  font-weight: 500;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  transition: all 0.2s ease;
  font-family: inherit;
}

.kms-auth-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.kms-auth-btn:active {
  transform: translateY(0);
}

.kms-auth-btn.kms-primary {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: #fff;
}

.kms-auth-btn.kms-primary:hover {
  background: linear-gradient(135deg, #7a8ff0 0%, #8a5bb2 100%);
}

.kms-auth-btn.kms-secondary {
  background: #2d3748;
  color: #fff;
  border: 1px solid #4a5568;
}

.kms-auth-btn.kms-secondary:hover {
  background: #3d4758;
  border-color: #5a6578;
}

.kms-auth-icon {
  font-size: 1.25rem;
}

.kms-auth-label {
  font-size: 1rem;
}

.kms-auth-hint {
  margin: 0.5rem 0 0 0;
  font-size: 0.8rem;
  color: #888;
  text-align: center;
}

.kms-divider {
  display: flex;
  align-items: center;
  text-align: center;
  margin: 1.5rem 0;
  color: #666;
  font-size: 0.875rem;
}

.kms-divider::before,
.kms-divider::after {
  content: '';
  flex: 1;
  border-bottom: 1px solid #333;
}

.kms-divider span {
  padding: 0 1rem;
}

.kms-input-label {
  display: block;
  margin-bottom: 0.5rem;
  font-size: 0.875rem;
  color: #ccc;
  font-weight: 500;
}

.kms-input {
  width: 100%;
  padding: 0.75rem;
  background: #1a1a2e;
  border: 1px solid #333;
  border-radius: 6px;
  color: #fff;
  font-size: 1rem;
  font-family: inherit;
  margin-bottom: 1rem;
  box-sizing: border-box;
}

.kms-input:focus {
  outline: none;
  border-color: #667eea;
  box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.kms-input::placeholder {
  color: #666;
}

.kms-modal-error {
  padding: 1rem;
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: 6px;
  color: #f87171;
  font-size: 0.875rem;
  margin-top: 1rem;
}

.kms-modal-loading {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  padding: 1rem;
  background: rgba(102, 126, 234, 0.1);
  border: 1px solid rgba(102, 126, 234, 0.3);
  border-radius: 6px;
  color: #a5b4fc;
  font-size: 0.875rem;
  margin-top: 1rem;
}

.kms-spinner {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(165, 180, 252, 0.3);
  border-top-color: #a5b4fc;
  border-radius: 50%;
  animation: kms-spin 0.8s linear infinite;
}

@keyframes kms-spin {
  to { transform: rotate(360deg); }
}

/* Helper classes to avoid inline styles (CSP compliance) */
.hidden {
  display: none !important;
}

.kms-char-count {
  margin: -0.5rem 0 0.5rem 0;
  font-size: 0.75rem;
  color: #666;
}

.kms-match-feedback {
  margin: -0.5rem 0 0.5rem 0;
  font-size: 0.75rem;
}

/* Color state classes for dynamic feedback */
.success {
  color: #48d391 !important;
}

.error {
  color: #ef4444 !important;
}

/* Multi-enrollment unlock instructions (dynamically created) */
.multi-enrollment-instructions {
  margin-bottom: 1.5rem;
  padding: 1rem;
  background: rgba(102, 126, 234, 0.1);
  border: 1px solid rgba(102, 126, 234, 0.3);
  border-radius: 6px;
}

.multi-enrollment-title {
  margin: 0 0 0.5rem 0;
  color: #a5b4fc;
  font-size: 0.875rem;
  font-weight: 600;
}

.multi-enrollment-description {
  margin: 0;
  color: #888;
  font-size: 0.8rem;
}

.kms-setup-success {
  padding: 1rem;
  background: rgba(72, 187, 120, 0.1);
  border: 1px solid rgba(72, 187, 120, 0.3);
  border-radius: 6px;
  color: #68d391;
  font-size: 0.875rem;
  margin-top: 1rem;
}

.kms-success-content {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.kms-success-icon {
  font-size: 1.5rem;
}

.kms-success-title {
  font-weight: 600;
  margin-bottom: 0.25rem;
}

.kms-success-message {
  opacity: 0.9;
}
`;

  const cssPath = join(distDir, 'enclave/enclave.css');
  writeFileSync(cssPath, css, 'utf-8');

  // Compute SRI hash
  const cssBuffer = Buffer.from(css, 'utf-8');
  const sri = computeSRIHash(cssBuffer);

  console.log(`✅ Generated: ${cssPath}`);
  console.log(`🔒 SRI: ${sri}`);

  return sri;
}

/**
 * Build the client script for the enclave
 * Compiles src/v2/client.ts and injects the hashed worker filename
 * @returns SRI hash for the client script
 */
async function buildEnclaveClient(workerFilename: string): Promise<string> {
  console.log('\n📦 Building KMS Enclave Client...');

  const clientPath = join(distDir, 'enclave/enclave-client.js');

  await esbuild.build({
    entryPoints: [join(srcDir, 'v2/client.ts')],
    bundle: true,
    outfile: clientPath,
    format: 'esm',
    target: 'es2022',
    platform: 'browser',
    minify: true,
    sourcemap: false,
    treeShaking: true,

    // Inject the hashed worker filename at build time
    define: {
      '__WORKER_FILENAME__': JSON.stringify(`./${workerFilename}`),
    },

    // Determinism settings
    logLevel: 'warning',
    legalComments: 'none',
    charset: 'utf8',

    // External dependencies (none - we bundle everything)
    external: [],
  });

  // Compute SRI hash
  const clientContent = readFileSync(clientPath);
  const sri = computeSRIHash(clientContent);

  console.log(`✅ Built: ${clientPath}`);
  console.log(`🔒 SRI: ${sri}`);

  return sri;
}

/**
 * Generate the HTML wrapper for the enclave
 * Includes both iframe status display and modal UI for popup windows
 */
function generateEnclaveHTML(workerHash: string, cssSRI: string, clientSRI: string): void {
  console.log('\n📝 Generating KMS Enclave HTML...');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AllTheServices KMS Enclave</title>
  <meta name="description" content="AllTheServices Key Management System Enclave">
  <link rel="icon" type="image/png" href="favicon.png">
  <link rel="stylesheet" href="enclave.css" integrity="${cssSRI}" crossorigin="anonymous">
</head>
<body>
  <!-- Iframe Status Display (shown when embedded in iframe) -->
  <div class="enclave-status">
    <div class="header">
      <img src="logo.png" alt="AllTheServices" class="logo">
      <h1>AllTheServices KMS Enclave</h1>
    </div>
    <div class="verification-badge">
      <a href="https://github.com/Lukium/ats-kms-enclave/tree/attestation" target="_blank" rel="noopener noreferrer">
        <img src="https://raw.githubusercontent.com/Lukium/ats-kms-enclave/attestation/verification-badge.svg" alt="KMS Verification Status" />
      </a>
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

  <!-- Unlock Modal (shown in popup window for unlock) -->
  <div id="unlock-modal" class="kms-modal hidden">
    <div class="kms-modal-backdrop"></div>
    <div class="kms-modal-content">
      <div class="kms-modal-header">
        <h3>🔐 Unlock KMS</h3>
        <p class="kms-modal-subtitle">Choose your unlock method</p>
      </div>

      <div class="kms-modal-body">
        <!-- WebAuthn Option -->
        <div class="kms-auth-option">
          <button id="kms-webauthn-btn" class="kms-auth-btn kms-primary">
            <span class="kms-auth-icon">🔑</span>
            <span class="kms-auth-label">Use Passkey</span>
          </button>
          <p class="kms-auth-hint">Authenticate with your device biometrics</p>
        </div>

        <!-- Divider -->
        <div class="kms-divider">
          <span>or</span>
        </div>

        <!-- Passphrase Option -->
        <div class="kms-auth-option">
          <form id="kms-unlock-form">
            <input type="text" name="username" autocomplete="username" class="kms-hidden-username" value="kms-user" readonly />
            <label for="kms-passphrase-input" class="kms-input-label">Passphrase</label>
            <input
              type="password"
              id="kms-passphrase-input"
              name="password"
              class="kms-input"
              placeholder="Enter your passphrase"
              autocomplete="current-password"
            />
            <button id="kms-passphrase-btn" type="button" class="kms-auth-btn kms-secondary">
              <span class="kms-auth-icon">🔐</span>
              <span class="kms-auth-label">Unlock with Passphrase</span>
            </button>
          </form>
        </div>

        <!-- Error Display -->
        <div id="kms-modal-error" class="kms-modal-error hidden"></div>

        <!-- Loading State -->
        <div id="kms-modal-loading" class="kms-modal-loading hidden">
          <span class="kms-spinner"></span>
          <span>Unlocking...</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Setup Modal (shown in popup window for setup) -->
  <div id="setup-modal" class="kms-modal hidden">
    <div class="kms-modal-backdrop"></div>
    <div class="kms-modal-content">
      <div class="kms-modal-header">
        <h3>🔐 Setup KMS Authentication</h3>
        <p class="kms-modal-subtitle">Choose your authentication method</p>
      </div>

      <div class="kms-modal-body">
        <!-- WebAuthn Setup Option -->
        <div class="kms-auth-option">
          <button id="kms-setup-webauthn-btn" class="kms-auth-btn kms-primary">
            <span class="kms-auth-icon">🔑</span>
            <span class="kms-auth-label">Setup Passkey</span>
          </button>
          <p class="kms-auth-hint">Register your device biometrics</p>
        </div>

        <!-- Divider -->
        <div class="kms-divider">
          <span>or</span>
        </div>

        <!-- Passphrase Setup Option -->
        <div class="kms-auth-option">
          <form id="kms-setup-form">
            <input type="text" name="username" autocomplete="username" class="kms-hidden-username" value="kms-user" readonly />
            <label for="kms-setup-passphrase-input" class="kms-input-label">Create Passphrase</label>
            <input
              type="password"
              id="kms-setup-passphrase-input"
              name="new-password"
              class="kms-input"
              placeholder="Enter a strong passphrase (min 12 chars)"
              autocomplete="new-password"
            />
            <div id="kms-passphrase-char-count" class="kms-char-count">
              0 / 12 characters
            </div>
            <label for="kms-setup-passphrase-confirm-input" class="kms-input-label">Confirm Passphrase</label>
            <input
              type="password"
              id="kms-setup-passphrase-confirm-input"
              name="new-password"
              class="kms-input"
              placeholder="Re-enter your passphrase"
              autocomplete="new-password"
            />
            <div id="kms-passphrase-match-feedback" class="kms-match-feedback hidden">
              <!-- Feedback will be inserted here dynamically -->
            </div>
            <button id="kms-setup-passphrase-btn" type="button" class="kms-auth-btn kms-secondary">
              <span class="kms-auth-icon">🔐</span>
              <span class="kms-auth-label">Setup with Passphrase</span>
            </button>
          </form>
        </div>

        <!-- Error Display -->
        <div id="kms-setup-error" class="kms-modal-error hidden"></div>

        <!-- Loading State -->
        <div id="kms-setup-loading" class="kms-modal-loading hidden">
          <span class="kms-spinner"></span>
          <span>Setting up...</span>
        </div>

        <!-- Success State -->
        <div id="kms-setup-success" class="kms-setup-success hidden">
          <div class="kms-success-content">
            <span class="kms-success-icon">✅</span>
            <div>
              <div class="kms-success-title">Setup Complete!</div>
              <div class="kms-success-message">You can now close this window and return to the main app.</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script type="module" src="enclave-client.js" integrity="${clientSRI}" crossorigin="anonymous"></script>
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
    const { hash, filename, sri: workerSRI } = await buildEnclaveWorker();

    // Generate CSS, client script, and HTML
    const cssSRI = generateEnclaveCSS();
    const clientSRI = await buildEnclaveClient(filename);
    generateEnclaveHTML(hash, cssSRI, clientSRI);

    // Copy static assets (logo, favicon) to dist/enclave/
    const staticAssetsDir = join(rootDir, 'placeholders/cf-pages');
    const logoSrc = join(staticAssetsDir, 'logo.png');
    const faviconSrc = join(staticAssetsDir, 'favicon.png');
    const logoDest = join(distDir, 'enclave/logo.png');
    const faviconDest = join(distDir, 'enclave/favicon.png');

    writeFileSync(logoDest, readFileSync(logoSrc));
    writeFileSync(faviconDest, readFileSync(faviconSrc));
    console.log(`✅ Copied static assets: logo.png, favicon.png`);

    // Write build manifest with SRI hashes
    const manifest = {
      version: '2.0.0',
      buildTime: SOURCE_DATE_EPOCH,
      files: {
        worker: {
          path: `enclave/${filename}`,
          filename: filename,
          hash: hash,
          algorithm: 'sha256',
          sri: workerSRI
        },
        client: {
          path: 'enclave/enclave-client.js',
          sri: clientSRI
        },
        css: {
          path: 'enclave/enclave.css',
          sri: cssSRI
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

    // Clean up old worker files (security: only keep current version)
    console.log(`\n🧹 Cleaning up old worker files...`);
    const fs = await import('fs');
    const existingWorkers = fs.readdirSync(cfPagesDir)
      .filter(f => f.startsWith('kms-worker.') && f.endsWith('.js') && f !== filename);

    for (const oldWorker of existingWorkers) {
      const oldPath = join(cfPagesDir, oldWorker);
      fs.unlinkSync(oldPath);
      console.log(`  🗑️  Removed: ${oldWorker}`);
    }

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

    // Copy logo and favicon
    const cfLogoPath = join(cfPagesDir, 'logo.png');
    writeFileSync(cfLogoPath, readFileSync(join(distDir, 'enclave/logo.png')));
    console.log(`  ✅ ${cfLogoPath}`);

    const cfFaviconPath = join(cfPagesDir, 'favicon.png');
    writeFileSync(cfFaviconPath, readFileSync(join(distDir, 'enclave/favicon.png')));
    console.log(`  ✅ ${cfFaviconPath}`);

    // Update the .well-known/kms-manifest.json with real data
    const cfManifestPath = join(cfPagesDir, '.well-known/kms-manifest.json');
    const cfManifest = {
      schema: 1,
      current: {
        version: '2.0.0',
        artifact: filename,
        sha256: hash,
        files: {
          worker: {
            filename: filename,
            sha256: hash,
            sri: workerSRI
          },
          client: {
            filename: 'enclave-client.js',
            sri: clientSRI
          },
          css: {
            filename: 'enclave.css',
            sri: cssSRI
          }
        },
        timestamp: new Date().toISOString(),
        build: {
          reproducible: true,
          environment: 'production',
          SOURCE_DATE_EPOCH: SOURCE_DATE_EPOCH
        }
      },
      allowed: [hash], // Current version is allowed
      deprecated: [],
      comment: `Phase 2.1: Deterministic builds with SRI (Subresource Integrity)`
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
