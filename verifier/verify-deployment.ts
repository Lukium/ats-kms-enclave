#!/usr/bin/env tsx
/**
 * KMS Enclave Deployment Verification Script
 *
 * Performs comprehensive verification of the deployed KMS enclave:
 * 1. Fetch manifest from kms.ats.run
 * 2. Verify deployed worker hash matches manifest
 * 3. Verify SRI hashes for all resources
 * 4. Verify security headers (CSP, CORP, etc.)
 * 5. [Future] Verify Rekor transparency log entry
 *
 * Part of Phase 2.1: Verifiable Builds
 */

import { createHash } from 'crypto';
import { execSync } from 'child_process';
import { readFileSync, writeFileSync } from 'fs';
import { verifyHeaders } from './verify-headers.js';

interface KMSManifest {
  schema: number;
  current: {
    version: string;
    commit: string;
    artifact: string;
    sha256: string;
    files: {
      worker: {
        filename: string;
        sha256: string;
        sri: string;
      };
      client: {
        filename: string;
        sri: string;
      };
      css: {
        filename: string;
        sri: string;
      };
    };
    timestamp: string;
    build: {
      reproducible: boolean;
      environment: string;
      SOURCE_DATE_EPOCH: string;
    };
    attestation?: {
      rekorUrl: string;
      attestationUrl: string;
    };
  };
  allowed: string[];
  deprecated: string[];
  comment: string;
}

export interface VerificationCheck {
  name: string;
  passed: boolean;
  message: string;
  details?: any;
}

export interface VerificationResult {
  url: string;
  timestamp: string;
  checks: VerificationCheck[];
  allPassed: boolean;
  manifest?: KMSManifest;
  workerHash?: string;
}

/**
 * Retry a function with exponential backoff
 */
async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  initialDelayMs: number = 2000,
  description: string = 'operation'
): Promise<T> {
  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      if (attempt < maxRetries) {
        const delayMs = initialDelayMs * Math.pow(2, attempt - 1);
        console.log(`⚠️  ${description} failed (attempt ${attempt}/${maxRetries}): ${lastError.message}`);
        console.log(`   Retrying in ${delayMs}ms...`);
        await new Promise(resolve => setTimeout(resolve, delayMs));
      }
    }
  }

  throw new Error(`${description} failed after ${maxRetries} attempts: ${lastError?.message}`);
}

/**
 * Fetch and parse the KMS manifest
 */
async function fetchManifest(baseUrl: string): Promise<KMSManifest> {
  const manifestUrl = `${baseUrl}/.well-known/kms-manifest.json`;
  console.log(`📥 Fetching manifest: ${manifestUrl}`);

  return retryWithBackoff(async () => {
    const response = await fetch(manifestUrl);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const contentType = response.headers.get('content-type');
    if (contentType && !contentType.includes('application/json')) {
      throw new Error(`Expected JSON but got ${contentType} (CDN might still be propagating)`);
    }

    const text = await response.text();

    // Try to parse as JSON
    let manifest: KMSManifest;
    try {
      manifest = JSON.parse(text);
    } catch (parseError) {
      // Provide helpful error for HTML responses (404 pages, etc)
      if (text.trim().startsWith('<!DOCTYPE') || text.trim().startsWith('<html')) {
        throw new Error('Received HTML instead of JSON (CDN propagation delay or 404)');
      }
      throw new Error(`Invalid JSON: ${parseError instanceof Error ? parseError.message : String(parseError)}`);
    }

    console.log(`✅ Manifest fetched (version: ${manifest.current.version})`);
    return manifest;
  }, 4, 3000, 'Manifest fetch');
}

/**
 * Verify all hash integrity checks (SHA256 and SRI)
 */
async function verifyHashIntegrity(baseUrl: string, manifest: KMSManifest): Promise<VerificationCheck> {
  console.log(`🔐 Verifying hash integrity...`);

  const results: { name: string; passed: boolean; expected: string; actual: string }[] = [];

  // 1. Verify Worker SHA256 hash
  try {
    const workerUrl = `${baseUrl}/${manifest.current.files.worker.filename}`;
    const response = await fetch(workerUrl);
    if (!response.ok) {
      results.push({
        name: 'Worker SHA256',
        passed: false,
        expected: manifest.current.files.worker.sha256,
        actual: `Failed to fetch: HTTP ${response.status}`,
      });
    } else {
      const content = await response.arrayBuffer();
      const hash = createHash('sha256').update(Buffer.from(content)).digest('hex');
      results.push({
        name: 'Worker SHA256',
        passed: hash === manifest.current.files.worker.sha256,
        expected: manifest.current.files.worker.sha256,
        actual: hash,
      });
    }
  } catch (error) {
    results.push({
      name: 'Worker SHA256',
      passed: false,
      expected: manifest.current.files.worker.sha256,
      actual: error instanceof Error ? error.message : String(error),
    });
  }

  // 2. Verify Worker SRI hash
  try {
    const workerUrl = `${baseUrl}/${manifest.current.files.worker.filename}`;
    const response = await fetch(workerUrl);
    if (!response.ok) {
      results.push({
        name: 'Worker SRI',
        passed: false,
        expected: manifest.current.files.worker.sri,
        actual: `Failed to fetch: HTTP ${response.status}`,
      });
    } else {
      const content = await response.arrayBuffer();
      const hash = createHash('sha384').update(Buffer.from(content)).digest('base64');
      const actualSRI = `sha384-${hash}`;
      results.push({
        name: 'Worker SRI',
        passed: actualSRI === manifest.current.files.worker.sri,
        expected: manifest.current.files.worker.sri,
        actual: actualSRI,
      });
    }
  } catch (error) {
    results.push({
      name: 'Worker SRI',
      passed: false,
      expected: manifest.current.files.worker.sri,
      actual: error instanceof Error ? error.message : String(error),
    });
  }

  // 3. Verify Client.js SRI hash
  try {
    const clientUrl = `${baseUrl}/${manifest.current.files.client.filename}`;
    const response = await fetch(clientUrl);
    if (!response.ok) {
      results.push({
        name: 'Client.js SRI',
        passed: false,
        expected: manifest.current.files.client.sri,
        actual: `Failed to fetch: HTTP ${response.status}`,
      });
    } else {
      const content = await response.arrayBuffer();
      const hash = createHash('sha384').update(Buffer.from(content)).digest('base64');
      const actualSRI = `sha384-${hash}`;
      results.push({
        name: 'Client.js SRI',
        passed: actualSRI === manifest.current.files.client.sri,
        expected: manifest.current.files.client.sri,
        actual: actualSRI,
      });
    }
  } catch (error) {
    results.push({
      name: 'Client.js SRI',
      passed: false,
      expected: manifest.current.files.client.sri,
      actual: error instanceof Error ? error.message : String(error),
    });
  }

  // 4. Verify Enclave.css SRI hash
  try {
    const cssUrl = `${baseUrl}/${manifest.current.files.css.filename}`;
    const response = await fetch(cssUrl);
    if (!response.ok) {
      results.push({
        name: 'Enclave.css SRI',
        passed: false,
        expected: manifest.current.files.css.sri,
        actual: `Failed to fetch: HTTP ${response.status}`,
      });
    } else {
      const content = await response.arrayBuffer();
      const hash = createHash('sha384').update(Buffer.from(content)).digest('base64');
      const actualSRI = `sha384-${hash}`;
      results.push({
        name: 'Enclave.css SRI',
        passed: actualSRI === manifest.current.files.css.sri,
        expected: manifest.current.files.css.sri,
        actual: actualSRI,
      });
    }
  } catch (error) {
    results.push({
      name: 'Enclave.css SRI',
      passed: false,
      expected: manifest.current.files.css.sri,
      actual: error instanceof Error ? error.message : String(error),
    });
  }

  const allPassed = results.every(r => r.passed);

  return {
    name: 'Hash Verification',
    passed: allPassed,
    message: allPassed ? 'All hashes verified' : 'Some hash verifications failed',
    details: results,
  };
}

/**
 * Verify allowed list contains current hash
 */
function verifyAllowedList(manifest: KMSManifest): VerificationCheck {
  const currentHash = manifest.current.sha256;
  const isAllowed = manifest.allowed.includes(currentHash);

  return {
    name: 'Allowed List',
    passed: isAllowed,
    message: isAllowed
      ? 'Current version is in allowed list'
      : 'Current version NOT in allowed list',
    details: {
      currentHash,
      allowed: manifest.allowed,
    },
  };
}

/**
 * Verify reproducible build by rebuilding from source and comparing hashes
 */
async function verifyReproducibleBuild(manifest: KMSManifest): Promise<VerificationCheck> {
  console.log(`🔨 Verifying reproducible build from commit ${manifest.current.commit.substring(0, 8)}...`);

  try {
    const commit = manifest.current.commit;
    const expectedHash = manifest.current.sha256;
    const workerFilename = manifest.current.files.worker.filename;

    // 1. Check out the commit
    console.log(`  📥 Checking out commit ${commit}...`);
    execSync(`git fetch origin ${commit}`, { stdio: 'pipe' });
    execSync(`git checkout ${commit}`, { stdio: 'pipe' });

    // 2. Install dependencies
    console.log(`  📦 Installing dependencies...`);
    execSync('pnpm install --frozen-lockfile', { stdio: 'pipe' });

    // 3. Run reproducible build
    console.log(`  🔨 Building with SOURCE_DATE_EPOCH=${manifest.current.build.SOURCE_DATE_EPOCH}...`);
    execSync('pnpm build:reproducible', {
      stdio: 'pipe',
      env: {
        ...process.env,
        SOURCE_DATE_EPOCH: manifest.current.build.SOURCE_DATE_EPOCH
      }
    });

    // 4. Compute hash of built artifact
    console.log(`  🔐 Computing hash of built artifact...`);
    const builtArtifact = readFileSync(`dist/enclave/${workerFilename}`);
    const actualHash = createHash('sha256').update(builtArtifact).digest('hex');

    // 5. Compare hashes
    const passed = actualHash === expectedHash;

    if (passed) {
      console.log(`  ✅ Build hash matches! ${actualHash.substring(0, 16)}...`);
    } else {
      console.log(`  ❌ Build hash mismatch!`);
      console.log(`     Expected: ${expectedHash}`);
      console.log(`     Actual:   ${actualHash}`);
    }

    return {
      name: 'Reproducible Build',
      passed,
      message: passed ? 'Build is reproducible - hash matches' : 'Build hash mismatch',
      details: {
        commit,
        expected: expectedHash,
        actual: actualHash,
        SOURCE_DATE_EPOCH: manifest.current.build.SOURCE_DATE_EPOCH,
        workerFilename: manifest.current.files.worker.filename,
        commands: [
          `git fetch origin ${commit}`,
          `git checkout ${commit}`,
          `pnpm install --frozen-lockfile`,
          `SOURCE_DATE_EPOCH=${manifest.current.build.SOURCE_DATE_EPOCH} pnpm build:reproducible`,
          `sha256sum dist/enclave/${manifest.current.files.worker.filename}`,
        ],
      },
    };
  } catch (error) {
    console.log(`  ❌ Build verification failed: ${error instanceof Error ? error.message : String(error)}`);
    return {
      name: 'Reproducible Build',
      passed: false,
      message: `Build verification error: ${error instanceof Error ? error.message : String(error)}`,
    };
  } finally {
    // Always return to the verifier branch
    // Note: Build artifacts (dist, node_modules) are left as untracked files
    // They don't interfere with verification and will be cleaned up when the runner is destroyed
    try {
      console.log(`  🔄 Returning to verifier branch...`);
      execSync('git checkout -f verifier', { stdio: 'pipe' });
      console.log(`  ✅ Returned to verifier branch`);
    } catch (cleanupError) {
      console.log(`  ⚠️  Warning: Failed to return to verifier branch - ${cleanupError instanceof Error ? cleanupError.message : String(cleanupError)}`);
    }
  }
}

/**
 * Verify GitHub attestations for built artifacts
 */
async function verifyGitHubAttestation(baseUrl: string, manifest: KMSManifest): Promise<VerificationCheck> {
  console.log(`🔐 Verifying GitHub attestations...`);

  try {
    // Download the worker artifact to verify
    const workerUrl = `${baseUrl}/${manifest.current.files.worker.filename}`;
    console.log(`  📥 Downloading worker: ${workerUrl}`);

    const response = await fetch(workerUrl);
    if (!response.ok) {
      return {
        name: 'GitHub Attestation',
        passed: false,
        message: `Failed to download worker: HTTP ${response.status}`,
      };
    }

    const workerContent = await response.arrayBuffer();
    const tempWorkerPath = `/tmp/${manifest.current.files.worker.filename}`;
    writeFileSync(tempWorkerPath, Buffer.from(workerContent));

    // Verify attestation using gh CLI
    console.log(`  🔍 Verifying attestation with gh CLI...`);
    try {
      // Verify the attestation
      execSync(`gh attestation verify ${tempWorkerPath} -R Lukium/ats-kms-enclave`, {
        encoding: 'utf-8'
      });

      console.log(`  ✅ Attestation verified successfully`);

      // Read attestation URLs from manifest
      const rekorUrl = manifest.current.attestation?.rekorUrl;
      const attestationUrl = manifest.current.attestation?.attestationUrl || 'https://github.com/Lukium/ats-kms-enclave/attestations';

      return {
        name: 'GitHub Attestation',
        passed: true,
        message: 'Attestation verified via GitHub CLI',
        details: {
          artifact: manifest.current.files.worker.filename,
          commit: manifest.current.commit,
          rekorUrl,
          attestationUrl,
        },
      };
    } catch (verifyError: any) {
      const errorOutput = verifyError.stderr || verifyError.stdout || verifyError.message;
      console.log(`  ❌ Attestation verification failed: ${errorOutput}`);

      return {
        name: 'GitHub Attestation',
        passed: false,
        message: 'Attestation verification failed',
        details: {
          artifact: manifest.current.files.worker.filename,
          error: errorOutput,
        },
      };
    }
  } catch (error) {
    console.log(`  ❌ Attestation verification error: ${error instanceof Error ? error.message : String(error)}`);
    return {
      name: 'GitHub Attestation',
      passed: false,
      message: `Verification error: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * Main verification orchestrator
 */
export async function verifyDeployment(baseUrl: string): Promise<VerificationResult> {
  console.log('🔐 KMS Enclave Deployment Verification');
  console.log('='.repeat(60));
  console.log(`📍 Target: ${baseUrl}`);
  console.log();

  const checks: VerificationCheck[] = [];
  let manifest: KMSManifest | undefined;

  try {
    // 1. Fetch manifest
    manifest = await fetchManifest(baseUrl);
    checks.push({
      name: 'Manifest Fetch',
      passed: true,
      message: `Manifest fetched (v${manifest.current.version})`,
    });

    // 2. Verify hash integrity (SHA256 + SRI)
    const hashCheck = await verifyHashIntegrity(baseUrl, manifest);
    checks.push(hashCheck);

    // 3. Verify GitHub attestation
    console.log();
    const attestationCheck = await verifyGitHubAttestation(baseUrl, manifest);
    checks.push(attestationCheck);

    // 4. Verify allowed list
    const allowedCheck = verifyAllowedList(manifest);
    checks.push(allowedCheck);

    // 5. Verify security headers
    console.log();
    const headersResult = await verifyHeaders(baseUrl);
    checks.push({
      name: 'Security Headers',
      passed: headersResult.allPassed,
      message: headersResult.allPassed ? 'All headers verified' : 'Some headers failed',
      details: headersResult.checks,
    });

    // 6. Verify reproducible build
    console.log();
    const buildCheck = await verifyReproducibleBuild(manifest);
    checks.push(buildCheck);

  } catch (error) {
    checks.push({
      name: 'Verification',
      passed: false,
      message: error instanceof Error ? error.message : String(error),
    });
  }

  const allPassed = checks.every(check => check.passed);

  return {
    url: baseUrl,
    timestamp: new Date().toISOString(),
    checks,
    allPassed,
    manifest,
  };
}

/**
 * Main entry point
 */
async function main() {
  const KMS_URL = process.env.KMS_URL || 'https://kms.ats.run';

  const result = await verifyDeployment(KMS_URL);

  // Print summary
  console.log();
  console.log('='.repeat(60));
  console.log('Verification Summary:');
  console.log('-'.repeat(60));

  for (const check of result.checks) {
    const status = check.passed ? '✅' : '❌';
    console.log(`${status} ${check.name}: ${check.message}`);

    if (!check.passed && check.details) {
      console.log(`   Details: ${JSON.stringify(check.details, null, 2)}`);
    }
  }

  console.log();
  console.log('='.repeat(60));

  if (result.allPassed) {
    console.log('✅ All verifications passed!');
    console.log(`🕒 Verified at: ${result.timestamp}`);
    console.log(`📦 Version: ${result.manifest?.current.version}`);
    console.log(`🔑 Hash: ${result.manifest?.current.sha256.substring(0, 8)}`);
  } else {
    console.log('❌ Verification failed!');
  }

  // Output JSON for report generation
  if (process.env.OUTPUT_JSON) {
    const fs = await import('fs');
    fs.writeFileSync(process.env.OUTPUT_JSON, JSON.stringify(result, null, 2));
  }

  process.exit(result.allPassed ? 0 : 1);
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
