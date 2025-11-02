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
import { verifyHeaders } from './verify-headers.js';

interface KMSManifest {
  schema: number;
  current: {
    version: string;
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
 * Fetch and parse the KMS manifest
 */
async function fetchManifest(baseUrl: string): Promise<KMSManifest> {
  const manifestUrl = `${baseUrl}/.well-known/kms-manifest.json`;
  console.log(`📥 Fetching manifest: ${manifestUrl}`);

  const response = await fetch(manifestUrl);
  if (!response.ok) {
    throw new Error(`Failed to fetch manifest: HTTP ${response.status}`);
  }

  const manifest = await response.json() as KMSManifest;
  console.log(`✅ Manifest fetched (version: ${manifest.current.version})`);

  return manifest;
}

/**
 * Fetch the deployed worker and compute its hash
 */
async function verifyWorkerHash(baseUrl: string, manifest: KMSManifest): Promise<VerificationCheck> {
  const workerUrl = `${baseUrl}/${manifest.current.files.worker.filename}`;
  console.log(`📥 Fetching worker: ${workerUrl}`);

  try {
    const response = await fetch(workerUrl);
    if (!response.ok) {
      return {
        name: 'Worker Hash',
        passed: false,
        message: `Failed to fetch worker: HTTP ${response.status}`,
      };
    }

    const content = await response.arrayBuffer();
    const hash = createHash('sha256').update(Buffer.from(content)).digest('hex');

    const expected = manifest.current.files.worker.sha256;
    const passed = hash === expected;

    return {
      name: 'Worker Hash',
      passed,
      message: passed ? 'Worker hash matches manifest' : 'Worker hash mismatch',
      details: {
        expected,
        actual: hash,
        url: workerUrl,
      },
    };
  } catch (error) {
    return {
      name: 'Worker Hash',
      passed: false,
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Verify SRI hashes for all resources
 */
async function verifySRIHashes(baseUrl: string, manifest: KMSManifest): Promise<VerificationCheck> {
  console.log(`🔐 Verifying SRI hashes...`);

  const resources = [
    { name: 'client.js', filename: manifest.current.files.client.filename, sri: manifest.current.files.client.sri },
    { name: 'enclave.css', filename: manifest.current.files.css.filename, sri: manifest.current.files.css.sri },
  ];

  const results: { name: string; passed: boolean; message: string }[] = [];

  for (const resource of resources) {
    const url = `${baseUrl}/${resource.filename}`;

    try {
      const response = await fetch(url);
      if (!response.ok) {
        results.push({
          name: resource.name,
          passed: false,
          message: `Failed to fetch: HTTP ${response.status}`,
        });
        continue;
      }

      const content = await response.arrayBuffer();
      const hash = createHash('sha384').update(Buffer.from(content)).digest('base64');
      const actualSRI = `sha384-${hash}`;

      const passed = actualSRI === resource.sri;
      results.push({
        name: resource.name,
        passed,
        message: passed ? 'SRI hash matches' : `SRI mismatch: expected ${resource.sri}, got ${actualSRI}`,
      });
    } catch (error) {
      results.push({
        name: resource.name,
        passed: false,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const allPassed = results.every(r => r.passed);

  return {
    name: 'SRI Hashes',
    passed: allPassed,
    message: allPassed ? 'All SRI hashes verified' : 'Some SRI hashes failed',
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
 * Placeholder for Rekor verification (Phase 2.2)
 */
function verifyRekorAttestation(manifest: KMSManifest): VerificationCheck {
  // TODO: Phase 2.2 - Implement Rekor transparency log verification
  // This will:
  // 1. Query Rekor for entry by hash
  // 2. Verify signature with cosign
  // 3. Validate timestamp
  // 4. Confirm entry matches manifest

  return {
    name: 'Rekor Attestation',
    passed: true, // Skipped for now
    message: '⏭️  Skipped (Phase 2.2)',
    details: {
      phase: '2.2',
      status: 'not-implemented',
      hash: manifest.current.sha256,
    },
  };
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

    // 2. Verify worker hash
    const workerCheck = await verifyWorkerHash(baseUrl, manifest);
    checks.push(workerCheck);

    // 3. Verify SRI hashes
    const sriCheck = await verifySRIHashes(baseUrl, manifest);
    checks.push(sriCheck);

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

    // 6. [Future] Verify Rekor attestation
    console.log();
    const rekorCheck = verifyRekorAttestation(manifest);
    checks.push(rekorCheck);

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
    process.exit(0);
  } else {
    console.log('❌ Verification failed!');
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
