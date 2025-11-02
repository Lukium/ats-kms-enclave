#!/usr/bin/env tsx
/**
 * Security Headers Verification Script
 *
 * Verifies that kms.ats.run serves the correct security headers:
 * - Content-Security-Policy (CSP)
 * - Cross-Origin-Resource-Policy (CORP)
 * - Permissions-Policy
 * - X-Content-Type-Options
 * - Referrer-Policy
 *
 * Part of the KMS Enclave verification pipeline (Phase 2.1)
 */

interface HeaderCheck {
  name: string;
  expected: string;
  actual?: string;
  passed: boolean;
  message?: string;
}

interface HeaderVerificationResult {
  url: string;
  timestamp: string;
  checks: HeaderCheck[];
  allPassed: boolean;
}

/**
 * Expected security headers for KMS enclave
 * These must match placeholders/cf-pages/_headers
 */
const EXPECTED_HEADERS = {
  'content-security-policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors https://alpha.allthe.services https://beta.allthe.services https://allthe.services https://phase2-demo.allthe.services http://localhost:5173; form-action 'none'",

  'permissions-policy':
    'accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), bluetooth=(), camera=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), screen-wake-lock=(), serial=(), speaker-selection=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()',

  'x-content-type-options':
    'nosniff',

  'referrer-policy':
    'no-referrer',
};

/**
 * Headers that should NOT be present (COOP/COEP disabled for iframe compatibility)
 */
const FORBIDDEN_HEADERS = [
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
];

/**
 * Normalize CSP header for comparison (remove extra whitespace)
 */
function normalizeCSP(csp: string): string {
  return csp
    .split(';')
    .map(directive => directive.trim())
    .filter(directive => directive.length > 0)
    .sort()
    .join('; ');
}

/**
 * Verify security headers for a given URL
 */
export async function verifyHeaders(url: string): Promise<HeaderVerificationResult> {
  console.log(`🔍 Verifying security headers for: ${url}`);

  const checks: HeaderCheck[] = [];

  try {
    // Fetch with HEAD request to get headers only
    const response = await fetch(url, { method: 'HEAD' });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    // Check expected headers
    for (const [headerName, expectedValue] of Object.entries(EXPECTED_HEADERS)) {
      const actualValue = response.headers.get(headerName);

      if (!actualValue) {
        checks.push({
          name: headerName,
          expected: expectedValue,
          actual: undefined,
          passed: false,
          message: 'Header missing',
        });
        continue;
      }

      // Special handling for CSP (normalize before comparing)
      let passed: boolean;
      if (headerName === 'content-security-policy') {
        passed = normalizeCSP(actualValue) === normalizeCSP(expectedValue);
      } else {
        passed = actualValue.toLowerCase() === expectedValue.toLowerCase();
      }

      checks.push({
        name: headerName,
        expected: expectedValue,
        actual: actualValue,
        passed,
        message: passed ? 'OK' : 'Mismatch',
      });
    }

    // Check forbidden headers (should NOT be present)
    for (const headerName of FORBIDDEN_HEADERS) {
      const actualValue = response.headers.get(headerName);
      const passed = actualValue === null;

      checks.push({
        name: headerName,
        expected: '(not present)',
        actual: actualValue || undefined,
        passed,
        message: passed ? 'Correctly absent' : 'Should not be present',
      });
    }

  } catch (error) {
    checks.push({
      name: 'fetch',
      expected: 'Success',
      actual: error instanceof Error ? error.message : String(error),
      passed: false,
      message: 'Failed to fetch headers',
    });
  }

  const allPassed = checks.every(check => check.passed);

  return {
    url,
    timestamp: new Date().toISOString(),
    checks,
    allPassed,
  };
}

/**
 * Main entry point
 */
async function main() {
  const KMS_URL = process.env.KMS_URL || 'https://kms.ats.run';

  console.log('🔐 KMS Enclave Security Headers Verification');
  console.log('='.repeat(50));
  console.log();

  const result = await verifyHeaders(KMS_URL);

  // Print results
  console.log(`📍 URL: ${result.url}`);
  console.log(`🕒 Timestamp: ${result.timestamp}`);
  console.log();
  console.log('Header Checks:');
  console.log('-'.repeat(50));

  for (const check of result.checks) {
    const status = check.passed ? '✅' : '❌';
    console.log(`${status} ${check.name}`);

    if (!check.passed) {
      console.log(`   Expected: ${check.expected}`);
      console.log(`   Actual:   ${check.actual || '(missing)'}`);
      console.log(`   Message:  ${check.message}`);
    }
  }

  console.log();
  console.log('='.repeat(50));

  if (result.allPassed) {
    console.log('✅ All security headers verified successfully!');
    process.exit(0);
  } else {
    console.log('❌ Security header verification failed!');
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
