/**
 * Phase 6: Integration Tests for KMS Iframe Isolation
 *
 * Comprehensive integration testing using real components (no mocks):
 * - KMSUser (parent context)
 * - KMSClient (iframe bridge)
 * - Worker (crypto operations)
 * - Storage (IndexedDB)
 *
 * Tests full message flow across cross-origin boundaries with real crypto.
 *
 * NOTE: V2 uses per-operation authentication - credentials must be passed
 * to every operation (no session-based lock/unlock).
 */

import { KMSUser } from '@/kms-user';
import type { AuthCredentials } from '@/types';

// Test configuration
const KMS_ORIGIN = 'http://localhost:5177';
const TEST_PASSPHRASE = 'integration-test-passphrase-secure-123';

// Test results tracking
interface TestResult {
  name: string;
  status: 'pass' | 'fail' | 'skip';
  duration: number;
  error?: string;
}

const testResults: TestResult[] = [];

// Test utilities
function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertNotNull<T>(value: T | null | undefined, message: string): T {
  if (value === null || value === undefined) {
    throw new Error(`Assertion failed: ${message}`);
  }
  return value;
}

async function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Test framework
async function runTest(name: string, testFn: () => Promise<void>): Promise<void> {
  const startTime = performance.now();
  try {
    await testFn();
    const duration = performance.now() - startTime;
    testResults.push({ name, status: 'pass', duration });
    logResult('✅', name, duration);
  } catch (error) {
    const duration = performance.now() - startTime;
    const errorMsg = error instanceof Error ? error.message : String(error);
    testResults.push({ name, status: 'fail', duration, error: errorMsg });
    logResult('❌', name, duration, errorMsg);
  }
}

function logResult(icon: string, name: string, duration: number, error?: string): void {
  const output = document.getElementById('test-output')!;
  const timestamp = new Date().toLocaleTimeString();
  const durationMs = duration.toFixed(2);

  const html = `
    <div class="test-result ${error ? 'test-fail' : 'test-pass'}">
      <div class="test-header">
        <span>${icon} ${name}</span>
        <span class="test-time">${timestamp} (${durationMs}ms)</span>
      </div>
      ${error ? `<pre class="test-error">${error}</pre>` : ''}
    </div>
  `;

  output.innerHTML += html;
}

function logSection(title: string): void {
  const output = document.getElementById('test-output')!;
  output.innerHTML += `<div class="test-section"><h3>${title}</h3></div>`;
}

function displaySummary(): void {
  const passed = testResults.filter(r => r.status === 'pass').length;
  const failed = testResults.filter(r => r.status === 'fail').length;
  const skipped = testResults.filter(r => r.status === 'skip').length;
  const totalDuration = testResults.reduce((sum, r) => sum + r.duration, 0);

  const output = document.getElementById('test-output')!;
  const html = `
    <div class="test-summary">
      <h2>Test Summary</h2>
      <p>
        Total: ${testResults.length} |
        ✅ Passed: ${passed} |
        ❌ Failed: ${failed} |
        ⏭️ Skipped: ${skipped} |
        Duration: ${(totalDuration / 1000).toFixed(2)}s
      </p>
      ${failed > 0 ? '<p class="summary-fail">⚠️ Some tests failed</p>' : '<p class="summary-pass">🎉 All tests passed</p>'}
    </div>
  `;

  output.innerHTML += html;
}

// Integration Test Suite
export class IntegrationTestSuite {
  private kmsUser: KMSUser | null = null;
  private credentials: AuthCredentials = { method: 'passphrase', passphrase: TEST_PASSPHRASE };

  async setup(): Promise<void> {
    // Create KMSUser instance (uses iframe element from the config)
    this.kmsUser = new KMSUser({
      kmsOrigin: KMS_ORIGIN,
    });

    // Initialize KMS User (creates iframe, waits for ready)
    await this.kmsUser.init();

    // Wait a bit for iframe to be fully ready
    await sleep(200);
  }

  async teardown(): Promise<void> {
    // Terminate KMS User (removes iframe)
    if (this.kmsUser) {
      this.kmsUser.terminate();
    }

    this.kmsUser = null;

    // Wait for cleanup
    await sleep(100);
  }

  // ============================================================================
  // Test Group 1: Setup Operations
  // ============================================================================

  async testPassphraseSetup(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Verify not setup initially
    const status = await kmsUser.isSetup();
    assert(status.isSetup === false, 'KMS should not be setup initially');

    // Setup passphrase
    const result = await kmsUser.setupPassphrase(TEST_PASSPHRASE);

    assert(result.success === true, 'Passphrase setup should succeed');
    assert(result.enrollmentId !== undefined, 'Should return enrollment ID');

    // Verify setup complete
    const statusAfter = await kmsUser.isSetup();
    assert(statusAfter.isSetup === true, 'KMS should be setup after passphrase setup');
    assert(statusAfter.methods.includes('passphrase'), 'Should have passphrase method enrolled');
  }

  // ============================================================================
  // Test Group 2: VAPID Key Lifecycle (with per-operation auth)
  // ============================================================================

  async testVAPIDGeneration(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Setup first (required before any operations)
    await kmsUser.setupPassphrase(TEST_PASSPHRASE);

    // Generate VAPID keypair (with credentials)
    const result = await kmsUser.generateVAPID(this.credentials);

    assert(result.publicKey !== undefined, 'Should return public key');
    assert(result.kid !== undefined, 'Should return key ID');
    assert(typeof result.publicKey === 'string', 'Public key should be string');
    assert(result.publicKey.length > 0, 'Public key should not be empty');
    assert(result.kid.startsWith('vapid-'), 'Kid should have vapid- prefix');
  }

  async testVAPIDSignJWT(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Setup and generate VAPID
    await kmsUser.setupPassphrase(TEST_PASSPHRASE);
    const vapidResult = await kmsUser.generateVAPID(this.credentials);
    const kid = vapidResult.kid;

    // Sign JWT with VAPID key (with credentials)
    const payload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@example.com',
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
    };

    const result = await kmsUser.signJWT(kid, payload, this.credentials);

    assert(result.jwt !== undefined, 'Should return JWT');
    assert(typeof result.jwt === 'string', 'JWT should be string');
    assert(result.jwt.split('.').length === 3, 'JWT should have 3 parts (header.payload.signature)');

    // Verify JWT structure
    const [header, payloadPart, signature] = result.jwt.split('.');
    assert(header!.length > 0, 'Header should not be empty');
    assert(payloadPart!.length > 0, 'Payload should not be empty');
    assert(signature!.length > 0, 'Signature should not be empty');
  }

  async testVAPIDGetPublicKey(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Setup and generate VAPID
    await kmsUser.setupPassphrase(TEST_PASSPHRASE);
    const vapidResult = await kmsUser.generateVAPID(this.credentials);
    const kid = vapidResult.kid;

    // Get public key (no credentials needed for public data)
    const result = await kmsUser.getPublicKey(kid);

    assert(result.publicKey !== undefined, 'Should return public key');
    assert(result.publicKey === vapidResult.publicKey, 'Should match original public key');
  }

  async testSignJWTWithWrongCredentials(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Setup and generate VAPID
    await kmsUser.setupPassphrase(TEST_PASSPHRASE);
    const vapidResult = await kmsUser.generateVAPID(this.credentials);

    // Try to sign with wrong passphrase
    const wrongCreds: AuthCredentials = { method: 'passphrase', passphrase: 'wrong-passphrase' };
    const payload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@example.com',
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    try {
      await kmsUser.signJWT(vapidResult.kid, payload, wrongCreds);
      throw new Error('Should have thrown error for wrong credentials');
    } catch (error) {
      // Expected to fail
      assert(
        error instanceof Error && error.message.includes('Decryption failed'),
        'Should throw decryption error for wrong credentials'
      );
    }
  }

  async testConcurrentVAPIDOperations(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Setup
    await kmsUser.setupPassphrase(TEST_PASSPHRASE);

    // Issue multiple VAPID generation requests concurrently
    const results = await Promise.all([
      kmsUser.generateVAPID(this.credentials),
      kmsUser.generateVAPID(this.credentials),
      kmsUser.generateVAPID(this.credentials),
    ]);

    // All should succeed
    assert(results.length === 3, 'Should have 3 results');
    results.forEach((result, i) => {
      assert(result.publicKey !== undefined, `Result ${i} should have public key`);
      assert(result.kid !== undefined, `Result ${i} should have kid`);
    });

    // All kids should be unique
    const kids = results.map(r => r.kid);
    const uniqueKids = new Set(kids);
    assert(uniqueKids.size === 3, 'All kids should be unique');
  }

  // ============================================================================
  // Test Group 3: Audit Chain Integrity
  // ============================================================================

  async testAuditChainVerification(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Setup (creates audit key)
    await kmsUser.setupPassphrase(TEST_PASSPHRASE);

    // Perform several operations to create audit entries
    const vapid1 = await kmsUser.generateVAPID(this.credentials);
    await kmsUser.signJWT(vapid1.kid, {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@example.com',
      exp: Math.floor(Date.now() / 1000) + 3600,
    }, this.credentials);

    const vapid2 = await kmsUser.generateVAPID(this.credentials);
    await kmsUser.signJWT(vapid2.kid, {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@example.com',
      exp: Math.floor(Date.now() / 1000) + 3600,
    }, this.credentials);

    // Verify audit chain
    const result = await kmsUser.verifyAuditChain();

    assert(result.valid === true, 'Audit chain should be valid');
    assert(result.entries > 0, 'Should have at least one audit entry');
  }

  // ============================================================================
  // Test Group 4: Performance Benchmarks
  // ============================================================================

  async testPerformanceVAPIDGeneration(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Setup
    await kmsUser.setupPassphrase(TEST_PASSPHRASE);

    // Measure VAPID generation time
    const startTime = performance.now();
    await kmsUser.generateVAPID(this.credentials);
    const duration = performance.now() - startTime;

    assert(duration < 1000, `VAPID generation should be < 1000ms (was ${duration.toFixed(2)}ms)`);
  }

  async testPerformanceJWTSigning(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Setup and generate VAPID
    await kmsUser.setupPassphrase(TEST_PASSPHRASE);
    const vapidResult = await kmsUser.generateVAPID(this.credentials);

    // Measure JWT signing time
    const payload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@example.com',
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const startTime = performance.now();
    await kmsUser.signJWT(vapidResult.kid, payload, this.credentials);
    const duration = performance.now() - startTime;

    assert(duration < 500, `JWT signing should be < 500ms (was ${duration.toFixed(2)}ms)`);
  }

  async testPerformanceSetupPassphrase(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Measure passphrase setup time (includes PBKDF2, should be 150-300ms)
    const startTime = performance.now();
    await kmsUser.setupPassphrase(TEST_PASSPHRASE);
    const duration = performance.now() - startTime;

    assert(
      duration >= 100 && duration < 5000,
      `Passphrase setup should be 100-5000ms (was ${duration.toFixed(2)}ms) - includes PBKDF2`
    );
  }
}

// Run all tests
async function runAllTests(): Promise<void> {
  const suite = new IntegrationTestSuite();

  logSection('🚀 Starting Integration Tests');
  logSection('ℹ️ V2 uses per-operation authentication - credentials passed to each operation');

  // Group 1: Setup
  logSection('Group 1: Setup Operations');

  await suite.setup();
  await runTest('Passphrase Setup', () => suite.testPassphraseSetup());
  await suite.teardown();

  // Group 2: VAPID Lifecycle
  logSection('Group 2: VAPID Key Lifecycle (Per-Operation Auth)');

  await suite.setup();
  await runTest('VAPID Generation', () => suite.testVAPIDGeneration());
  await suite.teardown();

  await suite.setup();
  await runTest('VAPID Sign JWT', () => suite.testVAPIDSignJWT());
  await suite.teardown();

  await suite.setup();
  await runTest('VAPID Get Public Key', () => suite.testVAPIDGetPublicKey());
  await suite.teardown();

  await suite.setup();
  await runTest('Sign JWT with Wrong Credentials', () => suite.testSignJWTWithWrongCredentials());
  await suite.teardown();

  await suite.setup();
  await runTest('Concurrent VAPID Operations', () => suite.testConcurrentVAPIDOperations());
  await suite.teardown();

  // Group 3: Audit Chain
  logSection('Group 3: Audit Chain Integrity');

  await suite.setup();
  await runTest('Audit Chain Verification', () => suite.testAuditChainVerification());
  await suite.teardown();

  // Group 4: Performance
  logSection('Group 4: Performance Benchmarks');

  await suite.setup();
  await runTest('Performance: VAPID Generation', () => suite.testPerformanceVAPIDGeneration());
  await suite.teardown();

  await suite.setup();
  await runTest('Performance: JWT Signing', () => suite.testPerformanceJWTSigning());
  await suite.teardown();

  await suite.setup();
  await runTest('Performance: Setup Passphrase', () => suite.testPerformanceSetupPassphrase());
  await suite.teardown();

  // Display summary
  displaySummary();
}

// Initialize and run tests when page loads
window.addEventListener('load', () => {
  console.log('[Integration Tests] Initializing...');

  // Add run button
  const runButton = document.getElementById('run-tests');
  if (runButton) {
    runButton.addEventListener('click', async () => {
      runButton.setAttribute('disabled', 'true');
      document.getElementById('test-output')!.innerHTML = '';
      await runAllTests();
      runButton.removeAttribute('disabled');
    });
  }

  console.log('[Integration Tests] Ready - click "Run Tests" to begin');
});
