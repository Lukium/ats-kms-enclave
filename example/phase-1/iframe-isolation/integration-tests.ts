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
    // Handle different error types
    let errorMsg: string;
    if (error instanceof Error) {
      errorMsg = error.message;
      if (error.stack) {
        errorMsg += '\n\nStack:\n' + error.stack;
      }
    } else if (typeof error === 'object' && error !== null) {
      errorMsg = JSON.stringify(error, null, 2);
    } else {
      errorMsg = String(error);
    }
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

function displayArtifact(title: string, data: any): void {
  const output = document.getElementById('test-output')!;

  // Format the data nicely
  let formattedData = '';
  if (typeof data === 'object' && data !== null) {
    // Show key properties in a readable format
    formattedData = Object.entries(data)
      .map(([key, value]) => {
        let displayValue = value;

        // Truncate long strings (like JWTs)
        if (typeof value === 'string' && value.length > 100) {
          displayValue = value.substring(0, 100) + '...';
        }

        // Format timestamps
        if (key === 'exp' || key === 'createdAt' || key === 'updatedAt') {
          displayValue = `${value} (${new Date(value as number).toLocaleString()})`;
        }

        return `<div><strong>${key}:</strong> ${typeof displayValue === 'object' ? JSON.stringify(displayValue) : displayValue}</div>`;
      })
      .join('');
  } else {
    formattedData = `<div>${data}</div>`;
  }

  const html = `
    <div class="cards-container">
      <div class="artifact-card">
        <div class="artifact-title">📦 ${title}</div>
        <div class="artifact-data">${formattedData}</div>
      </div>
    </div>
  `;

  output.innerHTML += html;
}

async function displayLatestAuditEntry(kmsUser: KMSUser): Promise<void> {
  try {
    const auditLog = await kmsUser.getAuditLog();
    if (!auditLog.entries || auditLog.entries.length === 0) {
      return; // No audit entries yet
    }

    const latestEntry = auditLog.entries[auditLog.entries.length - 1];

    // Determine color based on signer type
    let signerColor = '#4299e1'; // blue for UAK
    if (latestEntry.signer === 'LAK') {
      signerColor = '#48bb78'; // green for LAK
    } else if (latestEntry.signer === 'KIAK') {
      signerColor = '#ed8936'; // orange for KIAK
    }

    const output = document.getElementById('test-output')!;

    // Find the most recent cards-container and add the audit card to it
    const containers = output.querySelectorAll('.cards-container');
    if (containers.length === 0) {
      return; // No containers yet
    }

    const lastContainer = containers[containers.length - 1];

    const auditCardHtml = `
      <div class="audit-card" style="border-left-color: ${signerColor};">
        <div class="artifact-title">🔐 Audit Entry #${latestEntry.seqNum} (${latestEntry.signer})</div>
        <div class="artifact-data">
          <div><strong>Signer:</strong> ${latestEntry.signer}</div>
          <div><strong>Operation:</strong> ${latestEntry.op}</div>
          <div><strong>Request ID:</strong> ${latestEntry.requestId}</div>
          ${latestEntry.leaseId ? `<div><strong>Lease ID:</strong> ${latestEntry.leaseId}</div>` : ''}
          <div><strong>Chain Hash:</strong> ${latestEntry.chainHash}</div>
          <div><strong>Signature:</strong> ${latestEntry.sig}</div>
          ${latestEntry.cert ? `<div><strong>Has Delegation Cert:</strong> Yes (${latestEntry.cert.signerKind})</div>` : ''}
        </div>
      </div>
    `;

    lastContainer.innerHTML += auditCardHtml;
  } catch (error) {
    console.error('Failed to fetch audit entry:', error);
    // Don't display error - audit system might not be ready yet
  }
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
  private vapidKid: string | null = null; // Shared VAPID key ID for all tests
  private leaseId: string | null = null; // Shared lease ID for JWT tests

  async setup(): Promise<void> {
    // Create KMSUser instance (uses iframe element from the config)
    this.kmsUser = new KMSUser({
      kmsOrigin: KMS_ORIGIN,
    });

    // Initialize KMS User (creates iframe, waits for ready)
    await this.kmsUser.init();

    // Wait a bit for iframe to be fully ready
    await sleep(200);

    // Reset KMS to ensure clean state
    await this.kmsUser.resetKMS();
  }

  async setupPassphrase(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Verify not setup initially
    const status = await kmsUser.isSetup();
    assert(status.isSetup === false, 'KMS should not be setup initially');

    // Setup passphrase (creates MS + UAK + VAPID key)
    const result = await kmsUser.setupPassphrase(TEST_PASSPHRASE);
    displayArtifact('Passphrase Setup Complete', result);
    await displayLatestAuditEntry(kmsUser); // Show UAK-signed audit entry

    assert(result.success === true, 'Passphrase setup should succeed');
    assert(result.enrollmentId !== undefined, 'Should return enrollment ID');

    // V2 spec: VAPID key should be generated during setup
    assert(result.vapidPublicKey !== undefined, 'Should return VAPID public key');
    assert(typeof result.vapidPublicKey === 'string', 'VAPID public key should be string');
    assert(result.vapidPublicKey.length > 0, 'VAPID public key should not be empty');

    assert(result.vapidKid !== undefined, 'Should return VAPID kid');
    assert(typeof result.vapidKid === 'string', 'VAPID kid should be string');

    // Store VAPID kid for other tests to use
    this.vapidKid = result.vapidKid;
  }

  async teardown(): Promise<void> {
    // Terminate KMS User (removes iframe)
    if (this.kmsUser) {
      this.kmsUser.terminate();
    }

    this.kmsUser = null;
    this.vapidKid = null;

    // Wait for cleanup
    await sleep(100);
  }

  // ============================================================================
  // Test Group 1: Setup Operations
  // ============================================================================
  // NOTE: setupPassphrase() method is the actual setup - called once for all tests

  // ============================================================================
  // Test Group 2: VAPID Lease Lifecycle (V2 API)
  // ============================================================================

  async testCreateVAPIDLease(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Create VAPID lease (V2 API)
    const result = await kmsUser.createLease({
      userId: 'test-user-123',
      subs: [
        {
          url: 'https://fcm.googleapis.com/fcm/send/abc123',
          aud: 'https://fcm.googleapis.com',
          eid: 'ep-1',
        },
      ],
      ttlHours: 12,
      credentials: this.credentials,
    });
    displayArtifact('VAPID Lease Created', result);
    await displayLatestAuditEntry(kmsUser); // Show UAK-signed audit entry (lease creation requires credentials)

    assert(result.leaseId !== undefined, 'Should return lease ID');
    assert(result.exp !== undefined, 'Should return expiration');
    assert(result.quotas !== undefined, 'Should return quotas');
    assert(typeof result.leaseId === 'string', 'Lease ID should be string');
    assert(result.leaseId.startsWith('lease-'), 'Lease ID should have lease- prefix');
    assert(result.exp > Date.now(), 'Expiration should be in future');

    // Save lease ID for subsequent tests
    this.leaseId = result.leaseId;
  }

  async testIssueVAPIDJWT(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');
    const leaseId = assertNotNull(this.leaseId, 'Lease ID not set - testCreateVAPIDLease must run first');

    // Issue JWT using the existing lease (NO credentials needed - lease is the authorization!)
    const result = await kmsUser.issueVAPIDJWT({
      leaseId,
      endpoint: {
        url: 'https://fcm.googleapis.com/fcm/send/abc123',
        aud: 'https://fcm.googleapis.com',
        eid: 'ep-1',
      },
    });
    displayArtifact('VAPID JWT Issued', result);
    await displayLatestAuditEntry(kmsUser); // Show LAK-signed audit entry (JWT issuance uses LAK, not UAK!)

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

    // Use the shared VAPID key (created during setupPassphrase)
    const kid = assertNotNull(this.vapidKid, 'VAPID kid should be set by setupPassphrase');

    // Get public key (no credentials needed for public data)
    const result = await kmsUser.getPublicKey(kid);
    displayArtifact('VAPID Public Key Retrieved', result);
    await displayLatestAuditEntry(kmsUser); // Show audit entry for getPublicKey operation

    assert(result.publicKey !== undefined, 'Should return public key');
    assert(typeof result.publicKey === 'string', 'Public key should be string');
    assert(result.publicKey.length > 0, 'Public key should not be empty');
  }

  async testIssueJWTWithWrongCredentials(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Try to create lease with wrong passphrase
    const wrongCreds: AuthCredentials = { method: 'passphrase', passphrase: 'wrong-passphrase' };

    try {
      await kmsUser.createLease({
        userId: 'test-user-123',
        subs: [
          {
            url: 'https://fcm.googleapis.com/fcm/send/abc123',
            aud: 'https://fcm.googleapis.com',
            eid: 'ep-1',
          },
        ],
        ttlHours: 12,
        credentials: wrongCreds, // Wrong credentials!
      });
      throw new Error('Should have thrown error for wrong credentials');
    } catch (error) {
      // Expected to fail - check if it's the right error
      if (error instanceof Error && error.message === 'Should have thrown error for wrong credentials') {
        throw error; // Re-throw if operation succeeded when it shouldn't
      }

      // Display the error that was caught
      displayArtifact('Authentication Error (Expected)', {
        error: error instanceof Error ? error.message : String(error),
        expectedBehavior: 'Operation correctly rejected due to invalid credentials',
      });
      await displayLatestAuditEntry(kmsUser); // Show audit entry if failed auth was logged

      // V2 uses KCV for fast-fail, so error is "Invalid passphrase" not "Decryption failed"
      assert(
        error instanceof Error && (error.message.includes('Invalid passphrase') || error.message.includes('Decryption failed')),
        `Should throw authentication error for wrong credentials, got: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  async testConcurrentJWTIssuance(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');
    const leaseId = assertNotNull(this.leaseId, 'Lease ID not set - testCreateVAPIDLease must run first');

    // Issue 3 JWTs with staggered expirations for the SAME endpoint
    // This demonstrates the JWT stashing strategy for seamless relay switching:
    // - JWT #1: expires at T+15min (900s)
    // - JWT #2: expires at T+24min (900s + 540s stagger = 60% TTL)
    // - JWT #3: expires at T+33min (900s + 1080s stagger)
    //
    // When JWT #1 reaches 60% of its lifetime (9 minutes), the PWA switches to JWT #2,
    // which is already valid and has 15 minutes remaining. This ensures no interruption
    // in service when switching relays or rotating credentials.
    const endpoint = {
      url: 'https://fcm.googleapis.com/fcm/send/abc123',
      aud: 'https://fcm.googleapis.com',
      eid: 'ep-1',
    };

    const results = await kmsUser.issueVAPIDJWTs({
      leaseId,
      endpoint,
      count: 3,
    });

    // Display all results with expiration times (show full JWT, not truncated)
    const now = new Date();
    results.forEach((result, i) => {
      const expDate = new Date(result.exp * 1000);
      const ttlSeconds = Math.floor((expDate.getTime() - now.getTime()) / 1000);

      displayArtifact(`Stashed JWT ${i + 1}`, {
        jti: result.jti,
        exp: `${result.exp} (${expDate.toLocaleTimeString()})`,
        ttl: `${ttlSeconds}s (~${Math.floor(ttlSeconds / 60)} minutes remaining)`,
        issuedAt: now.toLocaleTimeString(),
        jwt: result.jwt, // Show full JWT (not truncated)
      });
    });

    // Verify all JWTs succeeded
    assert(results.length === 3, 'Should have 3 JWTs');
    results.forEach((result, i) => {
      assert(result.jwt !== undefined, `JWT ${i + 1} should have jwt`);
      assert(result.jti !== undefined, `JWT ${i + 1} should have jti`);
      assert(result.exp !== undefined, `JWT ${i + 1} should have exp`);
    });

    // All JTIs should be unique (each JWT gets unique ID)
    const jtis = results.map(r => r.jti);
    const uniqueJtis = new Set(jtis);
    assert(uniqueJtis.size === 3, 'All JWT IDs should be unique');

    // Expiration times should be staggered (NOT all the same!)
    // JWT stagger interval = 60% of TTL = 540s (9 minutes)
    // exp[0] = baseTime + 900s
    // exp[1] = baseTime + 900s + 540s = baseTime + 1440s
    // exp[2] = baseTime + 900s + 1080s = baseTime + 1980s
    const exps = results.map(r => r.exp);
    const diff1 = exps[1] - exps[0]; // Should be ~540s
    const diff2 = exps[2] - exps[1]; // Should be ~540s
    assert(Math.abs(diff1 - 540) < 2, `JWT[1] - JWT[0] should be ~540s, got ${diff1}s`);
    assert(Math.abs(diff2 - 540) < 2, `JWT[2] - JWT[1] should be ~540s, got ${diff2}s`);
  }

  // ============================================================================
  // Test Group 3: Audit Chain Integrity
  // ============================================================================

  async testAuditChainVerification(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Use the shared VAPID key (created during setupPassphrase)
    const vapidKid = assertNotNull(this.vapidKid, 'VAPID kid should be set by setupPassphrase');

    // Create lease 1
    const lease1 = await kmsUser.createLease({
      userId: 'test-user-1',
      subs: [{ url: 'https://fcm.googleapis.com/fcm/send/1', aud: 'https://fcm.googleapis.com', eid: 'ep-1' }],
      ttlHours: 12,
      credentials: this.credentials,
    });
    displayArtifact('Lease 1 Created', lease1);
    assertNotNull(lease1, 'Lease 1 creation failed');
    assertNotNull(lease1.leaseId, 'Lease 1 should have leaseId');

    // Issue JWT 1
    const jwt1 = await kmsUser.issueVAPIDJWT({
      leaseId: lease1.leaseId,
      endpoint: { url: 'https://fcm.googleapis.com/fcm/send/1', aud: 'https://fcm.googleapis.com', eid: 'ep-1' },
      kid: vapidKid,
      credentials: this.credentials,
    });
    displayArtifact('JWT 1 Issued', jwt1);

    // Create lease 2
    const lease2 = await kmsUser.createLease({
      userId: 'test-user-2',
      subs: [{ url: 'https://fcm.googleapis.com/fcm/send/2', aud: 'https://fcm.googleapis.com', eid: 'ep-2' }],
      ttlHours: 12,
      credentials: this.credentials,
    });
    displayArtifact('Lease 2 Created', lease2);
    assertNotNull(lease2, 'Lease 2 creation failed');
    assertNotNull(lease2.leaseId, 'Lease 2 should have leaseId');

    // Issue JWT 2
    const jwt2 = await kmsUser.issueVAPIDJWT({
      leaseId: lease2.leaseId,
      endpoint: { url: 'https://fcm.googleapis.com/fcm/send/2', aud: 'https://fcm.googleapis.com', eid: 'ep-2' },
      kid: vapidKid,
      credentials: this.credentials,
    });
    displayArtifact('JWT 2 Issued', jwt2);

    // Verify audit chain
    const result = await kmsUser.verifyAuditChain();
    displayArtifact('Audit Chain Verification', result);

    assert(result.valid === true, `Audit chain should be valid, got: ${JSON.stringify(result)}`);
    assert(result.entries > 0, 'Should have at least one audit entry');
  }

  // ============================================================================
  // Test Group 4: Performance Benchmarks
  // ============================================================================

  async testPerformanceVAPIDGeneration(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Measure VAPID generation time
    const startTime = performance.now();
    await kmsUser.generateVAPID(this.credentials);
    const duration = performance.now() - startTime;

    assert(duration < 1000, `VAPID generation should be < 1000ms (was ${duration.toFixed(2)}ms)`);
  }

  async testPerformanceJWTIssuance(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Use the shared VAPID key (created during setupPassphrase)
    const vapidKid = assertNotNull(this.vapidKid, 'VAPID kid should be set by setupPassphrase');

    // Create lease
    const leaseResult = await kmsUser.createLease({
      userId: 'test-user-perf',
      subs: [{ url: 'https://fcm.googleapis.com/fcm/send/abc', aud: 'https://fcm.googleapis.com', eid: 'ep-perf' }],
      ttlHours: 12,
      credentials: this.credentials,
    });

    // Measure JWT issuance time
    const startTime = performance.now();
    await kmsUser.issueVAPIDJWT({
      leaseId: leaseResult.leaseId,
      endpoint: { url: 'https://fcm.googleapis.com/fcm/send/abc', aud: 'https://fcm.googleapis.com', eid: 'ep-perf' },
      kid: vapidKid,
      credentials: this.credentials,
    });
    const duration = performance.now() - startTime;

    assert(duration < 500, `JWT issuance should be < 500ms (was ${duration.toFixed(2)}ms)`);
  }

  async testPerformanceSetupPassphrase(): Promise<void> {
    const kmsUser = assertNotNull(this.kmsUser, 'KMSUser not initialized');

    // Reset KMS to test setup performance from clean state
    await kmsUser.resetKMS();
    await sleep(200);

    // Measure passphrase setup time (includes PBKDF2, should be 150-300ms)
    const startTime = performance.now();
    const setupResult = await kmsUser.setupPassphrase(TEST_PASSPHRASE);
    const duration = performance.now() - startTime;

    assert(
      duration >= 100 && duration < 5000,
      `Passphrase setup should be 100-5000ms (was ${duration.toFixed(2)}ms) - includes PBKDF2`
    );

    // Store the new vapidKid after reset (for subsequent tests if any)
    this.vapidKid = setupResult.vapidKid;
  }
}

// Run all tests
async function runAllTests(): Promise<void> {
  const suite = new IntegrationTestSuite();

  logSection('🚀 Starting Integration Tests');
  logSection('ℹ️ V2 uses per-operation authentication - credentials passed to each operation');

  // ONE-TIME SETUP FOR ALL TESTS
  await suite.setup();  // Create iframe + reset database

  logSection('Group 1: Setup Operations');
  await runTest('Passphrase Setup', () => suite.setupPassphrase());  // Create MS + VAPID ONCE

  // Group 2: VAPID Lease Lifecycle - ALL tests use the SAME VAPID key
  logSection('Group 2: VAPID Lease Lifecycle (V2 API)');
  await runTest('Create VAPID Lease', () => suite.testCreateVAPIDLease());
  await runTest('Issue VAPID JWT', () => suite.testIssueVAPIDJWT());
  await runTest('VAPID Get Public Key', () => suite.testVAPIDGetPublicKey());
  await runTest('Create Lease with Wrong Credentials', () => suite.testIssueJWTWithWrongCredentials());
  await runTest('Concurrent JWT Issuance (Stashing)', () => suite.testConcurrentJWTIssuance());

  // Group 3: Audit Chain
  logSection('Group 3: Audit Chain Integrity');
  await runTest('Audit Chain Verification', () => suite.testAuditChainVerification());

  // Group 4: Performance
  logSection('Group 4: Performance Benchmarks');
  await runTest('Performance: VAPID Generation', () => suite.testPerformanceVAPIDGeneration());
  await runTest('Performance: JWT Issuance', () => suite.testPerformanceJWTIssuance());
  await runTest('Performance: Setup Passphrase', () => suite.testPerformanceSetupPassphrase());

  // ONE-TIME TEARDOWN
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

  // Add reset button
  const resetButton = document.getElementById('reset-demo');
  if (resetButton) {
    resetButton.addEventListener('click', async () => {
      const confirmed = confirm(
        '⚠️ This will delete all KMS data and reload the page.\n\n' +
        'This will trigger KIAK initialization event.\n\n' +
        'Continue?'
      );

      if (!confirmed) return;

      try {
        // Create temporary KMSUser instance to call resetKMS
        const tempKMS = new KMSUser({ kmsOrigin: KMS_ORIGIN });
        await tempKMS.init();

        // Call resetKMS but don't wait for response (it will timeout because DB is deleted)
        // Just reload after a short delay to ensure the message is sent
        tempKMS.resetKMS().catch(() => {
          // Ignore errors - the database deletion breaks the response channel
        });

        // Reload page after short delay - worker will initialize and log KIAK event
        setTimeout(() => {
          window.location.reload();
        }, 500);
      } catch (error) {
        alert(`Reset failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    });
  }

  console.log('[Integration Tests] Ready - click "Run Tests" to begin');
});
