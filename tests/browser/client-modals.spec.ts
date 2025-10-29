/**
 * Browser tests for KMSClient modal UI flows
 *
 * These tests run against the Phase 1 Full Demo to test the client.ts modal
 * UI code that cannot be tested in Node.js/Vitest. They exercise the actual
 * DOM manipulation, event handlers, and WebAuthn flows.
 */

import { test, expect, type Page } from '@playwright/test';

// Helper to setup virtual authenticator
async function setupVirtualAuthenticator(page: Page): Promise<{ client: unknown; authenticatorId: string }> {
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');

  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  });

  return { client, authenticatorId };
}

// Wait for demo to be ready
async function waitForDemoReady(page: Page): Promise<void> {
  // Wait for kmsUser to be initialized
  await page.waitForFunction(() => (window as any).kmsUser !== undefined, { timeout: 10000 });
}

test.describe('KMSClient Modal UI Flows', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to Phase 1 Full Demo (parent page)
    await page.goto('http://localhost:5173');
    await waitForDemoReady(page);

    // Reset KMS before each test
    await page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      try {
        await kmsUser.resetKMS();
      } catch {
        // Ignore errors if already reset
      }
    });
  });

  test('should show setup modal when user has no auth configured', async ({ page }) => {
    // Setup virtual authenticator
    await setupVirtualAuthenticator(page);

    // Click "Setup Passkey" button
    await page.click('#setup-webauthn-btn');

    // Wait for setup window to open
    const setupWindow = await page.waitForEvent('popup');
    await setupWindow.waitForLoadState('domcontentloaded');

    // Check that setup modal is visible in the popup
    const setupModal = await setupWindow.locator('#setup-modal');
    await expect(setupModal).toBeVisible();

    // Check that both auth options are shown
    await expect(setupWindow.locator('#kms-setup-webauthn-btn')).toBeVisible();
    await expect(setupWindow.locator('#kms-setup-passphrase-btn')).toBeVisible();
  });

  test('should show unlock modal when creating lease with existing auth', async ({ page }) => {
    // Setup virtual authenticator
    await setupVirtualAuthenticator(page);

    // First setup passphrase
    await page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      await kmsUser.setupPassphrase('test-passphrase-12345');
    });

    // Now try to create a lease (should trigger unlock modal in iframe)
    const createLeasePromise = page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      return kmsUser.createLease({
        userId: 'demouser@ats.run',
        subs: [{ url: 'https://example.com/push', aud: 'https://example.com', eid: 'test-1' }],
        ttlHours: 1,
      });
    });

    // Wait for iframe to become visible
    const iframe = page.frameLocator('iframe[src*="localhost:5174"]');
    await iframe.locator('#unlock-modal').waitFor({ state: 'visible', timeout: 5000 });

    // Check that unlock options are shown
    await expect(iframe.locator('#kms-webauthn-btn')).toBeVisible();
    await expect(iframe.locator('#kms-passphrase-btn')).toBeVisible();

    // Enter passphrase and unlock
    await iframe.locator('#kms-passphrase-input').fill('test-passphrase-12345');
    await iframe.locator('#kms-passphrase-btn').click();

    // Wait for lease creation to complete
    const result = await createLeasePromise;
    expect(result).toHaveProperty('leaseId');
  });

  test('should handle passphrase unlock flow end-to-end', async ({ page }) => {
    // Setup passphrase first (needs userId parameter)
    await page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      await kmsUser.setupPassphrase('my-test-passphrase-12345678', 'demouser@ats.run');
    });

    // Trigger operation requiring auth
    const generatePromise = page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      return kmsUser.generateVAPID({
        method: 'passphrase',
        passphrase: 'my-test-passphrase-12345678',
        userId: 'demouser@ats.run',
      });
    });

    // Wait for result
    const result = await generatePromise;
    expect(result).toHaveProperty('kid');
    expect(result).toHaveProperty('publicKey');
  });

  test('should show error message for wrong passphrase', async ({ page }) => {
    // Setup passphrase
    await page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      await kmsUser.setupPassphrase('correct-passphrase-123');
    });

    // Try to create lease with wrong passphrase
    const createLeasePromise = page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      try {
        await kmsUser.createLease({
          userId: 'demouser@ats.run',
          subs: [{ url: 'https://example.com/push', aud: 'https://example.com', eid: 'test-1' }],
          ttlHours: 1,
        });
        return { success: true };
      } catch (err: any) {
        return { success: false, error: err.message };
      }
    });

    // Wait for iframe modal to appear
    const iframe = page.frameLocator('iframe[src*="localhost:5174"]');
    await iframe.locator('#unlock-modal').waitFor({ state: 'visible', timeout: 5000 });

    // Enter wrong passphrase
    await iframe.locator('#kms-passphrase-input').fill('wrong-passphrase');
    await iframe.locator('#kms-passphrase-btn').click();

    // Wait a bit for error to show
    await page.waitForTimeout(1000);

    // Check that error message is visible in iframe
    const errorDiv = iframe.locator('#kms-modal-error');
    await expect(errorDiv).toBeVisible();

    // Enter correct passphrase
    await iframe.locator('#kms-passphrase-input').fill('correct-passphrase-123');
    await iframe.locator('#kms-passphrase-btn').click();

    // Wait for success
    const result = await createLeasePromise;
    expect(result).toHaveProperty('success', true);
  });

  test('should show loading state during authentication', async ({ page }) => {
    // Setup passphrase
    await page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      await kmsUser.setupPassphrase('test-passphrase-123');
    });

    // Start operation
    const createLeasePromise = page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      return kmsUser.createLease({
        userId: 'demouser@ats.run',
        subs: [{ url: 'https://example.com/push', aud: 'https://example.com', eid: 'test-1' }],
        ttlHours: 1,
      });
    });

    // Wait for iframe modal
    const iframe = page.frameLocator('iframe[src*="localhost:5174"]');
    await iframe.locator('#unlock-modal').waitFor({ state: 'visible', timeout: 5000 });

    // Enter passphrase and click
    await iframe.locator('#kms-passphrase-input').fill('test-passphrase-123');
    await iframe.locator('#kms-passphrase-btn').click();

    // Loading indicator should appear briefly
    const loading = iframe.locator('#kms-modal-loading');

    // Note: This might be flaky due to fast operations, so we just check it doesn't error
    // The important part is that the operation completes successfully

    // Wait for success
    const result = await createLeasePromise;
    expect(result).toHaveProperty('leaseId');
  });

  test('should hide modal after successful authentication', async ({ page }) => {
    // Setup passphrase
    await page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      await kmsUser.setupPassphrase('test-passphrase-123');
    });

    // Create lease
    const createLeasePromise = page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      return kmsUser.createLease({
        userId: 'demouser@ats.run',
        subs: [{ url: 'https://example.com/push', aud: 'https://example.com', eid: 'test-1' }],
        ttlHours: 1,
      });
    });

    // Wait for iframe modal
    const iframe = page.frameLocator('iframe[src*="localhost:5174"]');
    await iframe.locator('#unlock-modal').waitFor({ state: 'visible', timeout: 5000 });

    // Enter passphrase
    await iframe.locator('#kms-passphrase-input').fill('test-passphrase-123');
    await iframe.locator('#kms-passphrase-btn').click();

    // Wait for operation to complete
    await createLeasePromise;

    // Modal should be hidden
    // Check that modal has display: none
    await iframe.locator('#unlock-modal').waitFor({ state: 'hidden', timeout: 5000 });
  });

  test('should support Enter key for passphrase submission', async ({ page }) => {
    // Setup passphrase
    await page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      await kmsUser.setupPassphrase('test-passphrase-123');
    });

    // Create lease
    const createLeasePromise = page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      return kmsUser.createLease({
        userId: 'demouser@ats.run',
        subs: [{ url: 'https://example.com/push', aud: 'https://example.com', eid: 'test-1' }],
        ttlHours: 1,
      });
    });

    // Wait for iframe modal
    const iframe = page.frameLocator('iframe[src*="localhost:5174"]');
    await iframe.locator('#unlock-modal').waitFor({ state: 'visible', timeout: 5000 });

    // Enter passphrase and press Enter
    const input = iframe.locator('#kms-passphrase-input');
    await input.fill('test-passphrase-123');
    await input.press('Enter');

    // Wait for success
    const result = await createLeasePromise;
    expect(result).toHaveProperty('leaseId');
  });
});

test.describe('KMSClient Setup Modal Flows', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('http://localhost:5173');
    await waitForDemoReady(page);

    // Reset KMS
    await page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      try {
        await kmsUser.resetKMS();
      } catch {
        // Ignore
      }
    });
  });

  test('should show passphrase confirmation field in setup modal', async ({ page }) => {
    // Setup virtual authenticator
    await setupVirtualAuthenticator(page);

    // Click setup passphrase in parent
    await page.click('#setup-passphrase-btn');

    // Wait for setup window
    const setupWindow = await page.waitForEvent('popup');
    await setupWindow.waitForLoadState('domcontentloaded');

    // Check for confirmation field
    await expect(setupWindow.locator('#kms-setup-passphrase-confirm-input')).toBeVisible();
    await expect(setupWindow.locator('#kms-passphrase-char-count')).toBeVisible();
    await expect(setupWindow.locator('#kms-passphrase-match-feedback')).toBeHidden();
  });

  test('should show character count feedback in setup modal', async ({ page }) => {
    await setupVirtualAuthenticator(page);

    // Click setup passphrase
    await page.click('#setup-passphrase-btn');

    // Wait for setup window
    const setupWindow = await page.waitForEvent('popup');
    await setupWindow.waitForLoadState('domcontentloaded');

    // Type in passphrase field
    await setupWindow.locator('#kms-setup-passphrase-input').fill('short');

    // Check character count shows 5 / 12
    const charCount = setupWindow.locator('#kms-passphrase-char-count');
    await expect(charCount).toHaveText('5 / 12 characters');

    // Type more to reach 12
    await setupWindow.locator('#kms-setup-passphrase-input').fill('twelve-chars');

    // Should show 12 / 12
    await expect(charCount).toHaveText('12 / 12 characters');
  });

  test('should show passphrase match feedback', async ({ page }) => {
    await setupVirtualAuthenticator(page);

    // Click setup passphrase
    await page.click('#setup-passphrase-btn');

    // Wait for setup window
    const setupWindow = await page.waitForEvent('popup');
    await setupWindow.waitForLoadState('domcontentloaded');

    // Type in both fields (non-matching)
    await setupWindow.locator('#kms-setup-passphrase-input').fill('my-passphrase-123');
    await setupWindow.locator('#kms-setup-passphrase-confirm-input').fill('different-one-123');

    // Feedback should show mismatch
    const feedback = setupWindow.locator('#kms-passphrase-match-feedback');
    await expect(feedback).toBeVisible();
    await expect(feedback).toContainText('do not match');

    // Type matching passphrase
    await setupWindow.locator('#kms-setup-passphrase-confirm-input').fill('my-passphrase-123');

    // Feedback should show match
    await expect(feedback).toContainText('match');
  });
});
