/**
 * Playwright tests for client.ts UI code coverage
 *
 * These tests exercise the DOM manipulation and event handling code in client.ts
 * that cannot be tested in Node.js/Vitest. The goal is to increase test coverage
 * by running real browser interactions.
 */

import { test, expect, type Page } from '@playwright/test';

// Helper to setup virtual authenticator
async function setupVirtualAuthenticator(page: Page): Promise<void> {
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  });
}

// Wait for demo to be ready
async function waitForDemoReady(page: Page): Promise<void> {
  await page.waitForFunction(() => (window as any).kmsUser !== undefined, { timeout: 10000 });
}

test.describe('Client.ts UI Coverage Tests', () => {
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

  test('should show and interact with passphrase setup modal', async ({ page }) => {
    await setupVirtualAuthenticator(page);

    // Click setup passphrase button in parent
    await page.click('#setup-passphrase-btn');

    // Wait for setup window (new tab)
    const setupWindow = await page.waitForEvent('popup', { timeout: 5000 });
    await setupWindow.waitForLoadState('domcontentloaded');

    // Check modal is visible
    const setupModal = setupWindow.locator('#setup-modal');
    await expect(setupModal).toBeVisible();

    // Check passphrase input fields exist
    await expect(setupWindow.locator('#kms-setup-passphrase-input')).toBeVisible();
    await expect(setupWindow.locator('#kms-setup-passphrase-confirm-input')).toBeVisible();
    await expect(setupWindow.locator('#kms-setup-passphrase-btn')).toBeVisible();

    // Test character count updates
    await setupWindow.locator('#kms-setup-passphrase-input').fill('test12');
    const charCount = setupWindow.locator('#kms-passphrase-char-count');
    await expect(charCount).toContainText('6 / 12');

    // Type in confirmation field
    await setupWindow.locator('#kms-setup-passphrase-confirm-input').fill('different');

    // Match feedback should appear
    const feedback = setupWindow.locator('#kms-passphrase-match-feedback');
    await expect(feedback).toBeVisible();
    await expect(feedback).toContainText('do not match');

    // Type matching passphrase
    await setupWindow.locator('#kms-setup-passphrase-confirm-input').fill('test12');
    await expect(feedback).toContainText('match');
  });

  test('should show unlock modal when operation requires auth', async ({ page }) => {
    // Setup passphrase first using parent window (correct parameter order: userId, passphrase)
    await page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      await kmsUser.setupPassphrase('demouser@ats.run', 'test-passphrase-12345678');
    });

    // Wait a moment for setup to complete
    await page.waitForTimeout(500);

    // Trigger createLease which should show unlock modal in iframe
    const createLeasePromise = page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      return kmsUser.createLease({
        userId: 'demouser@ats.run',
        subs: [{ url: 'https://example.com/push', aud: 'https://example.com', eid: 'test-1' }],
        ttlHours: 1,
      });
    });

    // Wait for iframe to show modal
    const iframe = page.frameLocator('iframe[src*="localhost:5174"]');

    // Check unlock modal is visible
    await iframe.locator('#unlock-modal').waitFor({ state: 'visible', timeout: 5000 });

    // Check auth buttons are visible
    await expect(iframe.locator('#kms-webauthn-btn')).toBeVisible();
    await expect(iframe.locator('#kms-passphrase-btn')).toBeVisible();
    await expect(iframe.locator('#kms-passphrase-input')).toBeVisible();

    // Enter passphrase and submit
    await iframe.locator('#kms-passphrase-input').fill('test-passphrase-12345678');
    await iframe.locator('#kms-passphrase-btn').click();

    // Wait for operation to complete
    const result = await createLeasePromise;
    expect(result).toHaveProperty('leaseId');

    // Modal should hide
    await iframe.locator('#unlock-modal').waitFor({ state: 'hidden', timeout: 5000 });
  });

  test('should support Enter key in passphrase input', async ({ page }) => {
    await page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      await kmsUser.setupPassphrase('demouser@ats.run', 'enter-key-test-12345678');
    });

    await page.waitForTimeout(500);

    const createLeasePromise = page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      return kmsUser.createLease({
        userId: 'demouser@ats.run',
        subs: [{ url: 'https://example.com/push', aud: 'https://example.com', eid: 'test-1' }],
        ttlHours: 1,
      });
    });

    const iframe = page.frameLocator('iframe[src*="localhost:5174"]');
    await iframe.locator('#unlock-modal').waitFor({ state: 'visible', timeout: 5000 });

    // Type passphrase and press Enter
    const input = iframe.locator('#kms-passphrase-input');
    await input.fill('enter-key-test-12345678');
    await input.press('Enter');

    // Should complete successfully
    const result = await createLeasePromise;
    expect(result).toHaveProperty('leaseId');
  });

  test.skip('should show error for wrong passphrase', async ({ page }) => {
    await page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      await kmsUser.setupPassphrase('demouser@ats.run', 'correct-pass-12345678');
    });

    await page.waitForTimeout(500);

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

    const iframe = page.frameLocator('iframe[src*="localhost:5174"]');
    await iframe.locator('#unlock-modal').waitFor({ state: 'visible', timeout: 5000 });

    // Enter wrong passphrase
    await iframe.locator('#kms-passphrase-input').fill('wrong-passphrase');
    await iframe.locator('#kms-passphrase-btn').click();

    // Wait for error to appear
    await page.waitForTimeout(1000);
    const errorDiv = iframe.locator('#kms-modal-error');
    await expect(errorDiv).toBeVisible();

    // Enter correct passphrase
    await iframe.locator('#kms-passphrase-input').fill('correct-pass-12345678');
    await iframe.locator('#kms-passphrase-btn').click();

    // Should succeed
    const result = await createLeasePromise;
    expect(result.success).toBe(true);
  });

  test('should handle setupWebAuthn button click', async ({ page }) => {
    await setupVirtualAuthenticator(page);

    // Click setup webauthn button
    await page.click('#setup-webauthn-btn');

    // Setup window should open
    const setupWindow = await page.waitForEvent('popup', { timeout: 5000 });
    await setupWindow.waitForLoadState('domcontentloaded');

    // Check setup modal shows WebAuthn button
    await expect(setupWindow.locator('#kms-setup-webauthn-btn')).toBeVisible();
  });

  test('should handle modal showing and hiding', async ({ page }) => {
    await page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      await kmsUser.setupPassphrase('demouser@ats.run', 'modal-test-12345678');
    });

    await page.waitForTimeout(500);

    // Start operation
    const promise = page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      return kmsUser.createLease({
        userId: 'demouser@ats.run',
        subs: [{ url: 'https://example.com/push', aud: 'https://example.com', eid: 'test-1' }],
        ttlHours: 1,
      });
    });

    const iframe = page.frameLocator('iframe[src*="localhost:5174"]');

    // Modal should show
    await iframe.locator('#unlock-modal').waitFor({ state: 'visible', timeout: 5000 });

    // Complete auth
    await iframe.locator('#kms-passphrase-input').fill('modal-test-12345678');
    await iframe.locator('#kms-passphrase-btn').click();

    await promise;

    // Modal should hide
    await iframe.locator('#unlock-modal').waitFor({ state: 'hidden', timeout: 5000 });
  });

  test('should show multi-enrollment unlock UI when adding second authentication method', async ({ page }) => {
    await setupVirtualAuthenticator(page);

    // First, setup with passphrase
    await page.click('[data-action="setup-passphrase"]');
    await page.waitForTimeout(500);

    const iframe = page.frameLocator('iframe[src*="localhost:5174"]');

    // Fill in passphrase
    await iframe.locator('#kms-setup-passphrase-input').fill('test-passphrase-12345');
    await iframe.locator('#kms-setup-passphrase-confirm-input').fill('test-passphrase-12345');
    await iframe.locator('#kms-setup-passphrase-btn').click();

    // Wait for success
    await iframe.locator('#kms-setup-success').waitFor({ state: 'visible', timeout: 5000 });

    // Now try to add a second enrollment (passkey)
    await page.evaluate(async () => {
      const kmsUser = (window as any).kmsUser;
      return kmsUser.addEnrollment('test@example.com', 'passkey-prf');
    });

    await page.waitForTimeout(500);

    // Should show multi-enrollment unlock instructions
    const unlockInstructions = iframe.locator('#multi-enrollment-unlock');
    await expect(unlockInstructions).toBeVisible();
    await expect(unlockInstructions).toContainText('Multi-Enrollment Authentication Required');

    // Should show passphrase unlock option since we set up passphrase first
    const passphraseUnlock = iframe.locator('#temp-passphrase-unlock');
    await expect(passphraseUnlock).toBeVisible();

    const passphraseInput = iframe.locator('#temp-passphrase-input');
    await expect(passphraseInput).toBeVisible();

    // Enter passphrase to unlock
    await passphraseInput.fill('test-passphrase-12345');
    await iframe.locator('#temp-passphrase-btn').click();

    // Wait for WebAuthn prompt (would happen after successful unlock)
    await page.waitForTimeout(1000);
  });
});
