import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright configuration for browser-based KMS enclave tests
 *
 * These tests run in a real browser environment with WebAuthn virtual authenticator
 * to test the client.ts passkey flows that cannot be tested in Node.js/Vitest.
 */
export default defineConfig({
  testDir: './tests/browser',

  // Maximum time one test can run
  timeout: 30 * 1000,

  // Run tests in files in parallel
  fullyParallel: true,

  // Fail the build on CI if you accidentally left test.only
  forbidOnly: !!process.env.CI,

  // Retry on CI only
  retries: process.env.CI ? 2 : 0,

  // Reporter to use
  reporter: [
    ['list'],
    ['html', { open: 'never' }],
  ],

  // Shared settings for all projects
  use: {
    // Base URL for tests
    baseURL: 'http://localhost:5173',

    // Collect trace when retrying the failed test
    trace: 'on-first-retry',

    // Screenshot on failure
    screenshot: 'only-on-failure',
  },

  // Configure projects for different browsers
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
      },
    },
  ],

  // Web server for development
  webServer: {
    command: 'pnpm exec vite --port 5173',
    port: 5173,
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000,
  },
});
