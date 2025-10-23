import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Environment
    environment: 'happy-dom',

    // Coverage
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      all: true,
      include: ['src/**/*.ts'],
      exclude: [
        'node_modules/**',
        'tests/**',
        'build/**',
        'dist/**',
        '**/*.d.ts',
        '**/*.config.*',
      ],
      // 100% coverage required
      thresholds: {
        lines: 100,
        functions: 100,
        branches: 100,
        statements: 100,
      },
    },

    // Global setup
    globals: true,

    // Test files
    include: ['tests/**/*.test.ts'],

    // Timeout
    testTimeout: 10000,
  },

  resolve: {
    alias: {
      '@': '/src',
    },
  },
});
