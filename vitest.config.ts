import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Environment
    environment: 'happy-dom',

    // Setup file
    setupFiles: ['./tests/setup.ts'],

    // Coverage
    coverage: {
      provider: 'v8',
      reporter: ['json', 'json-summary', 'html', 'lcov'],
      all: true,
      include: ['src/v2/**/*.ts'],
      exclude: [
        'node_modules/**',
        'tests/**',
        'build/**',
        'dist/**',
        '**/*.d.ts',
        '**/*.config.*',
      ],
      // 80% coverage required for V2
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80,
      },
    },

    // Global setup
    globals: true,

    // Test files (V2 only)
    // Excludes: tests/unit/** (v1), tests/prototype/** (old prototypes)
    include: ['tests/v2/**/*.test.ts'],

    // Timeout
    testTimeout: 10000,
  },

  resolve: {
    alias: {
      '@': '/src',
    },
  },
});
