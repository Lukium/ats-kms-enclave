import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
      globals: {
        // Browser
        window: 'readonly',
        document: 'readonly',
        navigator: 'readonly',
        console: 'readonly',
        fetch: 'readonly',
        crypto: 'readonly',
        atob: 'readonly',
        btoa: 'readonly',
        // Node
        process: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        // Worker
        self: 'readonly',
        importScripts: 'readonly',
        // Web APIs
        MessageEvent: 'readonly',
        ErrorEvent: 'readonly',
        Worker: 'readonly',
        EventTarget: 'readonly',
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/explicit-function-return-type': 'warn',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-floating-promises': 'error',
      'no-console': ['warn', { allow: ['warn', 'error'] }],
    },
  },
  {
    ignores: [
      'node_modules/**',
      'dist/**',
      'coverage/**',
      'build/**',
      'example/**',
      '*.config.ts',
      '*.config.js',
      '**/*.d.ts',
    ],
  }
);
