const js = require('@eslint/js');
const globals = require('globals');

// Shared no-unused-vars policy: allow intentional throwaway bindings named _.
const noUnused = ['error', {
  argsIgnorePattern: '^_',
  varsIgnorePattern: '^_',
  caughtErrors: 'all',
  caughtErrorsIgnorePattern: '^_',
}];

// Allow empty catch blocks (e.g. best-effort localStorage writes).
const sharedRules = {
  'no-unused-vars': noUnused,
  'no-empty': ['error', { allowEmptyCatch: true }],
};

module.exports = [
  js.configs.recommended,
  {
    // Node backend (CommonJS modules).
    files: ['src/**/*.js'],
    ignores: ['src/public/**'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'commonjs',
      globals: { ...globals.node },
    },
    rules: sharedRules,
  },
  {
    // Browser frontend served from src/public.
    files: ['src/public/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'script',
      globals: {
        ...globals.browser,
        // Loaded from CDN <script> tags in index.html, not bundled.
        cytoscape: 'readonly',
        Chart: 'readonly',
        // Pure helper module loaded via its own <script> before app.js.
        HostSearch: 'readonly',
        // host-search.js is dual browser/node (module.exports fallback).
        module: 'readonly',
      },
    },
    rules: sharedRules,
  },
  {
    // node:test suite over the pure scanner helpers (CommonJS, Node).
    files: ['test/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'commonjs',
      globals: { ...globals.node },
    },
    rules: sharedRules,
  },
];
