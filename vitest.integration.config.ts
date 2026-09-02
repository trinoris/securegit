import { defineConfig } from 'vitest/config';

// Integration tests drive a real `git` binary against throwaway repositories.
// Slower, and separated so `npm test` stays fast — not because they are optional.
export default defineConfig({
  test: {
    include: ['src/**/*.integration.test.ts'],
    exclude: ['**/node_modules/**', 'dist/**'],
    testTimeout: 30_000,
  },
});
