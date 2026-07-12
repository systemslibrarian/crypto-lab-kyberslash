import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Unit tests live in src/. The Playwright a11y suite under e2e/ must never
    // be collected by Vitest (it uses @playwright/test, not vitest).
    include: ['src/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
