import { defineConfig } from 'vitest/config';

// Browser-side regression tests for public/app.js. These run in plain Node
// (no Cloudflare workerd plugin): app.js is a browser IIFE executed against
// hand-rolled DOM/WebSocket/fetch adapters with vitest fake timers.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/app/**/*.test.ts'],
  },
});
