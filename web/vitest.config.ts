import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    restoreMocks: true,
    globals: true,
    // scripts/*.test.mjs are node:test suites run via `node --test` in the
    // test script; Vitest must not try to discover them.
    exclude: ["**/node_modules/**", "**/dist/**", "**/scripts/**"],
  },
})
