import path from "node:path"
import { fileURLToPath } from "node:url"
import { defineConfig } from "vitest/config"

const root = fileURLToPath(new URL(".", import.meta.url))

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(root, "./src"),
    },
  },
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
