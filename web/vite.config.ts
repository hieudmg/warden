import path from "node:path"
import { fileURLToPath } from "node:url"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

const root = fileURLToPath(new URL(".", import.meta.url))

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(root, "./src") } },
  build: {
    outDir: path.resolve(root, "../internal/web/dist"),
    emptyOutDir: true,
    manifest: true,
    sourcemap: false,
  },
})
