import assert from "node:assert/strict"
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { test } from "node:test"

import { verifyDist } from "./verify-dist.mjs"

// fixture builds a temporary distribution directory from a map of
// relative paths to file contents and returns its root.
async function fixture(files) {
  const root = await mkdtemp(path.join(os.tmpdir(), "verify-dist-"))
  for (const [name, content] of Object.entries(files)) {
    const full = path.join(root, name)
    await mkdir(path.dirname(full), { recursive: true })
    await writeFile(full, content)
  }
  return root
}

test("complete local graph passes", async () => {
  const root = await fixture({
    ".vite/manifest.json": JSON.stringify({
      "index.html": {
        file: "index.html",
        isEntry: true,
        css: ["assets/app-a1.css"],
        imports: ["src/main.tsx"],
      },
      "src/main.tsx": { file: "assets/app-a1.js" },
    }),
    "index.html":
      '<html><script type="module" crossorigin src="/assets/app-a1.js"></script>' +
      '<link rel="stylesheet" crossorigin href="/assets/app-a1.css"></html>',
    "assets/app-a1.js": 'console.log("warden")',
    "assets/app-a1.css": ":root{color-scheme:light}",
  })
  await verifyDist(root)
  await rm(root, { recursive: true, force: true })
})

test("rejects external https script in index.html", async () => {
  const root = await fixture({
    ".vite/manifest.json": JSON.stringify({ "index.html": { file: "index.html" } }),
    "index.html": '<html><script type="module" src="https://cdn.example/app.js"></script></html>',
  })
  await assert.rejects(() => verifyDist(root), /cdn\.example/)
  await rm(root, { recursive: true, force: true })
})

test("rejects protocol-relative stylesheet in index.html", async () => {
  const root = await fixture({
    ".vite/manifest.json": JSON.stringify({ "index.html": { file: "index.html" } }),
    "index.html": '<html><link rel="stylesheet" href="//cdn.example/app.css"></html>',
  })
  await assert.rejects(() => verifyDist(root), /cdn\.example/)
  await rm(root, { recursive: true, force: true })
})

test("rejects manifest import that is not in the manifest", async () => {
  const root = await fixture({
    ".vite/manifest.json": JSON.stringify({
      "index.html": { file: "index.html", imports: ["src/main.tsx"] },
      "src/main.tsx": { file: "assets/app-a1.js", imports: ["src/missing.tsx"] },
    }),
    "index.html": '<html><script type="module" src="/assets/app-a1.js"></script></html>',
    "assets/app-a1.js": 'console.log("warden")',
  })
  await assert.rejects(() => verifyDist(root), /manifest import missing/)
  await rm(root, { recursive: true, force: true })
})

test("rejects emitted file that is missing on disk", async () => {
  const root = await fixture({
    ".vite/manifest.json": JSON.stringify({ "src/main.tsx": { file: "assets/app-a1.js" } }),
    "index.html": '<html><script type="module" src="/assets/app-a1.js"></script></html>',
  })
  await assert.rejects(() => verifyDist(root), /app-a1\.js/)
  await rm(root, { recursive: true, force: true })
})

test("rejects external url() reference in css", async () => {
  const root = await fixture({
    ".vite/manifest.json": JSON.stringify({
      "index.html": { file: "index.html", css: ["assets/app-a1.css"] },
    }),
    "index.html": '<html><link rel="stylesheet" href="/assets/app-a1.css"></html>',
    "assets/app-a1.css":
      "@font-face{font-family:X;src:url(https://fonts.example/x.woff2) format('woff2')}",
  })
  await assert.rejects(() => verifyDist(root), /fonts\.example/)
  await rm(root, { recursive: true, force: true })
})

test("allows data: and relative url() references in css", async () => {
  const root = await fixture({
    ".vite/manifest.json": JSON.stringify({
      "index.html": { file: "index.html", css: ["assets/app-a1.css"] },
    }),
    "index.html": '<html><link rel="stylesheet" href="/assets/app-a1.css"></html>',
    "assets/app-a1.css":
      ".a{background:url(data:image/png;base64,AAAA)}" +
      ".b{src:url(./font.woff2) format('woff2')}",
  })
  await verifyDist(root)
  await rm(root, { recursive: true, force: true })
})
