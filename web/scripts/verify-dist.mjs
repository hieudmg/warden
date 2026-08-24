#!/usr/bin/env node
//
// Verifies a Vite production distribution before it is embedded into the
// Go binary:
//   - every manifest entry (file, css, assets) exists on disk
//   - every manifest import/dynamicImport key resolves to another entry
//   - index.html and css files reference no external (http/https or
//     protocol-relative) URLs, so the served UI is fully self-contained
//
// Usage: node scripts/verify-dist.mjs <dist-root>

import { access, readFile } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

export async function verifyDist(root) {
  const manifestPath = path.join(root, ".vite", "manifest.json")
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"))

  const emitted = new Set()
  const cssFiles = new Set()
  for (const [key, entry] of Object.entries(manifest)) {
    if (entry.file) emitted.add(entry.file)
    for (const file of entry.css ?? []) {
      emitted.add(file)
      cssFiles.add(file)
    }
    for (const file of entry.assets ?? []) emitted.add(file)
    for (const imported of [...(entry.imports ?? []), ...(entry.dynamicImports ?? [])]) {
      if (!manifest[imported]) {
        throw new Error(`manifest import missing: ${key} -> ${imported}`)
      }
    }
  }

  for (const file of emitted) {
    await access(path.join(root, file))
  }

  await rejectExternalReferences(root, cssFiles)
}

async function rejectExternalReferences(root, cssFiles) {
  const html = await readFile(path.join(root, "index.html"), "utf8")
  for (const ref of extractHtmlReferences(html)) {
    assertLocalReference("index.html", ref)
  }
  for (const cssFile of cssFiles) {
    const css = await readFile(path.join(root, cssFile), "utf8")
    for (const ref of extractCssReferences(css)) {
      assertLocalReference(cssFile, ref)
    }
  }
}

function extractHtmlReferences(html) {
  const refs = []
  const pattern = /\b(?:src|href)\s*=\s*["']([^"']+)["']/gi
  let match
  while ((match = pattern.exec(html)) !== null) {
    refs.push(match[1])
  }
  return refs
}

function extractCssReferences(css) {
  const refs = []
  const pattern = /url\(\s*["']?([^"')]+)["']?\s*\)/g
  let match
  while ((match = pattern.exec(css)) !== null) {
    refs.push(match[1])
  }
  return refs
}

function assertLocalReference(source, ref) {
  // data:, blob:, root-relative, and relative references are local. The
  // release binary must never reach beyond its own embedded assets, so
  // http(s) schemes and protocol-relative URLs are rejected.
  if (/^https?:/i.test(ref) || ref.startsWith("//")) {
    throw new Error(`external reference in ${source}: ${ref}`)
  }
}

const isEntry = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)

if (isEntry) {
  const root = process.argv[2]
  if (!root) {
    console.error("usage: node scripts/verify-dist.mjs <dist-root>")
    process.exit(2)
  }
  verifyDist(root).then(
    () => console.log(`verify-dist: ok (${root})`),
    (error) => {
      console.error(`verify-dist: ${error.message}`)
      process.exit(1)
    },
  )
}
