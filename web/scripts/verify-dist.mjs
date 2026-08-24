#!/usr/bin/env node
//
// Verifies a Vite production distribution before it is embedded into the
// Go binary:
//   - the import/dynamicImport graph is walked recursively from the entry
//     points with a visited set (cyclic graphs cannot loop forever) and
//     every edge must resolve to a manifest entry
//   - every manifest entry's file, css, and assets exist on disk
//   - index.html and css files reference no external (http/https or
//     protocol-relative) URLs, so the served UI is fully self-contained
//
// Error messages name the offending manifest key or emitted file but never
// print source contents. Exit codes: 0 ok, 1 verification failure,
// 2 usage error.
//
// Usage: node scripts/verify-dist.mjs <dist-root>

import { readFile, stat } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

export async function verifyDist(root) {
  const manifestPath = path.join(root, ".vite", "manifest.json")
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"))

  const emitted = new Set()
  const cssFiles = new Set()
  const visited = new Set()

  const collect = (entry) => {
    if (entry.file) emitted.add(entry.file)
    for (const file of entry.css ?? []) {
      emitted.add(file)
      cssFiles.add(file)
    }
    for (const file of entry.assets ?? []) emitted.add(file)
  }

  // Recursive walk from the declared entry points. A manifest without
  // isEntry markers (older Vite output or minimal test fixtures) is walked
  // in full.
  const queue = Object.keys(manifest).filter((key) => manifest[key].isEntry === true)
  if (queue.length === 0) queue.push(...Object.keys(manifest))

  while (queue.length > 0) {
    const key = queue.pop()
    if (visited.has(key)) continue
    visited.add(key)
    const entry = manifest[key]
    collect(entry)
    for (const imported of [...(entry.imports ?? []), ...(entry.dynamicImports ?? [])]) {
      if (!manifest[imported]) {
        throw new Error(`manifest import missing: ${key} -> ${imported}`)
      }
      queue.push(imported)
    }
  }

  // Entries the graph never reaches (Vite can emit unused chunks) are
  // still part of the distribution and must exist.
  for (const key of Object.keys(manifest)) {
    if (visited.has(key)) continue
    const entry = manifest[key]
    collect(entry)
    for (const imported of [...(entry.imports ?? []), ...(entry.dynamicImports ?? [])]) {
      if (!manifest[imported]) {
        throw new Error(`manifest import missing: ${key} -> ${imported}`)
      }
    }
  }

  for (const file of emitted) {
    await assertFileExists(root, file)
  }

  await rejectExternalReferences(root, cssFiles)
}

async function assertFileExists(root, file) {
  try {
    const info = await stat(path.join(root, file))
    if (!info.isFile()) throw new Error("not a file")
  } catch {
    throw new Error(`missing emitted file: ${file}`)
  }
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
