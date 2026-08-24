#!/usr/bin/env bash
#
# Reproducible release builds for Warden Hub.
#
# Outputs into dist/:
#   dist/warden-server-linux-amd64   Linux server
#   dist/warden-linux-amd64          Linux client
#   dist/warden.exe                  Windows amd64 client
#
# Uses -trimpath and CGO_ENABLED=0 so builds are deterministic for a given
# Go toolchain, then prints SHA-256 checksums for every artifact.
#
# Usage: bash scripts/build-release.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
LDFLAGS="-s -w"

log() { printf '== %s\n' "$*"; }

cd "$ROOT"

# The server binary embeds the generated UI, so the frontend must be
# built before the release compilation below.
log "building frontend"
npm --prefix "$ROOT/web" ci
npm --prefix "$ROOT/web" test
npm --prefix "$ROOT/web" run build

log "building release artifacts into $DIST"
rm -rf "$DIST"
mkdir -p "$DIST"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "$LDFLAGS" \
  -o "$DIST/warden-server-linux-amd64" ./cmd/warden-server

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "$LDFLAGS" \
  -o "$DIST/warden-linux-amd64" ./cmd/warden

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags "$LDFLAGS" \
  -o "$DIST/warden.exe" ./cmd/warden

log "artifacts:"
(
  cd "$DIST"
  ls -la
  sha256sum ./* | tee SHA256SUMS
)
log "release complete"
