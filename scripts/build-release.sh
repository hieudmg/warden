#!/usr/bin/env bash
#
# Reproducible release builds for Warden Hub.
#
# Outputs into dist/:
#   dist/warden-server-linux-amd64   Linux server
#   dist/warden-linux-amd64          Linux client
#   dist/warden.exe                  Windows amd64 client
#
# Uses the exact minimum Go patch, -trimpath and CGO_ENABLED=0, then emits
# SHA256SUMS over the individual release bytes (never executes target binaries).
#
# Usage: bash scripts/build-release.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
LDFLAGS="-s -w"

log() { printf '== %s\n' "$*"; }

cd "$ROOT"

# Reject a silently different compiler/frontend runtime before installing deps.
minimum_go="$(awk '$1 == "go" { print $2 }' go.mod)"
[[ "$minimum_go" == 1.26.11 && "$(go env GOVERSION)" == "go$minimum_go" ]] || { echo 'Go1.26.11 required' >&2; exit 1; }
[[ "$(node --version)" == v26.12.1 && "$(npm --version)" == 11.20.0 ]] || { echo 'Node26.12.1/npm11.20.0 required' >&2; exit 1; }

# The server embeds the generated UI. This script runs only in read-only jobs;
# installation/build output never becomes code in the publisher.
log "building frontend"
npm --prefix "$ROOT/web" ci --include=dev
NODE_ENV=production npm --prefix "$ROOT/web" run build

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
  sha256sum ./warden-linux-amd64 ./warden-server-linux-amd64 ./warden.exe | tee SHA256SUMS
)
log "release complete"
