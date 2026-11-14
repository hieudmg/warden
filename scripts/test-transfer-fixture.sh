#!/usr/bin/env bash
# Offline synthetic provenance check; never executes an old server or real data.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/warden-transfer-source.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
cd "$ROOT"
# Extract only the historical producer's packages and pinned dependency metadata.
while IFS= read -r path; do
  case "$path" in *_test.go) continue ;; esac
  mkdir -p "$WORK/$(dirname "$path")"
  git show "c104353:$path" > "$WORK/$path"
done < <(git ls-tree -r --name-only c104353 -- go.mod go.sum internal/store internal/model internal/crypto migrations)
cp internal/store/testdata/export-c104353_test.go.txt "$WORK/internal/store/historical_fixture_test.go"
mkdir "$WORK/output"
(cd "$WORK" && GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off WARDEN_SYNTHETIC_OUTPUT="$WORK/output" go test ./internal/store -run '^TestSyntheticHistoricalExport$' -count=1)
case "${1:-}" in
  --write-synthetic-fixture)
    cp "$WORK/output/"*.json "$ROOT/internal/store/testdata/"
    ;;
  '')
    cmp "$WORK/output/warden-data-v1-c104353.json" internal/store/testdata/warden-data-v1-c104353.json
    ;;
  *) printf 'usage: bash scripts/test-transfer-fixture.sh [--write-synthetic-fixture]\n' >&2; exit 2 ;;
esac
printf 'Historical c104353 serializer: synthetic v1 fixture verified (no live data).\n'
