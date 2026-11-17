#!/usr/bin/env bash
# Disposable local integrated acceptance. Never uses a live installation/agent.
# Real init/serve/CLI binaries + production assets + signed WebAuthn fixtures.
# Synthetic PRF and deterministic graph/clock substitutes are TEST ONLY, not
# genuine-authenticator, production certificate-chain or native Windows proof.
set -euo pipefail
export GOTOOLCHAIN=go1.26.11
export TMPDIR=/var/tmp
export NODE_ENV=test
export PYTHONDONTWRITEBYTECODE=1
umask 022
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
for command in go node npm python3; do
  command -v "$command" >/dev/null || { printf 'Missing prerequisite: %s\n' "$command" >&2; exit 1; }
done
WORK="$(mktemp -d /var/tmp/wa.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
printf '== build/test production assets and binaries (Go %s)\n' "$(go env GOVERSION)"
npm --prefix web ci --include=dev
npm --prefix web test
NODE_ENV=production npm --prefix web run build
npm --prefix web audit --include=dev
mkdir "$WORK/bin"
go build -trimpath -o "$WORK/bin/warden-server" ./cmd/warden-server
go build -trimpath -o "$WORK/bin/warden" ./cmd/warden
export WARDEN_ACCEPTANCE_BIN="$WORK/bin"
# Prevent a renamed/missing test from silently producing a green empty run.
go test ./internal/server/runtime -list '^TestSecurityLifecycleHTTPS$' | grep -Fx TestSecurityLifecycleHTTPS
printf '== SecurityLifecycleHTTPS (one composed journey, explicit test substitutes)\n'
go test ./internal/server/runtime -run '^TestSecurityLifecycleHTTPS$' -count=1 -timeout=180s -v
go test ./internal/server/runtime -list '^TestAccountSecurityLifecycleHTTPS$' | grep -Fx TestAccountSecurityLifecycleHTTPS
printf '== AccountSecurityLifecycleHTTPS (password-protected same-DEK account journey)\n'
go test ./internal/server/runtime -run '^TestAccountSecurityLifecycleHTTPS$' -count=1 -timeout=180s -v
printf '== LegacyRefusalAndRollback (separate preservation/fault suites, not part of the composed journey)\n'
go test ./cmd/warden-server ./internal/store ./internal/server/runtime \
  -run 'TestServeRefusesUninitializedAndLegacyWithoutMutation|TestLegacyDBRefusalPreservesArtifacts|TestVersion1ExportFixtureIntoInitializedEmptyVault|TestImportFailurePreservesIdentityAndManagedData|TestConcurrentInitializedImports|TestHTTPSVersion1ImportPreservesIdentityAndFailureRetry' \
  -count=1 -timeout=180s -v
printf '== independent permanent-agent/real SSH graph lifecycle characterizations\n'
go test ./internal/client/agent \
  -run '^TestAuthAgentLivesUntilExternalCancellation$|^TestSSHPoolIdleExpiryDoesNotEndAuthAgent$|^TestAgentAPIMemoryLifetimeAndBoundedStreams$|^TestGraphOwnsAgentConnectionThroughPoolReuseAndIdleEviction$' \
  -count=1 -timeout=180s -v
python3 scripts/test_integration_runner.py
printf 'PASS local integrated checks. UNRUN gates: genuine PRF + production trust, NativeWindowsSecurity, hosted artifact/OIDC/signatures. NOT release acceptance.\n'
