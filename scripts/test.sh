#!/usr/bin/env bash
#
# End-to-end verification for Warden Hub.
#
# Builds warden-server and warden into a temporary directory, starts the
# server on an ephemeral loopback port with a freshly generated master key,
# and exercises the HTTP API + CLI:
#   - normal reads redact secrets (has_* markers only)
#   - transport retrieval returns the decrypted bundle with Cache-Control:
#     no-store
#   - a deleted jump reference fails at query time (422 invalid_graph)
#   - projects and reports persist with server-generated timestamps
#   - the CLI `warden report create` path works against the live server
#   - startup rejects a missing key and a key with unsafe permissions
#   - no secret string appears anywhere in captured logs/output
#
# Requires: bash 4+, curl, openssl, jq, go, and a Linux host (the server
# enforces Linux-only master-key validation).
#
# Usage: bash scripts/test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/warden-e2e.XXXXXX")"
SERVER_PID=""
SECRET="s3cr3t-e2e-value-9f2b7d"
PORT=""

log()  { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- Build binaries ---------------------------------------------------------
log "building binaries"
mkdir -p "$WORK/bin"
(
  cd "$ROOT"
  go build -o "$WORK/bin/warden-server" ./cmd/warden-server
  go build -o "$WORK/bin/warden" ./cmd/warden
)

# --- Server lifecycle helpers ----------------------------------------------
gen_key() { # $1 = path
  openssl rand -out "$1" 32
  chmod 0600 "$1"
}

start_server() { # $1 = port
  WARDEN_SERVER_LISTEN_ADDR="127.0.0.1:$1" \
  WARDEN_SERVER_DB_PATH="$WORK/warden.db" \
  WARDEN_SERVER_MASTER_KEY_PATH="$WORK/master.key" \
    "$WORK/bin/warden-server" serve >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
}

wait_healthy() { # $1 = port ; $2 = attempts
  local i
  for i in $(seq 1 "${2:-30}"); do
    if curl -fsS -o /dev/null "http://127.0.0.1:$1/api/v1/ssh-connections" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      return 1
    fi
    sleep 0.2
  done
  return 1
}

pick_port() { printf '%s' "$(( (RANDOM % 20000) + 20000 ))"; }

start_healthy_server() {
  local attempt
  for attempt in $(seq 1 20); do
    PORT="$(pick_port)"
    if start_server "$PORT" && wait_healthy "$PORT" 10; then
      log "server healthy on 127.0.0.1:$PORT (attempt $attempt)"
      return 0
    fi
    if [ -n "$SERVER_PID" ]; then
      kill "$SERVER_PID" 2>/dev/null || true
      wait "$SERVER_PID" 2>/dev/null || true
      SERVER_PID=""
    fi
  done
  fail "server never became healthy; last log:" "$(tail -20 "$WORK/server.log" 2>/dev/null || true)"
}

stop_server() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  SERVER_PID=""
}

base() { printf 'http://127.0.0.1:%s' "$PORT"; }

# --- Test: startup rejects missing key -------------------------------------
log "startup rejects missing master key"
if WARDEN_SERVER_LISTEN_ADDR="127.0.0.1:$(pick_port)" \
   WARDEN_SERVER_DB_PATH="$WORK/warden-missing.db" \
   WARDEN_SERVER_MASTER_KEY_PATH="$WORK/no-such-key" \
   "$WORK/bin/warden-server" serve >"$WORK/missing-key.log" 2>&1; then
  fail "server started with a missing master key"
fi
grep -q "load master key" "$WORK/missing-key.log" \
  || fail "missing-key error did not mention master key: $(cat "$WORK/missing-key.log")"

# --- Test: startup rejects unsafe key permissions ---------------------------
log "startup rejects key with unsafe permissions"
gen_key "$WORK/unsafe.key"
chmod 0644 "$WORK/unsafe.key"
if WARDEN_SERVER_LISTEN_ADDR="127.0.0.1:$(pick_port)" \
   WARDEN_SERVER_DB_PATH="$WORK/warden-unsafe.db" \
   WARDEN_SERVER_MASTER_KEY_PATH="$WORK/unsafe.key" \
   "$WORK/bin/warden-server" serve >"$WORK/unsafe-key.log" 2>&1; then
  fail "server started with a key that has unsafe permissions"
fi
grep -q "unsafe permissions" "$WORK/unsafe-key.log" \
  || fail "unsafe-key error did not mention permissions: $(cat "$WORK/unsafe-key.log")"

# --- Main server lifecycle --------------------------------------------------
log "generating master key"
gen_key "$WORK/master.key"

log "starting server"
start_healthy_server
API="$(base)"

# --- Test: profile CRUD redaction ------------------------------------------
log "list starts empty"
body="$(curl -fsS "$API/api/v1/ssh-connections")"
[ "$body" = "[]" ] || fail "initial ssh-connections list = $body, want []"

log "create ssh connection with secret"
create_json="$(
  curl -fsS -X POST "$API/api/v1/ssh-connections" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"e2e-host\",\"host\":\"example.invalid\",\"port\":22,\"username\":\"deploy\",\"password\":\"$SECRET\",\"jump_connection_ids\":\"[]\"}"
)"
E2E_ID="$(printf '%s' "$create_json" | jq -r '.id')"
[ "$E2E_ID" -gt 0 ] 2>/dev/null || fail "create returned no id: $create_json"

log "list redacts the secret"
list_json="$(curl -fsS "$API/api/v1/ssh-connections")"
printf '%s' "$list_json" | grep -q '"has_password":true' \
  || fail "list lacks has_password marker"
if printf '%s' "$list_json" | grep -qF "$SECRET"; then
  fail "list response leaked the secret"
fi

# --- Test: transport retrieval ----------------------------------------------
log "transport returns bundle with no-store"
transport_headers="$WORK/transport.headers"
curl -fsS -D "$transport_headers" -o "$WORK/transport.json" \
  "$API/api/v1/transport/ssh/$E2E_ID"
grep -qi '^cache-control: no-store' "$transport_headers" \
  || fail "transport response missing Cache-Control: no-store"
# []byte fields marshal as base64; decode the password back to bytes.
transport_secret="$(jq -r '.target.password' "$WORK/transport.json" | base64 -d)"
[ "$transport_secret" = "$SECRET" ] \
  || fail "transport bundle secret mismatch (got base64 $(jq -r '.target.password' "$WORK/transport.json"))"
printf '%s' "$(cat "$WORK/transport.json")" | jq -e '.target.name == "e2e-host"' >/dev/null \
  || fail "transport bundle target mismatch: $(cat "$WORK/transport.json")"

# --- Test: reports persist (HTTP) -------------------------------------------
log "deleted jump reference fails at query time"
jump_json="$(curl -fsS -X POST "$API/api/v1/ssh-connections" \
  -H 'Content-Type: application/json' \
  -d '{"name":"e2e-jump","host":"jump.invalid","port":22,"username":"jumpuser","jump_connection_ids":"[]"}')"
JUMP_ID="$(printf '%s' "$jump_json" | jq -r '.id')"
jumper_json="$(curl -fsS -X POST "$API/api/v1/ssh-connections" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"e2e-jumper\",\"host\":\"via.invalid\",\"port\":22,\"username\":\"jumper\",\"jump_connection_ids\":\"[$JUMP_ID]\"}")"
JUMPER_ID="$(printf '%s' "$jumper_json" | jq -r '.id')"
curl -fsS -X DELETE "$API/api/v1/ssh-connections/$JUMP_ID" -o /dev/null
code="$(curl -s -o "$WORK/jump-fail.json" -w '%{http_code}' \
  "$API/api/v1/transport/ssh/$JUMPER_ID")"
[ "$code" = "422" ] || fail "transport after jump deletion = HTTP $code, want 422"
grep -q "does not exist" "$WORK/jump-fail.json" \
  || fail "jump failure did not mention the missing reference: $(cat "$WORK/jump-fail.json")"

# --- Test: db CRUD redaction + transport bundle -----------------------------
log "create db connection with secret"
db_create_json="$(
  curl -fsS -X POST "$API/api/v1/db-connections" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"e2e-db\",\"host\":\"db.invalid\",\"port\":3306,\"username\":\"app\",\"password\":\"$SECRET\",\"database\":\"appdb\",\"ssh_connection_id\":0}"
)"
DB_ID="$(printf '%s' "$db_create_json" | jq -r '.id')"
[ "$DB_ID" -gt 0 ] 2>/dev/null || fail "db create returned no id: $db_create_json"

log "db list redacts the secret"
db_list_json="$(curl -fsS "$API/api/v1/db-connections")"
printf '%s' "$db_list_json" | grep -q '"has_password":true' \
  || fail "db list lacks has_password marker"
if printf '%s' "$db_list_json" | grep -qF "$SECRET"; then
  fail "db list response leaked the secret"
fi

log "db transport returns bundle with no-store"
db_headers="$WORK/db-transport.headers"
curl -fsS -D "$db_headers" -o "$WORK/db-transport.json" \
  "$API/api/v1/transport/db/$DB_ID"
grep -qi '^cache-control: no-store' "$db_headers" \
  || fail "db transport response missing Cache-Control: no-store"
db_transport_secret="$(jq -r '.password' "$WORK/db-transport.json" | base64 -d)"
[ "$db_transport_secret" = "$SECRET" ] \
  || fail "db transport bundle secret mismatch (got base64 $(jq -r '.password' "$WORK/db-transport.json"))"
printf '%s' "$(cat "$WORK/db-transport.json")" | jq -e '.database == "appdb"' >/dev/null \
  || fail "db transport bundle database mismatch: $(cat "$WORK/db-transport.json")"
if grep -qF "$SECRET" "$WORK/db-transport.json" 2>/dev/null; then
  fail "db transport response leaked the secret"
fi

# --- Test: reports persist (HTTP) -------------------------------------------
log "projects and reports persist"
curl -fsS -X POST "$API/api/v1/projects" \
  -H 'Content-Type: application/json' -d '{"name":"e2e-proj"}' -o /dev/null
curl -fsS -X POST "$API/api/v1/reports" \
  -H 'Content-Type: application/json' \
  -d '{"project":"e2e-proj","title":"e2e title","summary":"e2e summary body","agent_model":"e2e-agent"}' \
  -o "$WORK/report.json"
report_id="$(jq -r '.id' "$WORK/report.json")"
[ "$report_id" -gt 0 ] 2>/dev/null || fail "report create returned no id"
jq -e '.created_at != ""' "$WORK/report.json" >/dev/null \
  || fail "report missing server timestamp"
curl -fsS "$API/api/v1/projects" | grep -qF "e2e-proj" \
  || fail "project list missing e2e-proj"
reports_json="$(curl -fsS "$API/api/v1/projects/e2e-proj/reports")"
printf '%s' "$reports_json" | grep -qF "e2e summary body" \
  || fail "report list missing summary: $reports_json"

# --- Test: CLI report create against live server ----------------------------
log "cli report create against live server"
cli_out="$(
  WARDEN_CLIENT_API_BASE_URL="$API" "$WORK/bin/warden" report create \
    e2e-proj --title "cli title" --summary "cli summary body" \
    --agent-model "e2e-cli-agent" 2>"$WORK/cli-report.err"
)"
printf '%s' "$cli_out" | grep -qF "created for e2e-proj" \
  || fail "cli output unexpected: $cli_out"
[ ! -s "$WORK/cli-report.err" ] || fail "cli report wrote stderr: $(cat "$WORK/cli-report.err")"

# --- Test: no secret in logs -------------------------------------------------
log "no secret anywhere in captured logs"
if grep -qF "$SECRET" "$WORK/server.log" 2>/dev/null; then
  fail "server log contains the secret"
fi

log "ALL E2E CHECKS PASSED (server port $PORT)"
