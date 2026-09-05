#!/usr/bin/env bash
#
# Smoke tests for release installers using local, checksum-verified assets.
#
# Usage: bash scripts/test-installers.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/warden-installers.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

RELEASE="$WORK/release"
HOME_DIR="$WORK/home"
mkdir -p "$RELEASE" "$HOME_DIR"

make_release() {
  local server_marker=$1 client_marker=$2
  printf '%s\n' "$server_marker" > "$RELEASE/warden-server-linux-amd64"
  printf '%s\n' "$client_marker" > "$RELEASE/warden-linux-amd64"
  printf '%s\n' "$client_marker" > "$RELEASE/warden.exe"
  (
    cd "$RELEASE"
    sha256sum warden-server-linux-amd64 warden-linux-amd64 warden.exe > SHA256SUMS
  )
}

run_client_install() {
  printf '%s\n' "$1" | \
    HOME="$HOME_DIR" \
    XDG_CONFIG_HOME="$HOME_DIR/.config" \
    WARDEN_RELEASE_BASE_URL="file://$RELEASE" \
    WARDEN_INSTALL_DIR="$HOME_DIR/.local/bin" \
    WARDEN_CLIENT_CONFIG="${CLIENT_CONFIG_OVERRIDE:-}" \
    WARDEN_PROMPT_INPUT=/dev/stdin \
    bash "$ROOT/scripts/install-client.sh"
}

run_server_install() {
  printf '%s\n%s\n%s\n' "$1" "$2" "$3" | \
    HOME="$HOME_DIR" \
    WARDEN_RELEASE_BASE_URL="file://$RELEASE" \
    WARDEN_SERVER_DIR="$HOME_DIR/.warden" \
    WARDEN_PROMPT_INPUT=/dev/stdin \
    bash "$ROOT/scripts/install-server.sh" | tee "$WORK/server-install-output"
}

make_release server-v1 client-v1
run_client_install "https://warden.example:8080"
client_config="$HOME_DIR/.config/warden/client.json"
client_binary="$HOME_DIR/.local/bin/warden"
grep -q 'https://warden.example:8080' "$client_config"
grep -q 'client-v1' "$client_binary"
sed -i 's/30s/2m/' "$client_config"

make_release server-v2 client-v2
run_client_install ""
grep -q 'https://warden.example:8080' "$client_config"
grep -q '"timeout": "2m"' "$client_config"
grep -q 'client-v2' "$client_binary"
custom_client_config="$HOME_DIR/custom/client.json"
CLIENT_CONFIG_OVERRIDE="$custom_client_config" run_client_install "https://custom.example:8080"
grep -q 'https://custom.example:8080' "$custom_client_config"

run_server_install "127.0.0.1" "18080" ""
server_dir="$HOME_DIR/.warden"
server_config="$server_dir/server.json"
server_binary="$server_dir/warden-server"
service_file="$server_dir/warden-server.service"
grep -q '"listen_addr": "127.0.0.1:18080"' "$server_config"
grep -q '"db_path": "'$server_dir'/warden.db"' "$server_config"
grep -q 'ExecStart=' "$service_file"
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "$service_file"
fi
[ "$(wc -c < "$server_dir/master.key")" -eq 32 ]
key_before=$(sha256sum "$server_dir/master.key")
printf 'database marker\n' > "$server_dir/warden.db"

grep -q 'systemctl --user restart warden-server' "$WORK/server-install-output"

for invalid_endpoint in 'https://warden.example:8080?invalid=true' 'http://' 'https://warden.example/%zz'; do
  if run_client_install "$invalid_endpoint" >/dev/null 2>&1; then
    echo "client installer accepted invalid endpoint: $invalid_endpoint" >&2
    exit 1
  fi
done
if run_server_install '0.0.0.0' '18080' '' >/dev/null 2>&1; then
  echo 'server installer accepted a wildcard listen host' >&2
  exit 1
fi
if run_server_install '0:0:0:0:0:0::' '18080' '' >/dev/null 2>&1; then
  echo 'server installer accepted an IPv6 wildcard listen host' >&2
  exit 1
fi
cp "$RELEASE/SHA256SUMS" "$WORK/SHA256SUMS.good"
sed -i 's/^[0-9a-f]\{64\}  warden-linux-amd64/0000000000000000000000000000000000000000000000000000000000000000  warden-linux-amd64/' "$RELEASE/SHA256SUMS"
if run_client_install '' >/dev/null 2>&1; then
  echo 'client installer accepted an invalid checksum' >&2
  exit 1
fi
cp "$WORK/SHA256SUMS.good" "$RELEASE/SHA256SUMS"

make_release server-v3 client-v3
run_server_install "" "" ""
grep -q 'server-v3' "$server_binary"
grep -q 'database marker' "$server_dir/warden.db"
[ "$key_before" = "$(sha256sum "$server_dir/master.key")" ]
grep -q 'systemctl --user restart warden-server' "$WORK/server-install-output"

custom_dir="$HOME_DIR/.warden %state"
run_server_install "127.0.0.1" "19090" "$custom_dir"
custom_service="$custom_dir/warden-server.service"
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "$custom_service"
fi

grep -q '19090' "$custom_dir/server.json"
printf 'installer smoke tests passed\n'
