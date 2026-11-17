#!/usr/bin/env bash
#
# Install or update the Linux Warden client from the latest GitHub release.
#
# Usage: bash scripts/install-client.sh

set -euo pipefail

REPO="${WARDEN_REPO:-hieudmg/warden}"
RELEASE_BASE_URL="${WARDEN_RELEASE_BASE_URL:-https://github.com/$REPO/releases/latest/download}"
ASSET="warden-linux-amd64"
HOME_DIR="${HOME:?HOME must be set}"
INSTALL_DIR="${WARDEN_INSTALL_DIR:-$HOME_DIR/.local/bin}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME_DIR/.config}/warden"
CONFIG_FILE="${WARDEN_CLIENT_CONFIG:-${WARDEN_CLIENT_CONFIG_FILE:-$CONFIG_DIR/client.json}}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/warden-client-install.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

json_value() {
  local key=$1 file=$2
  sed -nE "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*$/\1/p" "$file" | head -n1
}

read_prompt() {
  local variable=$1 input="${WARDEN_PROMPT_INPUT:-}"
  if [ -z "$input" ] && [ ! -t 0 ] && [ -r /dev/tty ]; then
    input=/dev/tty
  fi
  if [ -n "$input" ]; then
    IFS= read -r "$variable" < "$input"
  else
    IFS= read -r "$variable"
  fi
}

validate_endpoint() {
  local value=$1 rest suffix
  case "$value" in
    http://*|https://*) ;;
    *) fail "endpoint must start with http:// or https://" ;;
  esac
  case "$value" in
    *'"'*|*'\\'*|*'?'*|*'#'*|*[$'\n\r\t ']* ) fail "endpoint contains unsupported whitespace or JSON characters" ;;
  esac
  rest="${value#*://}"
  [ -n "$rest" ] || fail "endpoint host must not be empty"
  case "$rest" in
    */*) [ -n "${rest%%/*}" ] || fail "endpoint host must not be empty" ;;
  esac
  while [[ "$rest" == *%* ]]; do
    suffix="${rest#*%}"
    [[ "$suffix" =~ ^[0-9A-Fa-f]{2} ]] || fail "endpoint contains an invalid URL escape"
    rest="${suffix:2}"
  done
}

write_client_config() {
  local endpoint=$1 timeout=${2:-30s} temp config_parent
  config_parent="$(dirname "$CONFIG_FILE")"
  if [ ! -d "$config_parent" ]; then
    mkdir -p "$config_parent"
    chmod 700 "$config_parent"
  fi
  temp="$WORK/client.json"
  printf '{\n  "api_base_url": "%s",\n  "timeout": "%s"\n}\n' "$endpoint" "$timeout" > "$temp"
  chmod 600 "$temp"
  install -m 0600 "$temp" "$CONFIG_FILE"
}

download_and_verify() {
  local asset=$1 output=$2 checksums expected actual
  checksums="$WORK/SHA256SUMS"
  curl --fail --location --silent --show-error --retry 3 \
    "$RELEASE_BASE_URL/$asset" --output "$output"
  curl --fail --location --silent --show-error --retry 3 \
    "$RELEASE_BASE_URL/SHA256SUMS" --output "$checksums"
  expected="$(awk -v asset="$asset" '$2 == asset || $2 == "./" asset || $2 == "*" asset { print $1; exit }' "$checksums")"
  [ -n "$expected" ] || fail "checksum for $asset not found in SHA256SUMS"
  actual="$(sha256sum "$output" | awk '{print $1}')"
  [ "$actual" = "$expected" ] || fail "checksum verification failed for $asset"
}

require_command curl
require_command sha256sum
require_command install

existing_endpoint=""
if [ -f "$CONFIG_FILE" ]; then
  existing_endpoint="$(json_value api_base_url "$CONFIG_FILE")"
fi
default_endpoint="${existing_endpoint:-http://127.0.0.1:8080}"
printf 'Warden API endpoint [%s]: ' "$default_endpoint"
read_prompt endpoint || fail 'interactive endpoint prompt was cancelled'
endpoint="${endpoint:-$default_endpoint}"
validate_endpoint "$endpoint"

download_and_verify "$ASSET" "$WORK/warden"
mkdir -p "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
install -m 0755 "$WORK/warden" "$INSTALL_DIR/warden"

timeout="30s"
if [ -f "$CONFIG_FILE" ]; then
  timeout="$(json_value timeout "$CONFIG_FILE")"
  timeout="${timeout:-30s}"
fi
write_client_config "$endpoint" "$timeout"

printf '\nWarden client installed/updated.\n'
printf '  Binary: %s\n' "$INSTALL_DIR/warden"
printf '  Config: %s\n' "$CONFIG_FILE"
printf '\nUser-scope setup:\n'
printf '  export PATH="%s:$PATH"\n' "$INSTALL_DIR"
printf '  export WARDEN_CLIENT_CONFIG="%s"\n' "$CONFIG_FILE"
printf '\nLinux global-path setup (requires sudo):\n'
printf '  sudo install -Dm755 "%s/warden" /usr/local/bin/warden\n' "$INSTALL_DIR"
printf '  sudo install -Dm644 "%s" /etc/warden/client.json\n' "$CONFIG_FILE"
printf '  export WARDEN_CLIENT_CONFIG=/etc/warden/client.json\n'
printf '\nTo update, rerun this installer; existing client config is preserved except endpoint.\n'
