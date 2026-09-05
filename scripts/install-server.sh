#!/usr/bin/env bash
#
# Install or update the Linux Warden server from the latest GitHub release.
# The script runs without sudo and prints both user- and system-scope service
# setup instructions.
#
# Usage: bash scripts/install-server.sh

set -euo pipefail
umask 077

[ "$(id -u)" -ne 0 ] || {
  printf 'ERROR: run this installer as the service user, not root.\n' >&2
  exit 1
}

REPO="${WARDEN_REPO:-hieudmg/warden}"
RELEASE_BASE_URL="${WARDEN_RELEASE_BASE_URL:-https://github.com/$REPO/releases/latest/download}"
ASSET="warden-server-linux-amd64"
HOME_DIR="${HOME:?HOME must be set}"
DEFAULT_SERVER_DIR="${WARDEN_SERVER_DIR:-$HOME_DIR/.warden}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/warden-server-install.XXXXXX")"
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
  sed -nE "s/^[[:space:]]*\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*$/\1/p" "$file" | head -n1
}

json_escape() {
  local value=$1
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "$value"
}

systemd_quote() {
  local value=$1
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//%/%%}
  printf '"%s"' "$value"
}

systemd_path() {
  local value=$1
  value=${value//\\/\\x5c}
  value=${value// /\\x20}
  value=${value//%/%%}
  printf '%s' "$value"
}

expand_path() {
  local value=$1
  case "$value" in
    '~') value="$HOME_DIR" ;;
    '~/'*) value="$HOME_DIR/${value#~/}" ;;
  esac
  case "$value" in
    /*) printf '%s' "$value" ;;
    *) printf '%s/%s' "$PWD" "${value#./}" ;;
  esac
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

validate_host() {
  local value=$1 normalized octet second third fourth
  [ -n "$value" ] || fail 'listen host must not be empty'
  case "$value" in
    *[$'\n\r\t ']*|*'"'*|*'\\'*|*'/'*) fail 'listen host contains unsupported characters' ;;
  esac
  normalized="${value,,}"
  case "$normalized" in
    localhost|::1) return 0 ;;
    fd7a:115c:a1e0:*)
      [[ "$normalized" =~ ^fd7a:115c:a1e0:[0-9a-f:]+$ ]] ||
        fail 'listen host must be a valid Tailscale IPv6 address'
      return 0
      ;;
  esac
  if [[ "$normalized" =~ ^127\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    second="${BASH_REMATCH[1]}"
    third="${BASH_REMATCH[2]}"
    fourth="${BASH_REMATCH[3]}"
    for octet in "$second" "$third" "$fourth"; do
      [ "$((10#$octet))" -le 255 ] || fail 'listen host is not a valid IPv4 address'
    done
    return 0
  fi
  if [[ "$normalized" =~ ^100\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    second="${BASH_REMATCH[1]}"
    third="${BASH_REMATCH[2]}"
    fourth="${BASH_REMATCH[3]}"
    for octet in "$second" "$third" "$fourth"; do
      [ "$((10#$octet))" -le 255 ] || fail 'listen host is not a valid IPv4 address'
    done
    [ "$((10#$second))" -ge 64 ] && [ "$((10#$second))" -le 127 ] ||
      fail 'listen host must be loopback or a Tailscale CGNAT address (100.64.0.0/10)'
    return 0
  fi
  fail 'listen host must be loopback or a Tailscale address; public and wildcard binds are unsafe'
}

validate_port() {
  local value=$1 number
  [[ "$value" =~ ^[0-9]+$ ]] || fail 'listen port must be a number between 1 and 65535'
  number=$((10#$value))
  [ "$number" -ge 1 ] && [ "$number" -le 65535 ] || fail 'listen port must be between 1 and 65535'
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

write_server_config() {
  local listen_addr=$1 server_dir=$2 temp db_path key_path
  db_path="$server_dir/warden.db"
  key_path="$server_dir/master.key"
  temp="$WORK/server.json"
  printf '{\n  "listen_addr": "%s",\n  "db_path": "%s",\n  "master_key_path": "%s",\n  "static_fs": ""\n}\n' \
    "$(json_escape "$listen_addr")" \
    "$(json_escape "$db_path")" \
    "$(json_escape "$key_path")" > "$temp"
  chmod 600 "$temp"
  install -m 0600 "$temp" "$server_dir/server.json"
}

write_service_unit() {
  local server_dir=$1 binary=$2 config=$3 service=$4
  cat > "$service" <<EOF
[Unit]
Description=Warden Hub management server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$(systemd_path "$server_dir")
ExecStart=$(systemd_quote "$binary") serve --config=$(systemd_quote "$config")
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$(systemd_path "$server_dir")
Restart=on-failure
RestartSec=5s
TimeoutStopSec=15s

[Install]
WantedBy=default.target
EOF
  chmod 644 "$service"
}

require_command curl
require_command sha256sum
require_command install
require_command id

server_dir="$DEFAULT_SERVER_DIR"
if [ -f "$server_dir/server.json" ]; then
  existing_listen="$(json_value listen_addr "$server_dir/server.json")"
else
  existing_listen=""
fi

default_host="127.0.0.1"
default_port="8080"
if [ -n "$existing_listen" ]; then
  if [[ "$existing_listen" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then
    default_host="${BASH_REMATCH[1]}"
    default_port="${BASH_REMATCH[2]}"
  elif [[ "$existing_listen" =~ ^(.+):([0-9]+)$ ]]; then
    default_host="${BASH_REMATCH[1]}"
    default_port="${BASH_REMATCH[2]}"
  fi
fi

printf 'Listen host [%s]: ' "$default_host"
read_prompt host || fail 'interactive listen-host prompt was cancelled'
host="${host:-$default_host}"
validate_host "$host"

printf 'Listen port [%s]: ' "$default_port"
read_prompt port || fail 'interactive listen-port prompt was cancelled'
port="${port:-$default_port}"
validate_port "$port"

printf 'Warden directory [%s]: ' "$server_dir"
read_prompt entered_dir || fail 'interactive directory prompt was cancelled'
server_dir="${entered_dir:-$server_dir}"
server_dir="$(expand_path "$server_dir")"
case "$server_dir" in
  *[$'\n\r\t']*|*'"'*|*'\\'*|*'$'*|*'`'*) fail 'Warden directory contains unsupported systemd characters' ;;
esac

if [[ "$host" == *:* ]]; then
  listen_addr="[$host]:$port"
else
  listen_addr="$host:$port"
fi

mkdir -p "$server_dir"
chmod 700 "$server_dir"
download_and_verify "$ASSET" "$WORK/warden-server"
binary_path="$server_dir/warden-server"
install -m 0755 "$WORK/warden-server" "$binary_path"

key_path="$server_dir/master.key"
if [ ! -e "$key_path" ]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -out "$key_path" 32
  else
    dd if=/dev/urandom of="$key_path" bs=32 count=1 status=none
  fi
fi
[ -f "$key_path" ] || fail "master key path is not a regular file: $key_path"
chmod 600 "$key_path"
[ "$(wc -c < "$key_path")" -eq 32 ] || fail "master key must contain exactly 32 bytes: $key_path"

write_server_config "$listen_addr" "$server_dir"
service_file="$server_dir/warden-server.service"
write_service_unit "$server_dir" "$binary_path" "$server_dir/server.json" "$service_file"

user_name="$(id -un)"
user_group="$(id -gn)"
printf '\nWarden server installed/updated.\n'
printf '  Binary: %s\n' "$binary_path"
printf '  Config: %s/server.json\n' "$server_dir"
printf '  Database: %s/warden.db\n' "$server_dir"
printf '  Master key: %s/master.key\n' "$server_dir"
printf '  Service unit: %s\n' "$service_file"
printf '\nUser-scope setup (recommended):\n'
printf '  mkdir -p "$HOME/.config/systemd/user"\n'
printf '  install -m 0644 "%s" "$HOME/.config/systemd/user/warden-server.service"\n' "$service_file"
printf '  systemctl --user daemon-reload\n'
printf '  systemctl --user enable --now warden-server\n'
printf '\nUser-scope upgrade/restart:\n'
printf '  systemctl --user daemon-reload\n'
printf '  systemctl --user restart warden-server\n'
printf '  systemctl --user status warden-server\n'
printf '\nSystem-scope setup:\n'
printf '  sudo install -Dm644 "%s" /etc/systemd/system/warden-server.service\n' "$service_file"
printf '  sudo mkdir -p /etc/systemd/system/warden-server.service.d\n'
printf '  printf "[Service]\\nUser=%s\\nGroup=%s\\n" | sudo tee /etc/systemd/system/warden-server.service.d/user.conf\n' "$user_name" "$user_group"
printf '  sudo systemctl daemon-reload\n'
printf '  sudo systemctl enable --now warden-server\n'
printf '\nSystem-scope upgrade/restart:\n'
printf '  sudo systemctl daemon-reload\n'
printf '  sudo systemctl restart warden-server\n'
printf '  sudo systemctl status warden-server\n'
printf '\nThe generated service unit is refreshed on every installer run; existing database and master key are preserved.\n'
