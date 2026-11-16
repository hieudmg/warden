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
INSTALL_STAGE=""
SERVICE_STAGE=""
ROLLBACK_DIR=""
binary_path=""
service_file=""
PUBLISH_COMMITTED=0
download_pid=""
cleanup() {
  local rollback_failed=0
  if [ -n "$download_pid" ]; then
    kill -TERM "$download_pid" 2>/dev/null || true
    wait "$download_pid" 2>/dev/null || true
  fi
  if [ -n "$ROLLBACK_DIR" ]; then
    if [ "$PUBLISH_COMMITTED" = 0 ]; then
      # Never remove a concurrent custom unit: only our published inode is owned.
      if [ -n "$SERVICE_STAGE" ] && [ "$service_file" -ef "$SERVICE_STAGE" ]; then
        rm -f -- "$service_file" || rollback_failed=1
      fi
      if [ "$binary_path" -ef "$ROLLBACK_DIR/new" ]; then
        if [ -e "$ROLLBACK_DIR/old" ]; then
          mv -fT -- "$ROLLBACK_DIR/old" "$binary_path" || rollback_failed=1
        else
          rm -f -- "$binary_path" || rollback_failed=1
        fi
      fi
    fi
    if [ "$rollback_failed" = 0 ]; then
      rm -rf -- "$ROLLBACK_DIR" || printf 'ERROR: private staging cleanup failed: %s\n' "$ROLLBACK_DIR" >&2
    else
      printf 'ERROR: rollback failed; recovery directory retained: %s\n' "$ROLLBACK_DIR" >&2
    fi
  fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
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

download_and_verify() {
  python3 - "$RELEASE_BASE_URL" "$1" "$2" <<'WARDEN_DOWNLOAD_PY' &
# Kept identical in both standalone shell installers; tested against real curl.
import hashlib
import os
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import urljoin, urlsplit

BINARY_LIMIT = 256 << 20
CHECKSUM_LIMIT = 1 << 20
CONNECT_SECONDS = 10
TOTAL_SECONDS = 300


def https_url(url):
    parsed = urlsplit(url)
    if (len(url) > 8192 or any(ord(c) <= 32 or ord(c) == 127 for c in url)
            or parsed.scheme != 'https' or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment):
        raise ValueError('release URLs and every redirect must use verified HTTPS')


def fetch(url, output, limit, deadline, owned):
    https_url(url)
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    owned.append(output)
    with os.fdopen(fd, 'w+b') as dest:
        for hop in range(11):
            https_url(url)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('release operation deadline exceeded')
            fd, header = tempfile.mkstemp(prefix='headers.', dir=os.path.dirname(output))
            os.close(fd)
            proc = None
            try:
                # No automatic redirect/retry can reset the operation deadline.
                # curl's protocol restrictions are defense in depth; this loop
                # checks Location before each subsequent request, including CDNs.
                proc = subprocess.Popen([
                    'curl', '--disable', '--fail', '--silent', '--show-error',
                    '--proto', '=https', '--proto-redir', '=https',
                    '--connect-timeout', str(CONNECT_SECONDS),
                    '--max-time', str(remaining), '--max-filesize', str(limit+1),
                    '--max-redirs', '0', '--suppress-connect-headers',
                    '--dump-header', header, '--output', '-', url,
                ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                dest.seek(0)
                dest.truncate()
                count = 0
                status = None
                location = None
                headers_due = time.monotonic() + CONNECT_SECONDS
                with selectors.DefaultSelector() as ready:
                    ready.register(proc.stdout, selectors.EVENT_READ)
                    while ready.get_map():
                        now = time.monotonic()
                        if now >= deadline or (status is None and now >= headers_due):
                            raise TimeoutError('release connect/headers or operation deadline exceeded')
                        with open(header, 'rb') as source:
                            raw = source.read(131073)
                        if len(raw) > 131072:
                            raise ValueError('release response headers too large')
                        # Ignore informational blocks; proxy CONNECT headers are
                        # suppressed by curl, not mistaken for origin readiness.
                        for block in raw.split(b'\r\n\r\n')[:-1]:
                            lines = block.split(b'\r\n')
                            fields = lines[0].split()
                            if len(fields) >= 2 and fields[1].isdigit() and int(fields[1]) >= 200:
                                status = int(fields[1])
                                locations = [line.split(b':', 1)[1].strip() for line in lines[1:] if line.lower().startswith(b'location:')]
                                if len(locations) > 1:
                                    raise ValueError('ambiguous redirect Location')
                                location = locations[0].decode('ascii') if locations else None
                        for key, _ in ready.select(min(0.02, max(0, deadline-now))):
                            chunk = os.read(key.fd, min(65536, limit-count+1))
                            if not chunk:
                                ready.unregister(key.fileobj)
                                continue
                            count += len(chunk)
                            if count > limit:
                                raise ValueError('release stream exceeds byte limit')
                            dest.write(chunk)
                code = proc.wait(timeout=max(0.001, deadline-time.monotonic()))
                if code:
                    raise RuntimeError('curl failed; original installation preserved')
                # Read after exit too: a tiny response may finish before polling.
                with open(header, 'rb') as source:
                    raw = source.read(131073)
                if len(raw) > 131072:
                    raise ValueError('release response headers too large')
                blocks = raw.split(b'\r\n\r\n')[:-1]
                if not blocks:
                    raise ValueError('missing release response headers')
                lines = blocks[-1].split(b'\r\n')
                status = int(lines[0].split()[1])
                locations = [line.split(b':', 1)[1].strip() for line in lines[1:] if line.lower().startswith(b'location:')]
                if len(locations) > 1:
                    raise ValueError('ambiguous redirect Location')
                location = locations[0].decode('ascii') if locations else None
                if status in (301, 302, 303, 307, 308) and location:
                    url = urljoin(url, location)
                    continue
                if not 200 <= status < 300:
                    raise ValueError('unexpected release HTTP status')
                return
            finally:
                if proc is not None:
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait()
                    proc.stdout.close()
                os.unlink(header)
        raise ValueError('too many release redirects')


def download_release(base, asset, output):
    deadline = time.monotonic() + TOTAL_SECONDS
    checksums = output + '.SHA256SUMS'
    owned = []
    try:
        https_url(base)
        # Track only exclusively created names, never remove a collision.
        for name, limit in ((asset, BINARY_LIMIT), ('SHA256SUMS', CHECKSUM_LIMIT)):
            path = output if name == asset else checksums
            fetch(base.rstrip('/')+'/'+name, path, limit, deadline, owned)
        matches = []
        with open(checksums, encoding='ascii') as source:
            for line in source.read().splitlines():
                if not line:
                    continue
                entry = re.fullmatch(r'([0-9a-fA-F]{64}) [ *](.+)', line)
                if not entry:
                    raise ValueError('invalid SHA256SUMS entry')
                name = entry[2]
                if name.startswith('./'):
                    name = name[2:]
                if name == asset:
                    matches.append(entry[1].lower())
        digest = hashlib.sha256()
        with open(output, 'rb') as source:
            for chunk in iter(lambda: source.read(65536), b''):
                digest.update(chunk)
        if len(matches) != 1 or digest.hexdigest() != matches[0]:
            raise ValueError('missing, ambiguous or incorrect release checksum')
        if time.monotonic() >= deadline:
            raise TimeoutError('release operation deadline exceeded')
        owned.remove(output)
    finally:
        for path in owned:
            if os.path.exists(path):
                os.unlink(path)


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt('download interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    download_release(*sys.argv[1:])
WARDEN_DOWNLOAD_PY
  download_pid=$!
  wait "$download_pid"
  download_pid=""
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
require_command python3
require_command install
require_command id

server_dir="$DEFAULT_SERVER_DIR"
# HTTPS origin/RP/TLS/storage configuration belongs to explicit init, not this
# noninteractive installer. Existing configuration and identity remain opaque.
printf 'Warden directory [%s]: ' "$server_dir"
read_prompt entered_dir || fail 'interactive directory prompt was cancelled'
server_dir="${entered_dir:-$server_dir}"
server_dir="$(expand_path "$server_dir")"
case "$server_dir" in
  *[$'\n\r\t']*|*'"'*|*'\\'*|*'$'*|*'`'*) fail 'Warden directory contains unsupported systemd characters' ;;
esac

download_and_verify "$ASSET" "$WORK/warden-server"
if [ ! -d "$server_dir" ]; then
  mkdir -p "$server_dir"
  chmod 700 "$server_dir"
fi
binary_path="$server_dir/warden-server"
[ ! -L "$binary_path" ] || fail 'refusing a symlink binary target'
# Prepare everything before publication. Private same-filesystem hard links
# preserve original bytes/mode and identify exactly which new inode we own.
ROLLBACK_DIR="$(mktemp -d "$server_dir/.warden-server.rollback.XXXXXX")"
INSTALL_STAGE="$(mktemp "$ROLLBACK_DIR/.warden-server.install.XXXXXX")"
install -m 0755 "$WORK/warden-server" "$INSTALL_STAGE"
ln -- "$INSTALL_STAGE" "$ROLLBACK_DIR/new"
if [ -e "$binary_path" ]; then ln -- "$binary_path" "$ROLLBACK_DIR/old"; fi

service_file="$server_dir/warden-server.service"
# Existing unit/custom hardening stays intact, including symlink collisions.
if [ ! -e "$service_file" ] && [ ! -L "$service_file" ]; then
  SERVICE_STAGE="$(mktemp "$ROLLBACK_DIR/.warden-service.install.XXXXXX")"
  write_service_unit "$server_dir" "$binary_path" "$server_dir/server.json" "$SERVICE_STAGE"
fi
user_name="$(id -un)"
user_group="$(id -gn)"
mv -fT -- "$INSTALL_STAGE" "$binary_path"
INSTALL_STAGE=""
if [ -n "$SERVICE_STAGE" ]; then
  # Exclusive publication cannot overwrite a concurrently installed service.
  ln -T -- "$SERVICE_STAGE" "$service_file"
fi
PUBLISH_COMMITTED=1
printf '\nWarden server installed/updated.\n'
printf '  Binary: %s\n' "$binary_path"
printf '  Config: %s/server.json\n' "$server_dir"
printf '  Database: %s/warden.db\n' "$server_dir"
printf '  Service unit: %s\n' "$service_file"
printf '\nExplicit manual initialization (fresh installations only):\n'
printf '  "%s" init --config "%s/server.json"\n' "$binary_path" "$server_dir"
printf '  init prompts for a NEW database path, HTTPS public origin, RP ID and TLS/proxy configuration.\n'
printf '  Save and re-enter recovery; after init exits, serve starts locked.\n'
printf '  Existing initialized storage: do NOT rerun init; retain configuration and manually restart when ready.\n'
printf '  Legacy storage: retain old binary/config/DB/WAL/SHM/key; export with the OLD release, then initialize separate fresh storage, import and verify before manual cutover.\n'
printf '  This installer never creates/reads a master.key, starts setup, or runs service commands.\n'
printf '\nUser-scope setup (ONLY after successful init; recommended):\n'
printf '  mkdir -p "$HOME/.config/systemd/user"\n'
printf '  install -m 0644 "%s" "$HOME/.config/systemd/user/warden-server.service"\n' "$service_file"
printf '  systemctl --user daemon-reload\n'
printf '  systemctl --user enable --now warden-server\n'
printf '\nUser-scope upgrade/restart:\n'
printf '  systemctl --user daemon-reload\n'
printf '  systemctl --user restart warden-server\n'
printf '  systemctl --user status warden-server\n'
printf '\nSystem-scope setup (ONLY after successful init):\n'
printf '  sudo install -Dm644 "%s" /etc/systemd/system/warden-server.service\n' "$service_file"
printf '  sudo mkdir -p /etc/systemd/system/warden-server.service.d\n'
printf '  printf "[Service]\\nUser=%s\\nGroup=%s\\n" | sudo tee /etc/systemd/system/warden-server.service.d/user.conf\n' "$user_name" "$user_group"
printf '  sudo systemctl daemon-reload\n'
printf '  sudo systemctl enable --now warden-server\n'
printf '\nSystem-scope upgrade/restart:\n'
printf '  sudo systemctl daemon-reload\n'
printf '  sudo systemctl restart warden-server\n'
printf '  sudo systemctl status warden-server\n'
printf '\nExisting config, DB/WAL/SHM, key and service unit are preserved without opening storage or changing their permissions.\n'
printf 'No service stop/restart is performed; executable-only updates require a manual restart.\n'
