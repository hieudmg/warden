#!/usr/bin/env bash
#
# Install or update the Linux Warden client from the latest GitHub release.
#
# Usage: bash scripts/install-client.sh

set -euo pipefail
umask 077

REPO="${WARDEN_REPO:-hieudmg/warden}"
RELEASE_BASE_URL="${WARDEN_RELEASE_BASE_URL:-https://github.com/$REPO/releases/latest/download}"
ASSET="warden-linux-amd64"
HOME_DIR="${HOME:?HOME must be set}"
INSTALL_DIR="${WARDEN_INSTALL_DIR:-$HOME_DIR/.local/bin}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME_DIR/.config}/warden"
CONFIG_FILE="${WARDEN_CLIENT_CONFIG:-${WARDEN_CLIENT_CONFIG_FILE:-$CONFIG_DIR/client.json}}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/warden-client-install.XXXXXX")"
INSTALL_STAGE=""
CONFIG_STAGE=""
download_pid=""
PUBLISH_TARGETS=()
PUBLISH_DIRS=()
PUBLISH_COMMITTED=0
prepare_rollback() {
  local target=$1 stage=$2 private
  private="$(mktemp -d "$(dirname "$target")/.warden-rollback.XXXXXX")"
  PUBLISH_TARGETS+=("$target")
  PUBLISH_DIRS+=("$private")
  ln -- "$stage" "$private/new"
  if [ -e "$target" ]; then ln -- "$target" "$private/old"; fi
}
cleanup() {
  local i rollback_failed=0
  if [ -n "$download_pid" ]; then
    kill -TERM "$download_pid" 2>/dev/null || true
    wait "$download_pid" 2>/dev/null || true
  fi
  if [ "$PUBLISH_COMMITTED" = 0 ]; then
    for ((i=${#PUBLISH_TARGETS[@]}-1; i>=0; i--)); do
      if [ "${PUBLISH_TARGETS[i]}" -ef "${PUBLISH_DIRS[i]}/new" ]; then
        if [ -e "${PUBLISH_DIRS[i]}/old" ]; then
          mv -fT -- "${PUBLISH_DIRS[i]}/old" "${PUBLISH_TARGETS[i]}" || rollback_failed=1
        else
          rm -f -- "${PUBLISH_TARGETS[i]}" || rollback_failed=1
        fi
      fi
    done
  fi
  [ -z "$INSTALL_STAGE" ] || rm -f -- "$INSTALL_STAGE"
  [ -z "$CONFIG_STAGE" ] || rm -f -- "$CONFIG_STAGE"
  if [ "$rollback_failed" = 0 ]; then
    for i in "${PUBLISH_DIRS[@]}"; do rm -rf -- "$i"; done
  else
    printf 'ERROR: rollback failed; retain private .warden-rollback directories for manual recovery.\n' >&2
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
  python3 - "$value" <<'PY'
import sys
from urllib.parse import urlsplit
origin = urlsplit(sys.argv[1])
if not origin.hostname:
    raise ValueError('endpoint host must not be empty')
# Access validates numeric/range/bracket syntax rather than trusting raw text.
port = origin.port
PY
  case "$value" in
    https://*) ;;
    *) fail "endpoint must use HTTPS with a verified certificate" ;;
  esac
  case "$value" in
    *'"'*|*'\\'*|*'?'*|*'#'*|*[$'\n\r\t ']* ) fail "endpoint contains unsupported whitespace or JSON characters" ;;
  esac
  rest="${value#*://}"
  case "$rest" in
    *@*|*'\'* ) fail 'endpoint must not contain userinfo or backslashes' ;;
    */*) [ "${rest#*/}" = "" ] || fail 'endpoint must be an HTTPS origin without a path' ;;
  esac
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

prepare_client_config() {
  python3 - "$CONFIG_FILE" "$1" "$WORK/client.json" <<'PY'
import json, os, sys
path, endpoint, output = sys.argv[1:]
config = {'timeout': '30s'}
if os.path.exists(path):
    with open(path) as source:
        config = json.load(source)
    if not isinstance(config, dict):
        raise ValueError('existing client config must be a JSON object')
config['api_base_url'] = endpoint
with os.fdopen(os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as dest:
    json.dump(config, dest, indent=2)
    dest.write('\n')
PY
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

require_command curl
require_command python3
require_command install

[ ! -L "$CONFIG_FILE" ] || fail 'refusing a symlink config target'
existing_endpoint="$(python3 - "$CONFIG_FILE" <<'PY'
import json, os, sys
if os.path.exists(sys.argv[1]):
    with open(sys.argv[1]) as source:
        config = json.load(source)
    if not isinstance(config, dict) or not isinstance(config.get('api_base_url', ''), str):
        raise ValueError('existing client config must be a JSON object with a string endpoint')
    print(config.get('api_base_url', ''))
PY
)"
default_endpoint="${existing_endpoint:-}"
# No public HTTPS identity can be guessed by an installer.
printf 'Warden API endpoint [%s]: ' "$default_endpoint"
read_prompt endpoint || fail 'interactive endpoint prompt was cancelled'
endpoint="${endpoint:-$default_endpoint}"
validate_endpoint "$endpoint"

prepare_client_config "$endpoint"
download_and_verify "$ASSET" "$WORK/warden"
mkdir -p "$INSTALL_DIR"
[ ! -L "$INSTALL_DIR/warden" ] || fail 'refusing a symlink binary target'
INSTALL_STAGE="$(mktemp "$INSTALL_DIR/.warden.install.XXXXXX")"
install -m 0755 "$WORK/warden" "$INSTALL_STAGE"
config_parent="$(dirname "$CONFIG_FILE")"
if [ ! -d "$config_parent" ]; then
  mkdir -p "$config_parent"
  chmod 700 "$config_parent"
fi
CONFIG_STAGE="$(mktemp "$config_parent/.warden-config.XXXXXX")"
install -m 0600 "$WORK/client.json" "$CONFIG_STAGE"
prepare_rollback "$INSTALL_DIR/warden" "$INSTALL_STAGE"
prepare_rollback "$CONFIG_FILE" "$CONFIG_STAGE"
mv -fT -- "$INSTALL_STAGE" "$INSTALL_DIR/warden"
INSTALL_STAGE=""
mv -fT -- "$CONFIG_STAGE" "$CONFIG_FILE"
CONFIG_STAGE=""
PUBLISH_COMMITTED=1

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
