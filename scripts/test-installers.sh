#!/usr/bin/env bash
# Offline fixtures only. curl and every service/elevation command are sandboxed.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/wi.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/bin" "$WORK/home" "$WORK/release" "$WORK/temp"
export HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home/.config" TMPDIR="$WORK/temp"
export FIXTURE_ROOT="$WORK" WARDEN_PROMPT_INPUT=/dev/stdin
export WARDEN_RELEASE_BASE_URL=https://release.invalid/download
export PATH="$WORK/bin:/usr/bin:/bin"
for command in sudo systemctl tailscale sysctl openssl dd; do
  printf '#!/bin/sh\necho forbidden-%s >> "$FIXTURE_ROOT/effects"\nexit 97\n' "$command" > "$WORK/bin/$command"
  chmod 700 "$WORK/bin/$command"
done
printf '#!/bin/sh\ncase "$1" in -u) echo "${FIXTURE_UID:-1000}";; -un) echo fixture;; -gn) echo fixture;; *) exit 98;; esac\n' > "$WORK/bin/id"
chmod 700 "$WORK/bin/id"
cat > "$WORK/bin/mv" <<'SH'
#!/bin/bash
if [ "${FIXTURE_FAIL_CONFIG_PUBLISH:-}" = 1 ] && [[ "${!#}" == */client.json ]]; then exit 93; fi
source_path="${@: -2:1}"
if [ "${FIXTURE_UNIT_FAILURE:-}" = rollback ] && [[ "$source_path" == */old ]] && [[ "${!#}" == */warden-server ]]; then
  echo rollback > "$FIXTURE_UNIT_CASE/rollback-triggered"; exit 96
fi
if [ "${FIXTURE_UNIT_FAILURE:-}" = binary ] && [[ "${!#}" == */warden-server ]]; then
  echo binary > "$FIXTURE_UNIT_CASE/triggered"; exit 96
fi
exec /usr/bin/mv "$@"
SH
chmod 700 "$WORK/bin/mv"
cat > "$WORK/bin/mktemp" <<'SH'
#!/bin/bash
if [ "${FIXTURE_UNIT_FAILURE:-}" = mktemp ] && [[ "${!#}" == *'.warden-service.install.'* ]]; then
  echo mktemp > "$FIXTURE_UNIT_CASE/triggered"; exit 94
fi
exec /usr/bin/mktemp "$@"
SH
cat > "$WORK/bin/chmod" <<'SH'
#!/bin/bash
if [ "${FIXTURE_UNIT_FAILURE:-}" = chmod ] && [[ "${!#}" == *'.warden-service.install.'* ]]; then
  echo chmod > "$FIXTURE_UNIT_CASE/triggered"; exit 94
fi
exec /usr/bin/chmod "$@"
SH
cat > "$WORK/bin/cat" <<'SH'
#!/bin/bash
if [ "${FIXTURE_UNIT_FAILURE:-}" = write ] && [[ "$(readlink "/proc/$$/fd/1")" == *'.warden-service.install.'* ]]; then
  echo write > "$FIXTURE_UNIT_CASE/triggered"; exit 94
fi
exec /usr/bin/cat "$@"
SH
cat > "$WORK/bin/ln" <<'SH'
#!/bin/bash
if [[ "${!#}" == */warden-server.service ]]; then
  case "${FIXTURE_UNIT_FAILURE:-}" in
    collision)
      (set -o noclobber; printf 'competing custom unit\n' > "${!#}") || exit 98
      /usr/bin/chmod 440 "${!#}"
      echo collision > "$FIXTURE_UNIT_CASE/triggered";;
    symlink)
      /usr/bin/ln -s "$FIXTURE_UNIT_CASE/competing-unit" "${!#}"
      echo symlink > "$FIXTURE_UNIT_CASE/triggered";;
    directory)
      /usr/bin/mkdir "${!#}"; /usr/bin/chmod 750 "${!#}"
      echo directory > "$FIXTURE_UNIT_CASE/triggered";;
    directory-symlink)
      /usr/bin/ln -s "$FIXTURE_UNIT_CASE/competing-dir" "${!#}"
      echo directory-symlink > "$FIXTURE_UNIT_CASE/triggered";;
    link|rollback) echo link > "$FIXTURE_UNIT_CASE/triggered"; exit 95;;
  esac
fi
exec /usr/bin/ln "$@"
SH
chmod 700 "$WORK/bin/mktemp" "$WORK/bin/chmod" "$WORK/bin/cat" "$WORK/bin/ln"
cat > "$WORK/bin/curl" <<'PY'
#!/usr/bin/python3
import os, pathlib, sys, time
args=sys.argv[1:]
assert args[0]=='--disable', args
for flag,value in [('--proto','=https'),('--proto-redir','=https'),('--connect-timeout','10')]:
    assert args[args.index(flag)+1]==value, args
assert 0<float(args[args.index('--max-time')+1])<=300
assert '--insecure' not in args and '-k' not in args
url=args[-1]
assert url.startswith('https://release.invalid/download/'), url
root=pathlib.Path(os.environ['FIXTURE_ROOT'])
(root/'curl-calls').open('a').write(url+'\n')
# The enclosing installer must create private files BEFORE any response bytes.
work=pathlib.Path(os.environ['TMPDIR'])
for p in work.rglob('*'):
    if p.is_file(): assert p.stat().st_mode & 0o077 == 0, str(p)
header=pathlib.Path(args[args.index('--dump-header')+1])
header.write_bytes(b'HTTP/1.1 200 OK\r\n\r\n')
if os.environ.get('FIXTURE_HANG'):
    (root/'curl.pid').write_text(str(os.getpid()))
    time.sleep(30)
data=(root/'release'/url.rsplit('/',1)[1]).read_bytes()
if '--output' in args and args[args.index('--output')+1]!='-':
    pathlib.Path(args[args.index('--output')+1]).write_bytes(data)
else:
    sys.stdout.buffer.write(data)
PY
chmod 700 "$WORK/bin/curl"
make_release() {
  printf 'synthetic binary; never executed %s\n' "$1" > "$WORK/release/warden-linux-amd64"
  cp "$WORK/release/warden-linux-amd64" "$WORK/release/warden-server-linux-amd64"
  cp "$WORK/release/warden-linux-amd64" "$WORK/release/warden.exe"
  (cd "$WORK/release"; sha256sum ./warden-linux-amd64 ./warden-server-linux-amd64 ./warden.exe > SHA256SUMS)
}
client() { printf '%s\n' "$1" | bash "$ROOT/scripts/install-client.sh"; }
server() { printf '%s\n' "${1:-}" | bash "$ROOT/scripts/install-server.sh"; }
server_publication_cases() {
  local initial failure case_root calls_before failed=0
  for initial in existing fresh; do
    for failure in mktemp write chmod link collision symlink directory directory-symlink binary; do
      case_root="$WORK/server-$initial-$failure"
      mkdir -p "$case_root/server" "$case_root/competing-dir"
      chmod 750 "$case_root/competing-dir"
      printf 'competing custom unit\n' > "$case_root/competing-unit"
      chmod 440 "$case_root/competing-unit"
      if [ "$initial" = existing ]; then
        printf 'original executable\n' > "$case_root/server/warden-server"
        chmod 711 "$case_root/server/warden-server"
        for state in server.json warden.db warden.db-wal warden.db-shm master.key .initialized; do
          printf 'opaque original %s\n' "$state" > "$case_root/server/$state"
          chmod 400 "$case_root/server/$state"
        done
      fi
      python3 - "$case_root" <<'PY'
import json, pathlib, stat, sys
root=pathlib.Path(sys.argv[1])
snapshot={p.name:{'mode':stat.S_IMODE(p.stat().st_mode),'bytes':p.read_bytes().hex()} for p in (root/'server').iterdir()}
(root/'before.json').write_text(json.dumps(snapshot))
PY
      calls_before="$(wc -l < "$WORK/curl-calls" 2>/dev/null || printf 0)"
      if FIXTURE_UNIT_FAILURE="$failure" FIXTURE_UNIT_CASE="$case_root" server "$case_root/server" > "$case_root/output" 2>&1; then
        echo "server $initial/$failure ignored publication failure" >&2; failed=1
      fi
      [ -e "$case_root/triggered" ] || { echo "fixture failed before intended $initial/$failure publication guard" >&2; failed=1; }
      [ "$(wc -l < "$WORK/curl-calls")" -eq "$((calls_before+2))" ] || { echo 'fixture did not reach both verified downloads' >&2; failed=1; }
      if ! python3 - "$case_root" "$failure" <<'PY'
import json, pathlib, stat, sys
root=pathlib.Path(sys.argv[1]); failure=sys.argv[2]
expected=json.loads((root/'before.json').read_text())
if failure=='collision': expected['warden-server.service']={'mode':0o440,'bytes':b'competing custom unit\n'.hex()}
if failure=='symlink': expected['warden-server.service']={'symlink':str(root/'competing-unit')}
if failure=='directory-symlink': expected['warden-server.service']={'symlink':str(root/'competing-dir')}
if failure=='directory': expected['warden-server.service']={'directory':{'mode':0o750,'children':[]}}
actual={}
for p in (root/'server').iterdir():
    if p.is_symlink(): actual[p.name]={'symlink':str(p.readlink())}
    elif p.is_file(): actual[p.name]={'mode':stat.S_IMODE(p.stat().st_mode),'bytes':p.read_bytes().hex()}
    else: actual[p.name]={'directory':{'mode':stat.S_IMODE(p.stat().st_mode),'children':sorted(q.name for q in p.iterdir())}}
assert actual==expected, f'{root.name}: publication failure changed originals/absence or leaked stages: {actual} != {expected}'
assert (root/'competing-unit').read_bytes()==b'competing custom unit\n'
assert stat.S_IMODE((root/'competing-unit').stat().st_mode)==0o440
assert not list((root/'competing-dir').iterdir()), 'wrote inside a competing unit symlink-to-directory'
assert stat.S_IMODE((root/'competing-dir').stat().st_mode)==0o750
PY
      then failed=1; fi
    done
  done
  # With rollback I/O also denied, recovery must retain original bytes/mode.
  case_root="$WORK/server-recovery"
  mkdir -p "$case_root/server"
  printf 'original executable\n' > "$case_root/server/warden-server"
  chmod 711 "$case_root/server/warden-server"
  if FIXTURE_UNIT_FAILURE=rollback FIXTURE_UNIT_CASE="$case_root" server "$case_root/server" > "$case_root/output" 2>&1; then
    echo 'ignored unit/rollback failure' >&2; failed=1
  fi
  if ! python3 - "$case_root" <<'PY'
import pathlib,stat,sys
root=pathlib.Path(sys.argv[1]);server=root/'server'
backups=list(server.glob('.warden-server.rollback.*/old'))
assert len(backups)==1, 'failed rollback erased or never retained original backup'
assert backups[0].read_bytes()==b'original executable\n'
assert stat.S_IMODE(backups[0].stat().st_mode)==0o711
assert stat.S_IMODE(backups[0].parent.stat().st_mode)==0o700
assert (root/'rollback-triggered').exists(), 'rollback fixture not reached'
assert str(backups[0].parent) in (root/'output').read_text(), 'missing recovery-stage diagnostic'
assert not (server/'warden-server.service').exists()
PY
  then failed=1; fi
  # Python3 absence must fail before downloads or any target publication.
  mkdir "$WORK/no-python" "$WORK/no-python-target"
  for command in bash dirname rm; do /usr/bin/ln -s "/usr/bin/$command" "$WORK/no-python/$command"; done
  for command in id mktemp curl; do /usr/bin/ln -s "$WORK/bin/$command" "$WORK/no-python/$command"; done
  calls_before="$(wc -l < "$WORK/curl-calls")"
  if PATH="$WORK/no-python" server "$WORK/no-python-target" > "$WORK/no-python-output" 2>&1; then echo 'missing Python3 prerequisite accepted' >&2; failed=1; fi
  [ -z "$(find "$WORK/no-python-target" -mindepth 1 -print -quit)" ] || failed=1
  [ "$(wc -l < "$WORK/curl-calls")" -eq "$calls_before" ] || failed=1
  grep -q 'required command not found: python3' "$WORK/no-python-output" || failed=1
  [ ! -e "$WORK/effects" ] || failed=1
  [ -z "$(find "$TMPDIR" -mindepth 1 -print -quit)" ] || failed=1
  [ "$failed" = 0 ]
}
make_release v1
: > "$WORK/curl-calls"
if [ "${1:-}" = server-publication ]; then
  server_publication_cases
  printf 'server publication failure fixtures passed (no service/elevation/binary execution)\n'
  exit 0
fi
server_publication_cases
client https://warden.example > "$WORK/client.out"
client_config="$HOME/.config/warden/client.json"
client_binary="$HOME/.local/bin/warden"
grep -q https://warden.example "$client_config"
grep -q 'never executed v1' "$client_binary"
# Existing client trust/timeout/unknown nonsecret settings survive endpoint edits.
printf '{"api_base_url":"https://warden.example","timeout":"2m","ca_certificate":"/private/public-ca.pem","keep":{"value":1}}\n' > "$client_config"
client https://changed.example > "$WORK/client-update.out"
python3 - "$client_config" <<'PY'
import json,sys
with open(sys.argv[1]) as file: config=json.load(file)
assert config['api_base_url']=='https://changed.example'
assert config['timeout']=='2m'
assert config['ca_certificate']=='/private/public-ca.pem'
assert config['keep']=={'value':1}
PY
# No HTTPS origin is invented for a fresh server and no setup/service runs.
server > "$WORK/server.out"
server_dir="$HOME/.warden"
[ ! -e "$server_dir/master.key" ]
[ ! -e "$server_dir/server.json" ]
[ ! -e "$server_dir/warden.db" ]
grep -q 'init --config' "$WORK/server.out"
grep -q 'manual' "$WORK/server.out"
for setting in UMask=0077 NoNewPrivileges=yes ProtectSystem=strict ReadWritePaths=; do grep -q "$setting" "$server_dir/warden-server.service"; done
grep -q 'systemctl --user restart' "$WORK/server.out"
grep -q 'sudo systemctl restart' "$WORK/server.out"
# Initialized/legacy artifacts are opaque: preserve exact bytes AND modes.
for state in initialized legacy; do
  for file in server.json warden.db warden.db-wal warden.db-shm master.key; do
    [ ! -e "$server_dir/$file" ] || chmod 600 "$server_dir/$file"
    printf '%s %s\n' "$state" "$file" > "$server_dir/$file"
    chmod 400 "$server_dir/$file"
  done
  (cd "$server_dir"; sha256sum server.json warden.db* master.key warden-server.service) > "$WORK/state.before"
  server > "$WORK/$state.out"
  (cd "$server_dir"; sha256sum server.json warden.db* master.key warden-server.service) > "$WORK/state.after"
  cmp "$WORK/state.before" "$WORK/state.after"
  [ "$(stat -c %a "$server_dir/master.key")" = 400 ]
  grep -qi 'export' "$WORK/$state.out"
  grep -qi 'fresh' "$WORK/$state.out"
done
before="$(sha256sum "$client_binary" "$client_config")"
make_release v2
if FIXTURE_FAIL_CONFIG_PUBLISH=1 client https://not-published.example > "$WORK/config-publish-failure.out" 2>&1; then echo 'ignored config publication failure' >&2; exit 1; fi
[ "$before" = "$(sha256sum "$client_binary" "$client_config")" ] || { echo 'config publication failure did not roll back executable/config' >&2; exit 1; }
if HOME="$WORK/fresh" FIXTURE_FAIL_CONFIG_PUBLISH=1 client https://new.example > "$WORK/fresh-config-failure.out" 2>&1; then echo 'ignored fresh config publication failure' >&2; exit 1; fi
[ ! -e "$WORK/fresh/.local/bin/warden" ] && [ ! -e "$WORK/fresh/.config/warden/client.json" ]
make_release v1
cp "$WORK/release/SHA256SUMS" "$WORK/sums.good"
for invalid in duplicate wrongdigest wrongalgorithm truncated; do
  cp "$WORK/sums.good" "$WORK/release/SHA256SUMS"
  case "$invalid" in
    duplicate) grep 'warden-linux-amd64$' "$WORK/sums.good" >> "$WORK/release/SHA256SUMS";;
    wrongdigest) printf '%064d  ./warden-linux-amd64\n' 0 > "$WORK/release/SHA256SUMS";;
    wrongalgorithm) printf '%0128d  ./warden-linux-amd64\n' 0 > "$WORK/release/SHA256SUMS";;
    truncated) printf 'abc  ./warden-linux-amd64\n' > "$WORK/release/SHA256SUMS";;
  esac
  if client https://warden.example > "$WORK/error.out" 2>&1; then echo "accepted $invalid" >&2; exit 1; fi
  [ "$before" = "$(sha256sum "$client_binary" "$client_config")" ]
done
cp "$WORK/sums.good" "$WORK/release/SHA256SUMS"
for url in http://release.invalid file:///tmp/fake; do
  if WARDEN_RELEASE_BASE_URL="$url" client https://warden.example > "$WORK/error.out" 2>&1; then echo 'accepted insecure release URL' >&2; exit 1; fi
done
for endpoint in http://warden.example 'https://warden.example?x=y' 'https://warden.example/%zz' 'https://warden.example/path' 'https://user:pass@warden.example' 'https://:' 'https://warden.example:bad' 'https://warden.example:65536'; do
  if client "$endpoint" > "$WORK/error.out" 2>&1; then echo 'accepted insecure/invalid endpoint' >&2; exit 1; fi
done
if FIXTURE_UID=0 server > "$WORK/root.out" 2>&1; then echo 'accepted root installer' >&2; exit 1; fi
# Interrupt a real installer wrapper while its fixture curl child is blocked.
# Parent cleanup must terminate/join that child before deleting owned stages.
printf 'https://warden.example\n' > "$WORK/prompt"
FIXTURE_HANG=1 WARDEN_PROMPT_INPUT="$WORK/prompt" bash "$ROOT/scripts/install-client.sh" > "$WORK/interrupted.out" 2>&1 &
installer_pid=$!
for ((i=0; i<100; i++)); do
  [ ! -e "$WORK/curl.pid" ] || break
  sleep .02
done
[ -e "$WORK/curl.pid" ] || { kill -TERM "$installer_pid"; wait "$installer_pid" || true; echo 'fixture never reached download' >&2; exit 1; }
curl_pid="$(< "$WORK/curl.pid")"
kill -TERM "$installer_pid"
if wait "$installer_pid"; then echo 'interrupted installer reported success' >&2; exit 1; fi
if kill -0 "$curl_pid" 2>/dev/null; then echo 'curl survived interrupted installer' >&2; exit 1; fi
[ "$before" = "$(sha256sum "$client_binary" "$client_config")" ]
grep -q -- '--config=/etc/warden/server.json' "$ROOT/deploy/systemd/warden-server.service"
for setting in UMask=0077 NoNewPrivileges=yes ProtectSystem=strict ReadWritePaths=/var/lib/warden; do
  grep -q "$setting" "$ROOT/deploy/systemd/warden-server.service"
done
[ ! -e "$WORK/effects" ]
[ -z "$(find "$TMPDIR" -mindepth 1 -print -quit)" ]
[ -z "$(find "$HOME" "$WORK/fresh" \( -name '.warden-rollback.*' -o -name '.warden-config.*' -o -name '.warden.install.*' \) -print -quit)" ]
printf 'offline installer fixtures passed (no external curl/service/elevation/binary execution)\n'
