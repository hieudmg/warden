#!/usr/bin/env python3
"""Build the data-only handoff; publisher executes its own static inline guard."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import zipfile

BINARIES = ['warden-linux-amd64', 'warden-server-linux-amd64', 'warden.exe']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise SystemExit(message)


def main():
    dist, archive = map(Path, sys.argv[1:])
    require(set(p.name for p in dist.iterdir()) == set(BINARIES + ['SHA256SUMS']), 'unexpected build assets')
    assets = []
    content = {}
    for name in sorted(BINARIES + ['SHA256SUMS']):
        p = dist / name
        require(p.is_file() and not p.is_symlink(), 'nonregular build asset')
        limit = 1 << 20 if name == 'SHA256SUMS' else 256 << 20
        require(0 < p.stat().st_size <= limit, 'asset size')
        data = p.read_bytes()
        require(0 < len(data) <= limit, 'asset size')
        content[name] = data
        assets.append({'name': name, 'size': len(data), 'sha256': sha(data)})
    checksums = ''.join(f'{sha(content[name])}  ./{name}\n' for name in BINARIES)
    require(content['SHA256SUMS'].decode('ascii') == checksums, 'checksums do not match exact build bytes')
    env = os.environ
    require(re.fullmatch(r'[0-9a-f]{40}', env['GITHUB_SHA']), 'invalid source SHA')
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', env['RELEASE_VERSION']), 'invalid release version')
    require(env['MINIMUM_GO'] == '1.26.11', 'unapproved build minimum')
    for key in ['GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT']:
        require(re.fullmatch(r'[1-9][0-9]*', env[key]), 'invalid run identity')
    manifest = dict(schema=1, repository=env['GITHUB_REPOSITORY'], source_sha=env['GITHUB_SHA'],
                    event=env['GITHUB_EVENT_NAME'], ref=env['GITHUB_REF'], workflow_ref=env['GITHUB_WORKFLOW_REF'],
                    run_id=env['GITHUB_RUN_ID'], run_attempt=env['GITHUB_RUN_ATTEMPT'],
                    release_version=env['RELEASE_VERSION'], minimum_go=env['MINIMUM_GO'], assets=assets)
    content['manifest.json'] = (json.dumps(manifest, sort_keys=True, separators=(',', ':'))+'\n').encode()
    # Stored entries permit strict bounded extraction without decompression bombs.
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_STORED) as z:
        for name, data in sorted(content.items()):
            z.writestr(name, data)
    with open(env['GITHUB_OUTPUT'], 'a') as output:
        output.write(f'manifest-sha={sha(content["manifest.json"])}\narchive-sha={sha(archive.read_bytes())}\n')
        output.write(f'source-sha={env["GITHUB_SHA"]}\nrun-id={env["GITHUB_RUN_ID"]}\nrun-attempt={env["GITHUB_RUN_ATTEMPT"]}\n')
        output.write(f'version={env["RELEASE_VERSION"]}\n')


if __name__ == '__main__':
    main()
