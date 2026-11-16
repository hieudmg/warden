#!/usr/bin/env python3
"""Execute the real inline publisher guards with synthetic bytes and a fake gh."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from test_workflows import ROOT, step, workflow

ASSETS = ['SHA256SUMS', 'warden-linux-amd64', 'warden-server-linux-amd64', 'warden.exe']
SHA = '96e2ed4986f3423f423942d817c0f220470f15e9'


def digest(data):
    return hashlib.sha256(data).hexdigest()


class PublicationFixtures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='w16p.', dir='/var/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / 'input'
        self.dist.mkdir()
        for name in ASSETS[1:]:
            (self.dist / name).write_bytes(b'NONEXECUTABLE synthetic release bytes: ' + name.encode())
        (self.dist / 'SHA256SUMS').write_text(''.join(f'{digest((self.dist/n).read_bytes())}  ./{n}\n' for n in ASSETS[1:]))
        self.env = dict(os.environ, GITHUB_REPOSITORY='hieudmg/warden', GITHUB_SHA=SHA,
                        GITHUB_EVENT_NAME='push', GITHUB_REF='refs/heads/main', GITHUB_RUN_ID='1234',
                        GITHUB_RUN_ATTEMPT='2', GITHUB_WORKFLOW_REF='hieudmg/warden/.github/workflows/release.yml@refs/heads/main',
                        GITHUB_OUTPUT=str(self.root/'build-output'), RELEASE_VERSION='0.22.1', MINIMUM_GO='1.26.11')

    def bundle(self):
        script = ROOT / 'scripts/ci/release_bundle.py'
        self.assertTrue(script.exists(), 'missing byte-bound release builder')
        archive = self.root/'incoming'/'release-1234-2.zip'
        archive.parent.mkdir(exist_ok=True)
        archive.unlink(missing_ok=True)
        p = subprocess.run(['python3', str(script), str(self.dist), str(archive)], env=self.env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        outputs = dict(line.split('=', 1) for line in (self.root/'build-output').read_text().splitlines())
        self.env.update(SOURCE_SHA=SHA, RUN_ID='1234', RUN_ATTEMPT='2', MANIFEST_SHA=outputs['manifest-sha'],
                        ARCHIVE_SHA=outputs['archive-sha'], ARTIFACT_DIGEST=outputs['archive-sha'], ARTIFACT_ID='99')
        return archive

    def validate(self):
        publish = workflow('release.yml')['jobs'].get('publish')
        self.assertIsNotNone(publish, 'missing isolated byte-bound publisher')
        return subprocess.run(['bash', '-euo', 'pipefail', '-c', step(publish, 'validate')['run']],
                              cwd=self.root, env=self.env, capture_output=True, text=True)

    def mutate(self, archive, change, reanchor=False):
        with zipfile.ZipFile(archive) as z:
            files = {i.filename: z.read(i) for i in z.infolist()}
        change(files)
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as z:
            for name, data in files.items():
                z.writestr(name, data)
        # Even if an attacker can substitute the archive/service digest, the
        # separate trusted manifest output must still reject changed identity.
        self.env['ARCHIVE_SHA'] = self.env['ARTIFACT_DIGEST'] = digest(archive.read_bytes())
        if reanchor:
            self.env['MANIFEST_SHA'] = digest(files['manifest.json'])

    def test_builder_rejects_wrong_checksums_even_when_python_optimization_is_enabled(self):
        (self.dist/'SHA256SUMS').write_text('0'*64+'  ./warden.exe\n')
        self.env['PYTHONOPTIMIZE'] = '1'
        script = ROOT / 'scripts/ci/release_bundle.py'
        self.assertTrue(script.exists(), 'missing byte-bound release builder')
        p = subprocess.run(['python3', str(script), str(self.dist), str(self.root/'invalid.zip')],
                           env=self.env, capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0, 'optimized Python bypassed checksum validation')
        self.assertFalse((self.root/'invalid.zip').exists())

    def test_bundle_binds_real_bytes_and_exact_t14_checksum_format(self):
        archive = self.bundle()
        with zipfile.ZipFile(archive) as z:
            m = json.loads(z.read('manifest.json'))
            self.assertEqual(set(z.namelist()), set(ASSETS+['manifest.json']))
            self.assertEqual(m['source_sha'], SHA)
            self.assertEqual(m['minimum_go'], '1.26.11')
            for item in m['assets']:
                self.assertEqual(item['sha256'], digest((self.dist/item['name']).read_bytes()))
                self.assertEqual(item['size'], len((self.dist/item['name']).read_bytes()))
        p = self.validate()
        self.assertEqual(p.returncode, 0, p.stderr)
        # Attestation subjects resolve to the actual individual release bytes,
        # not the transport ZIP or a mirrored model of the validator.
        paths = step(workflow('release.yml')['jobs']['publish'], 'attest')['with']['subject-path'].splitlines()
        self.assertEqual(sorted(Path(n).name for n in paths), ASSETS)
        for name in paths:
            self.assertEqual((self.root/name).read_bytes(), (self.dist/Path(name).name).read_bytes())

    def test_tamper_missing_extra_traversal_and_wrong_digest_fail_before_publication(self):
        for scenario in ['tamper', 'missing', 'extra', 'traversal', 'manifest-digest', 'self-rehashed']:
            with self.subTest(scenario=scenario):
                archive = self.bundle()
                def change(files):
                    if scenario == 'tamper': files['warden.exe'] += b'tampered'
                    if scenario == 'missing': del files['warden.exe']
                    if scenario == 'extra': files['unexpected.exe'] = b'extra'
                    if scenario == 'traversal': files['../outside'] = b'escape'
                    if scenario == 'manifest-digest':
                        m = json.loads(files['manifest.json']); m['assets'][0]['sha256'] = '0'*64
                        files['manifest.json'] = json.dumps(m).encode()
                    if scenario == 'self-rehashed':
                        files['warden.exe'] += b'tampered'
                        m = json.loads(files['manifest.json'])
                        for a in m['assets']:
                            if a['name'] == 'warden.exe':
                                a.update(size=len(files['warden.exe']), sha256=digest(files['warden.exe']))
                        files['manifest.json'] = json.dumps(m).encode()
                self.mutate(archive, change)
                p = self.validate()
                self.assertNotEqual(p.returncode, 0, p.stdout)
                self.assertFalse((self.root/'dist').exists(), 'rejected input published/extracted')
                self.assertFalse((self.root/'outside').exists())

    def test_wrong_source_run_attempt_event_workflow_fork_fail_even_with_rehashed_manifest(self):
        for field, value in [('source_sha', 'a'*40), ('run_id', '999'), ('run_attempt', '1'),
                             ('event', 'pull_request'), ('repository', 'attacker/warden'),
                             ('workflow_ref', 'attacker/warden/.github/workflows/release.yml@refs/heads/main'),
                             ('ref', 'refs/heads/hostile'), ('minimum_go', '1.26.0'),
                             ('release_version', '0.23.0')]:
            with self.subTest(field=field):
                archive = self.bundle()
                def change(files):
                    m = json.loads(files['manifest.json']); m[field] = value
                    files['manifest.json'] = json.dumps(m).encode()
                self.mutate(archive, change, reanchor=True)
                p = self.validate()
                self.assertNotEqual(p.returncode, 0, p.stdout)
                self.assertFalse((self.root/'dist').exists())

    def test_untrusted_current_run_and_archive_digest_fail(self):
        archive = self.bundle()
        for key, value in [('GITHUB_EVENT_NAME', 'workflow_run'), ('GITHUB_REPOSITORY', 'attacker/warden'),
                           ('GITHUB_SHA', 'a'*40), ('GITHUB_RUN_ATTEMPT', '1'),
                           ('ARTIFACT_DIGEST', '0'*64), ('ARCHIVE_SHA', '0'*64)]:
            with self.subTest(key=key):
                old = self.env[key]; self.env[key] = value
                p = self.validate(); self.env[key] = old
                self.assertNotEqual(p.returncode, 0)
                self.assertFalse((self.root/'dist').exists())
        self.assertTrue(archive.exists())

    def test_generated_provenance_binds_actual_individual_bytes_and_run_source(self):
        self.bundle()
        p = self.validate()
        self.assertEqual(p.returncode, 0, p.stderr)
        publish = workflow('release.yml')['jobs']['publish']
        self.assertTrue(any(s.get('id') == 'provenance' for s in publish['steps']),
                        'missing actual generated-provenance guard before publication')
        bundle = json.loads((ROOT/'scripts/ci/fixtures/provenance.json').read_text())
        self.env['PROVENANCE_BUNDLE'] = str(self.root/'attestation.json')
        self.env['GITHUB_SERVER_URL'] = 'https://github.com'
        command = step(publish, 'provenance')['run']
        import base64
        import copy
        for scenario in ['valid', 'mutant-payload-type', 'wrong-predicate-type', 'wrong-workflow',
                         'zip-subject', 'wrong-digest', 'wrong-source', 'wrong-attempt']:
            b = copy.deepcopy(bundle)
            statement = json.loads(base64.b64decode(b['dsseEnvelope']['payload']))
            if scenario == 'mutant-payload-type':
                # @sigstore/core GHSA-jfc7-64v2-mr8c: same low-byte PAE is not
                # permission to accept a nonliteral envelope content type.
                b['dsseEnvelope']['payloadType'] = ''.join(chr(ord(c)+256) for c in b['dsseEnvelope']['payloadType'])
            if scenario == 'wrong-predicate-type': statement['predicateType'] = 'https://example.invalid/custom'
            if scenario == 'wrong-workflow':
                statement['predicate']['buildDefinition']['externalParameters']['workflow']['path'] = '.github/workflows/other.yml'
            if scenario == 'zip-subject': statement['subject'][0]['name'] = 'release.zip'
            if scenario == 'wrong-digest': statement['subject'][0]['digest']['sha256'] = '0'*64
            if scenario == 'wrong-source':
                statement['predicate']['buildDefinition']['resolvedDependencies'][0]['digest']['gitCommit'] = 'a'*40
            if scenario == 'wrong-attempt':
                statement['predicate']['runDetails']['metadata']['invocationId'] = 'https://github.com/hieudmg/warden/actions/runs/1234/attempts/1'
            b['dsseEnvelope']['payload'] = base64.b64encode(json.dumps(statement).encode()).decode()
            Path(self.env['PROVENANCE_BUNDLE']).write_text(json.dumps(b))
            p = subprocess.run(['bash', '-euo', 'pipefail', '-c', command], cwd=self.root, env=self.env, capture_output=True, text=True)
            self.assertEqual(p.returncode == 0, scenario == 'valid', p.stderr)

    def test_mutable_create_and_clobber_use_only_verified_assets_and_source(self):
        self.bundle()
        p = self.validate()
        self.assertEqual(p.returncode, 0, p.stderr)
        fake = self.root/'bin'; fake.mkdir()
        gh = fake/'gh'
        gh.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ['CALLS'], 'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[1] == 'release':
    args = sys.argv[1:]
    if args.count('--repo') != 1 or args.index('--repo')+1 == len(args) or args[args.index('--repo')+1] != 'hieudmg/warden':
        sys.exit('release command missing or wrong explicit repository')
if '--include' in sys.argv and os.environ['EXISTING']=='no':
    print('HTTP/2.0 404 Not Found'); sys.exit(1)
if '--include' in sys.argv and os.environ['EXISTING']=='error':
    print('HTTP/2.0 500 Internal Server Error'); sys.exit(1)
''')
        gh.chmod(0o700)
        # The isolated publisher has no checkout/remotes. Never let the caller's
        # GH_REPO hide missing repository selection in the actual inline shell.
        self.env.pop('GH_REPO', None)
        self.env.update(PATH=str(fake)+os.pathsep+self.env['PATH'], CALLS=str(self.root/'calls'), RELEASE_TAG='v0.22.1')
        command = step(workflow('release.yml')['jobs']['publish'], 'publish')['run']
        for existing in ['yes', 'no', 'error']:
            self.env['EXISTING'] = existing
            (self.root/'calls').write_text('')
            p = subprocess.run(['bash', '-euo', 'pipefail', '-c', command], cwd=self.root, env=self.env, capture_output=True, text=True)
            calls = [json.loads(l) for l in (self.root/'calls').read_text().splitlines()]
            if existing == 'error':
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(len(calls), 1, 'non-404 metadata failure continued to publication')
                continue
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue(any(f'sha={SHA}' in c for c in calls))
            if existing == 'yes':
                self.assertTrue(any('force=true' in c for c in calls))
                self.assertTrue(any('--clobber' in c for c in calls))
            assets = [c for c in calls if c[:2] in [['release', 'upload'], ['release', 'create']]]
            self.assertEqual(len(assets), 1)
            for n in ASSETS: self.assertIn('dist/'+n, assets[0])
            self.assertNotIn('manifest.json', ' '.join(assets[0]))
            for call in calls:
                if call[0] == 'release':
                    self.assertEqual(call[call.index('--repo')+1], 'hieudmg/warden')
        # Prove the fake rejects both omissions and wrong targets, rather than
        # just accepting commands because GITHUB_REPOSITORY happens to be set.
        for operation, existing in [('edit', 'yes'), ('upload', 'yes'), ('create', 'no')]:
            for repo_args in ['', '--repo attacker/warden']:
                with self.subTest(operation=operation, repo_args=repo_args):
                    self.env['EXISTING'] = existing
                    lines = command.splitlines(keepends=True)
                    mutated = ''.join(line.replace('--repo "$GITHUB_REPOSITORY"', repo_args)
                                      if 'gh release '+operation+' ' in line else line for line in lines)
                    self.assertNotEqual(mutated, command, 'production must select the repo explicitly')
                    p = subprocess.run(['bash', '-euo', 'pipefail', '-c', mutated], cwd=self.root,
                                       env=self.env, capture_output=True, text=True)
                    self.assertNotEqual(p.returncode, 0, 'fake gh accepted missing/wrong repository')
                    self.assertIn('missing or wrong explicit repository', p.stderr)


if __name__ == '__main__':
    unittest.main()
