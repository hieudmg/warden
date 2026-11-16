#!/usr/bin/env python3
"""Offline contracts for the actual workflow, never GitHub writes.

BaseLoader constructs only strings/lists/maps, not executable YAML objects, and
preserves Actions' `on` key (unlike YAML 1.1 boolean resolution).
"""
import json
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
PINS = json.loads((Path(__file__).with_name('action-pins.json')).read_text())


def workflow(name):
    path = ROOT / '.github/workflows' / name
    if not path.exists():
        raise AssertionError(f'missing required workflow: {name}')
    return yaml.load(path.read_text(), Loader=yaml.BaseLoader)


def step(job, step_id):
    return next(s for s in job['steps'] if s.get('id') == step_id)


class WorkflowContracts(unittest.TestCase):
    def test_default_and_build_test_permissions_are_read_only(self):
        for name in ['release.yml', 'test.yml']:
            with self.subTest(workflow=name):
                w = workflow(name)
                self.assertEqual(w['permissions'], {'contents': 'read'})
                for key, job in w['jobs'].items():
                    if key != 'publish':
                        self.assertEqual(job.get('permissions', w['permissions']), {'contents': 'read'})
                        text = json.dumps(job)
                        self.assertNotIn('secrets.', text)
                        self.assertNotIn('id-token', text)
                        self.assertNotIn('contents: write', text)
                        self.assertNotIn('continue-on-error', job)

    def test_every_external_action_is_an_api_verified_known_repo_commit(self):
        for name in ['release.yml', 'test.yml']:
            w = workflow(name)
            for job in w['jobs'].values():
                for s in job.get('steps', []):
                    if 'uses' not in s:
                        continue
                    repo, sha = s['uses'].split('@')
                    with self.subTest(action=s['uses']):
                        self.assertIn(repo, PINS)
                        self.assertRegex(sha, r'^[0-9a-f]{40}$')
                        self.assertEqual(sha, PINS[repo]['sha'])
                        if repo == 'actions/checkout':
                            self.assertEqual(s['with']['persist-credentials'], 'false')
                        if repo == 'actions/setup-go':
                            self.assertEqual(s['with']['go-version-file'], 'go.mod')
                        if repo == 'actions/setup-node':
                            self.assertEqual(s['with']['node-version'], '26.12.1')
                            self.assertEqual(s['with']['package-manager-cache'], 'false')

    def test_unprivileged_checks_cover_web_go_race_stress_installers_and_audits(self):
        w = workflow('test.yml')
        self.assertEqual(set(w['on']), {'pull_request', 'workflow_call'})
        self.assertNotIn('pull_request_target', w['on'])
        linux = w['jobs']['linux']
        self.assertEqual(linux['timeout-minutes'], '20')
        self.assertEqual(linux['env']['GOTOOLCHAIN'], 'go1.26.11')
        commands = '\n'.join(s.get('run', '') for s in linux['steps'])
        for command in ['npm --prefix web ci --include=dev', 'npm --prefix web test',
                        'npm --prefix web run build', 'npm --prefix web audit --include=dev',
                        'go test ./...', 'go test -race ./...', 'go vet ./...',
                        'go test -race ./internal/client/ssh ./internal/client/db -count=25',
                        'bash scripts/test-installers.sh', 'python3 scripts/installers_test.py',
                        "go test ./internal/server/runtime -run '^TestHTTPSRuntimeSubprocessRestartAuthentication$'",
                        'golang.org/x/vuln/cmd/govulncheck@v1.9.0',
                        'python3 -m unittest discover -s scripts/ci']:
            self.assertIn(command, commands)
        self.assertIn('11.20.0', commands)

    def test_native_windows_executes_named_nonempty_security_matrix(self):
        job = workflow('test.yml')['jobs']['windows']
        self.assertEqual(job['runs-on'], 'windows-latest')
        self.assertNotIn('continue-on-error', job)
        text = json.dumps(job)
        self.assertIn('shell', text)
        self.assertIn('powershell', text)  # Desktop 5.1, not pwsh
        self.assertIn('scripts/ci/test-windows.ps1', text)
        harness = (ROOT / 'scripts/ci/test-windows.ps1').read_text()
        for required in ['-list', '-json', 'skip', 'pass', '461808', 'Desktop',
                         'TestPipeSquatterCannotCollectSecrets', 'TestRuntimeACLRejectsOtherUser',
                         'TestWindowsCopyNativePathContainment', 'TestWindowsStagingOwnerACLBeforeFirstWrite',
                         'TestWindowsPowerShellTrustedHTTPSReleaseMatrix']:
            self.assertIn(required, harness)
        self.assertNotIn('-c ', harness)

    def test_publisher_is_isolated_and_binds_trusted_build_outputs(self):
        w = workflow('release.yml')
        self.assertEqual(w['on'], {'push': {'branches': ['main']}})
        self.assertEqual(w['concurrency'], {'group': 'release-main', 'cancel-in-progress': 'false'})
        self.assertEqual(w['jobs']['checks']['uses'], './.github/workflows/test.yml')
        build, publish = w['jobs']['build'], w['jobs']['publish']
        self.assertEqual(build['needs'], 'checks')
        self.assertEqual(publish['needs'], 'build')
        self.assertEqual(publish['permissions'], {'contents': 'write', 'attestations': 'write', 'id-token': 'write'})
        self.assertEqual(publish['if'], "github.repository == 'hieudmg/warden' && github.event_name == 'push' && github.ref == 'refs/heads/main'")
        self.assertNotIn('workflow_run', json.dumps(w))
        for s in publish['steps']:
            self.assertNotIn('continue-on-error', s)
            self.assertNotIn('if', s)  # Every guard must succeed before the next step.
            self.assertNotIn('checkout', s.get('uses', ''))
            self.assertNotIn('setup-', s.get('uses', ''))
            for forbidden in ['npm ', 'go build', 'go install', 'bash scripts/', 'eval ']:
                self.assertNotIn(forbidden, s.get('run', ''))
        download = step(publish, 'download')['with']
        self.assertEqual(download['artifact-ids'], '${{ needs.build.outputs.artifact-id }}')
        self.assertEqual(download['digest-mismatch'], 'error')
        self.assertEqual(download['skip-decompress'], 'true')
        self.assertNotIn('github-token', download)  # same-run runtime scope, no cross-run token
        self.assertNotIn('name', download)
        validate = step(publish, 'validate')
        for key in ['SOURCE_SHA', 'RUN_ID', 'RUN_ATTEMPT', 'MANIFEST_SHA', 'ARCHIVE_SHA', 'ARTIFACT_DIGEST']:
            self.assertIn('needs.build.outputs.', validate['env'][key])
        attest = step(publish, 'attest')
        self.assertEqual(attest['with']['subject-path'], 'dist/warden-server-linux-amd64\ndist/warden-linux-amd64\ndist/warden.exe\ndist/SHA256SUMS\n')
        self.assertEqual([s['id'] for s in publish['steps']], ['download', 'validate', 'attest', 'provenance', 'publish'])
        self.assertEqual(attest['uses'], 'actions/attest@'+PINS['actions/attest']['sha'])
        # Direct official attest defaults to SLSA provenance with no predicate or
        # SBOM input. Keep the wrapper's Node header option and fixed file list.
        self.assertEqual(set(attest['with']), {'subject-path', 'create-storage-record', 'push-to-registry'})
        self.assertEqual(attest['with']['create-storage-record'], 'false')
        self.assertEqual(attest['with']['push-to-registry'], 'false')
        self.assertEqual(attest['env'], {'NODE_OPTIONS': '--max-http-header-size=32768'})
        publication = step(publish, 'publish')['run']
        self.assertIn('force=true', publication)
        self.assertIn('--clobber', publication)
        self.assertIn('GITHUB_SHA', publication)
        self.assertNotIn('release.zip', publication)


if __name__ == '__main__':
    unittest.main()
