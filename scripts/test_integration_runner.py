#!/usr/bin/env python3
"""Offline declaration contracts; the real HTTPS journey runs in test.sh."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class IntegrationRunnerContracts(unittest.TestCase):
    def test_production_builds_do_not_inherit_test_node_env(self):
        for name in ['scripts/test.sh', 'scripts/build-release.sh', '.github/workflows/test.yml']:
            self.assertIn('NODE_ENV=production npm --prefix', (ROOT / name).read_text(), name)

    def test_emitted_assets_do_not_contain_react_development_runtime(self):
        assets = list((ROOT / 'internal/web/dist/assets').glob('management-*.js'))
        self.assertTrue(assets, 'build the production distribution before this contract')
        for asset in assets:
            self.assertFalse('react_stack_bottom_frame' in asset.read_text(), asset.name)

    def test_runner_uses_built_binaries_and_named_authenticated_https_journey(self):
        script = (ROOT / 'scripts/test.sh').read_text()
        for required in ['GOTOOLCHAIN=go1.26.11', 'TMPDIR=/var/tmp',
                         'TestSecurityLifecycleHTTPS', 'WARDEN_ACCEPTANCE_BIN',
                         'TestLegacyDBRefusalPreservesArtifacts',
                         'TestHTTPSVersion1ImportPreservesIdentityAndFailureRetry',
                         'TestAgentAPIMemoryLifetimeAndBoundedStreams',
                         'npm --prefix web ci --include=dev', '-timeout=180s']:
            self.assertIn(required, script)
        for obsolete in ['MASTER_KEY_PATH', 'gen_key()', 'http://127.0.0.1',
                         'load master key', 'curl -k', 'InsecureSkipVerify']:
            self.assertNotIn(obsolete, script)

    def test_read_only_ci_runs_the_integrated_runner(self):
        workflow = (ROOT / '.github/workflows/test.yml').read_text()
        self.assertIn('bash scripts/test.sh', workflow)


if __name__ == '__main__':
    unittest.main()
