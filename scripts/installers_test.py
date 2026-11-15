#!/usr/bin/env python3
"""Disposable, verified-TLS tests of the exact standalone installer downloader."""
import hashlib
import http.server
import os
import re
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def downloader(script):
    text = (ROOT / 'scripts' / script).read_text()
    code = re.split(r"<<'WARDEN_DOWNLOAD_PY'\s*&?\n", text, maxsplit=1)[1].split('\nWARDEN_DOWNLOAD_PY', 1)[0]
    namespace = {'__name__': 'installer_fixture'}
    exec(compile(code, script, 'exec'), namespace)
    return namespace


class InstallerHTTPS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='it.', dir='/var/tmp')
        cls.path = Path(cls.work.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', str(cls.path/'key'), '-out', str(cls.path/'cert')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.old_ca = os.environ.get('CURL_CA_BUNDLE')
        os.environ['CURL_CA_BUNDLE'] = str(cls.path/'cert')

    @classmethod
    def tearDownClass(cls):
        if cls.old_ca is None:
            os.environ.pop('CURL_CA_BUNDLE', None)
        else:
            os.environ['CURL_CA_BUNDLE'] = cls.old_ca
        cls.work.cleanup()

    def run_case(self, script, scenario):
        ns = downloader(script)
        ns.update(BINARY_LIMIT=16, CHECKSUM_LIMIT=128, CONNECT_SECONDS=0.1, TOTAL_SECONDS=0.25)
        payload = b'b'*16
        sums = hashlib.sha256(payload).hexdigest().encode()+b'  ./warden-linux-amd64\n'
        if scenario == 'binary +1':
            payload += b'b'
        if scenario == 'checksum +1':
            ns['CHECKSUM_LIMIT'] = len(sums)-1
        if scenario == 'checksum exact':
            ns['CHECKSUM_LIMIT'] = len(sums)
        if scenario == 'duplicate':
            sums += sums
            ns['CHECKSUM_LIMIT'] = len(sums)
        if scenario == 'bad digest':
            sums = b'0'*64+b'  ./warden-linux-amd64\n'
        if scenario == 'truncated digest':
            sums = b'a'*63+b'  ./warden-linux-amd64\n'
        if scenario == 'path entry':
            sums = hashlib.sha256(payload).hexdigest().encode()+b'  path/warden-linux-amd64\n'
        hits = []
        class Peer(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *args):
                pass
            def do_GET(self):
                hits.append(self.path)
                checksum = self.path.endswith('SHA256SUMS')
                if scenario == 'slow headers':
                    time.sleep(0.18)
                if scenario == 'shared deadline':
                    time.sleep(0.15)
                if scenario in ('downgrade', 'CDN'):
                    self.send_response(302)
                    self.send_header('Location', target_url+self.path)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                body = sums if checksum else payload
                self.send_response(200)
                if scenario == 'truncated body':
                    self.send_header('Content-Length', str(len(body)+1))
                else:
                    self.send_header('Transfer-Encoding', 'chunked')  # absent Length
                self.end_headers()
                self.wfile.flush()
                if scenario == 'slow body':
                    time.sleep(0.4)
                try:
                    if scenario == 'truncated body':
                        self.wfile.write(body)
                    else:
                        self.wfile.write(('%x\r\n' % len(body)).encode()+body+b'\r\n0\r\n\r\n')
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass
                self.close_connection = True
        class Target(Peer):
            def do_GET(self):
                hits.append('target'+self.path)
                body = sums if self.path.endswith('SHA256SUMS') else payload
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        def start(handler, tls):
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
            server.daemon_threads = False
            if tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(self.path/'cert', self.path/'key')
                server.socket = ctx.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
            thread.start()
            self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join()))
            return server
        target = start(Target, scenario != 'downgrade')
        target_url = ('http' if scenario == 'downgrade' else 'https')+'://localhost:'+str(target.server_port)
        origin = start(Peer, True)
        base = 'https://127.0.0.1:'+str(origin.server_port)
        if scenario == 'initial HTTP':
            base = 'http://127.0.0.1:'+str(origin.server_port)
        if scenario == 'shared deadline':
            ns['CONNECT_SECONDS'] = 0.2
        with tempfile.TemporaryDirectory(prefix='dl.', dir=self.path) as work:
            os.chmod(work, 0o700)
            output = Path(work)/'binary'
            success = scenario in ('exact', 'checksum exact', 'CDN')
            if success:
                ns['download_release'](base, 'warden-linux-amd64', str(output))
                self.assertEqual(output.read_bytes(), payload)
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            else:
                trusted_ca = os.environ.get('CURL_CA_BUNDLE')
                if scenario == 'untrusted TLS':
                    os.environ.pop('CURL_CA_BUNDLE', None)
                try:
                    with self.assertRaises((ValueError, RuntimeError, TimeoutError)):
                        ns['download_release'](base, 'warden-linux-amd64', str(output))
                finally:
                    if trusted_ca is not None:
                        os.environ['CURL_CA_BUNDLE'] = trusted_ca
                self.assertFalse(output.exists())
            self.assertEqual(sorted(p.name for p in Path(work).iterdir()), ['binary'] if success else [])
        if scenario == 'downgrade':
            self.assertFalse(any(hit.startswith('target') for hit in hits))
        if scenario == 'CDN':
            self.assertEqual(len([h for h in hits if h.startswith('target')]), 2)

    def test_streaming_tls_redirect_checksum_deadlines(self):
        for script in ('install-client.sh', 'install-server.sh'):
            for scenario in ('exact', 'checksum exact', 'binary +1', 'checksum +1', 'duplicate', 'bad digest', 'truncated digest', 'path entry', 'truncated body', 'slow headers', 'slow body', 'shared deadline', 'downgrade', 'initial HTTP', 'untrusted TLS', 'CDN'):
                with self.subTest(script=script, scenario=scenario):
                    self.run_case(script, scenario)

    def test_powershell_source_contract_only(self):
        # Not a substitute for native Windows PowerShell execution.
        source = (ROOT/'scripts/install-client.ps1').read_text()
        for required in ('BinaryLimit = 256L << 20', 'ChecksumLimit = 1L << 20',
                         'ConnectMilliseconds = 10000', 'TotalMilliseconds = 300000',
                         'AllowAutoRedirect = false', 'ResponseHeadersRead',
                         'SslPolicyErrors.None', 'FileMode.CreateNew',
                         'Directory.CreateDirectory(path, security)', 'CheckACL(file.GetAccessControl())',
                         'operation.Register', 'input.ReadAsync', 'File.Replace(stage, target, backup)',
                         'InstallBoth', 'binaryPublication.Rollback()', 'configPublication.Rollback()',
                         'expected != null', "PSEdition -ne 'Desktop'"):
            self.assertIn(required, source)
        for forbidden in ('Invoke-WebRequest', 'DownloadFile', 'DangerousAcceptAnyServerCertificateValidator', 'ServicePointManager.ServerCertificateValidationCallback ='):
            self.assertNotIn(forbidden, source)
        self.assertEqual(source.count('new CancellationTokenSource(TotalMilliseconds)'), 1)

    def test_stage_collision_is_never_cleaned_as_owned(self):
        for script in ('install-client.sh', 'install-server.sh'):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix='collision.', dir=self.path) as work:
                ns = downloader(script)
                original = ns['fetch']
                output = Path(work)/'stage'
                def colliding_fetch(*args):
                    output.write_bytes(b'foreign collision')
                    return original(*args)
                ns['fetch'] = colliding_fetch
                with self.assertRaises(FileExistsError):
                    ns['download_release']('https://127.0.0.1:1', 'warden-linux-amd64', str(output))
                self.assertTrue(output.exists(), 'removed a stage never exclusively created by this download')
                self.assertEqual(output.read_bytes(), b'foreign collision')

    def test_standalone_downloaders_are_identical(self):
        a = re.split(r"<<'WARDEN_DOWNLOAD_PY'\s*&?\n", (ROOT/'scripts/install-client.sh').read_text(), maxsplit=1)[1].split('\nWARDEN_DOWNLOAD_PY',1)[0]
        b = re.split(r"<<'WARDEN_DOWNLOAD_PY'\s*&?\n", (ROOT/'scripts/install-server.sh').read_text(), maxsplit=1)[1].split('\nWARDEN_DOWNLOAD_PY',1)[0]
        self.assertEqual(a, b)

if __name__ == '__main__':
    unittest.main()
