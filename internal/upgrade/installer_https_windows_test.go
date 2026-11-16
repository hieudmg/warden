//go:build windows

package upgrade

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // Thumbprint identifies only this disposable certificate, not payload integrity.
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// CI-only opt-in: this fixture temporarily trusts its own unique CA in the
// disposable runner's CURRENT USER Root store. It never changes LocalMachine,
// installs Warden, executes downloaded bytes, or relaxes production TLS checks.
// Cross-compilation/Linux mocks cannot establish any native result here.
func TestWindowsPowerShellTrustedHTTPSReleaseMatrix(t *testing.T) {
	if os.Getenv("WARDEN_NATIVE_HTTPS_FIXTURE") != "1" {
		t.Skip("requires explicit disposable-hosted-runner CA-store fixture opt-in")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_OS") != "Windows" {
		t.Fatal("CA-store fixture is restricted to disposable hosted Windows CI")
	}
	shell, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Fatal(err)
	}
	certutil, err := exec.LookPath("certutil.exe")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writePrivate := func(prefix string, data []byte) string {
		t.Helper()
		f, err := createUpgradeTemp(dir, prefix)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return f.Name()
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTemplate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Warden T16 isolated fixture " + serial.Text(16)},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	caFile := writePrivate("ca-", rootDER)
	thumb := sha1.Sum(rootDER)
	thumbprint := strings.ToUpper(hex.EncodeToString(thumb[:]))
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, ca, key)
	if err != nil {
		t.Fatal(err)
	}
	var forbiddenHTTP, crlRequests, peerConnections, payloadRequests atomic.Int32
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ca.crl" {
			forbiddenHTTP.Add(1)
			http.Error(w, "forbidden fixture payload", 500)
			return
		}
		t.Logf("native HTTPS fixture CRL request: %d", crlRequests.Add(1))
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlDER)
	}))
	defer crlServer.Close()
	leaf := &x509.Certificate{SerialNumber: new(big.Int).Add(serial, big.NewInt(1)), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CRLDistributionPoints: []string{crlServer.URL + "/ca.crl"}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: key}
	payload := []byte("synthetic release bytes; never execute")
	sum := sha256.Sum256(payload)
	checksums := fmt.Sprintf("%x  ./warden.exe\n", sum)
	var goodRequests, cdnRequests atomic.Int32
	var cdnURL string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		mode, asset := parts[0], parts[1]
		payloadRequests.Add(1)
		t.Logf("native HTTPS fixture request: mode=%q asset=%q", mode, asset)
		defer t.Logf("native HTTPS fixture request=end: mode=%q asset=%q", mode, asset)
		if mode == "redirect" {
			http.Redirect(w, r, cdnURL+"/cdn/"+asset, http.StatusFound)
			return
		}
		if mode == "downgrade" {
			http.Redirect(w, r, crlServer.URL+"/forbidden", http.StatusFound)
			return
		}
		if mode == "slow-headers" {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(12 * time.Second):
			}
		}
		body := payload
		if asset == "SHA256SUMS" {
			body = []byte(checksums)
			if mode == "bad-digest" {
				body = []byte(strings.Repeat("0", 64) + "  ./warden.exe\n")
			}
			if mode == "duplicate" {
				body = append(body, body...)
			}
		}
		if mode == "truncated" {
			w.Header().Set("Content-Length", fmt.Sprint(len(body)+1))
		}
		if mode == "binary-oversize" && asset == "warden.exe" || mode == "checksum-oversize" && asset == "SHA256SUMS" {
			remaining := int64(256<<20) + 1
			if asset == "SHA256SUMS" {
				remaining = (1 << 20) + 1
			}
			// Exact production limits; no shortened C# constants or Length-only test.
			block := make([]byte, 65536)
			for remaining > 0 {
				n := int64(len(block))
				if n > remaining {
					n = remaining
				}
				if _, err := w.Write(block[:n]); err != nil {
					return
				}
				remaining -= n
			}
			return
		}
		if mode == "exact" {
			goodRequests.Add(1)
		}
		if mode == "cdn" {
			cdnRequests.Add(1)
		}
		_, _ = w.Write(body)
	})
	serve := func(peer string) *httptest.Server {
		srv := httptest.NewUnstartedServer(handler)
		srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				peerConnections.Add(1)
				t.Logf("native HTTPS fixture peer=%s connection=new", peer)
			}
			if state == http.StateActive || state == http.StateClosed {
				t.Logf("native HTTPS fixture peer=%s connection=%s", peer, state)
			}
		}
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}
	cdn := serve("CDN")
	cdnURL = strings.Replace(cdn.URL, "127.0.0.1", "localhost", 1)
	origin := serve("origin")
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted HTTPS reached payload handler") }))
	defer untrusted.Close()
	installer, err := os.ReadFile("../../scripts/install-client.ps1")
	if err != nil {
		t.Fatal(err)
	}
	source, err := installerDownloaderSource(installer)
	if err != nil {
		t.Fatal(err)
	}
	sourceFile := writePrivate("source-", []byte(source))
	env := append(os.Environ(), "WARDEN_FIXTURE_CA="+caFile, "WARDEN_FIXTURE_THUMBPRINT="+thumbprint,
		"WARDEN_FIXTURE_SOURCE="+sourceFile, "WARDEN_FIXTURE_ROOT="+dir, "WARDEN_FIXTURE_ORIGIN="+origin.URL,
		"WARDEN_FIXTURE_UNTRUSTED="+untrusted.URL, "WARDEN_FIXTURE_HTTP="+crlServer.URL)
	defer func() {
		t.Logf("native HTTPS observed counts after process joins: connections=%d payload=%d CRL=%d exact=%d CDN=%d forbiddenHTTP=%d",
			peerConnections.Load(), payloadRequests.Load(), crlRequests.Load(), goodRequests.Load(), cdnRequests.Load(), forbiddenHTTP.Load())
	}()
	runPS := func(ctx context.Context, phase, program string) error {
		cmd := exec.CommandContext(ctx, shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShellCommand(powerShellFixtureProgram(program)))
		cmd.Env = env
		err := runPowerShellFixtureCommand(cmd, func(line string) { t.Logf("native HTTPS %s: %s", phase, line) })
		t.Logf("native HTTPS %s process joined: error=%v context=%v", phase, err, ctx.Err())
		if ctx.Err() != nil {
			return fmt.Errorf("%s context: %w (process: %v)", phase, ctx.Err(), err)
		}
		return err
	}
	// Preflight, import and downloads share the original matrix deadline.
	matrixCtx, cancelMatrix := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelMatrix()
	preflight := `$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion -lt [Version]'5.1') { throw 'Desktop 5.1 required' }
$framework = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release
if ($framework.Release -lt 461808) { throw '.NET4.7.2+ required' }
[Console]::Out.WriteLine('CurrentUser unique-CA-preflight:begin')
$ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($env:WARDEN_FIXTURE_CA)
if ($ca.Thumbprint -ne $env:WARDEN_FIXTURE_THUMBPRINT) { throw 'preflight certificate mismatch' }
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    if ($store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $ca.Thumbprint, $false).Count -ne 0) { throw 'fixture CA already exists; refuse ownership' }
    [Console]::Out.WriteLine('CurrentUser unique-CA-preflight absence:PASS')
} finally { $store.Close() }
`
	if err := runPS(matrixCtx, "preflight", preflight); err != nil {
		t.Fatalf("native current-user CA preflight: %v", err)
	}
	// Arm only after preexisting absence is proven, before any partial import.
	// Independent cleanup also runs if the main PowerShell process is killed.
	// Compare the exact generated certificate bytes before removing its thumbprint.
	cleanup := `$ErrorActionPreference = 'Stop'
[Console]::Out.WriteLine('cleanup certificate-load:begin')
$ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($env:WARDEN_FIXTURE_CA)
if ($ca.Thumbprint -ne $env:WARDEN_FIXTURE_THUMBPRINT) { throw 'cleanup certificate mismatch' }
[Console]::Out.WriteLine('cleanup certificate-load:end')
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
try {
    [Console]::Out.WriteLine('cleanup CurrentUser store-open:begin')
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    [Console]::Out.WriteLine('cleanup CurrentUser store-open:end')
    foreach ($cert in $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $env:WARDEN_FIXTURE_THUMBPRINT, $false)) {
        if ([Convert]::ToBase64String($cert.RawData) -ne [Convert]::ToBase64String($ca.RawData)) { throw 'refuse unrelated certificate cleanup' }
        [Console]::Out.WriteLine('cleanup exact-certificate remove:begin')
        $store.Remove($cert)
        [Console]::Out.WriteLine('cleanup exact-certificate remove:end')
    }
    if ($store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $env:WARDEN_FIXTURE_THUMBPRINT, $false).Count -ne 0) { throw 'fixture CA remains after independent cleanup' }
    [Console]::Out.WriteLine('cleanup exact-certificate absence:PASS')
} finally {
    $store.Close()
    [Console]::Out.WriteLine('cleanup CurrentUser store-close:end')
}
`
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := runPS(ctx, "independent-cleanup", cleanup); err != nil {
			t.Errorf("exact current-user certificate cleanup: %v", err)
		}
	}()
	// Documented test-only CurrentUser CLI alternative; noninteractive behavior
	// remains a native-CI question. Go owns certutil directly, never via PS.
	// Reserve its bounded output-pipe join within, not beyond, the matrix budget.
	deadline, _ := matrixCtx.Deadline()
	importCtx, cancelImport := context.WithDeadline(matrixCtx, deadline.Add(-time.Second))
	cmd := exec.CommandContext(importCtx, certutil, "-user", "-addstore", "Root", caFile)
	cmd.Env = env
	cmd.WaitDelay = time.Second
	t.Log("native HTTPS CurrentUser unique-CA-import:begin")
	importErr := runPowerShellFixtureCommand(cmd, func(line string) { t.Logf("native HTTPS certutil: %s", line) })
	importContextErr := importCtx.Err()
	cancelImport()
	t.Logf("native HTTPS certutil process joined: error=%v context=%v", importErr, importContextErr)
	if importErr != nil || importContextErr != nil {
		t.Fatalf("native current-user CA import: process=%v context=%v", importErr, importContextErr)
	}
	t.Log("native HTTPS CurrentUser unique-CA-import:end")
	program := `$ErrorActionPreference = 'Stop'
[Console]::Out.WriteLine('runtime-check:begin')
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion -lt [Version]'5.1') { throw 'Desktop 5.1 required' }
$framework = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release
if ($framework.Release -lt 461808) { throw '.NET4.7.2+ required' }
[Console]::Out.WriteLine('runtime-check:end')
[Console]::Out.WriteLine('HTTP-assembly-load:begin')
Add-Type -AssemblyName System.Net.Http
[Console]::Out.WriteLine('HTTP-assembly-load:end')
[Console]::Out.WriteLine('actual-CSharp-compile:begin')
Add-Type -ReferencedAssemblies ([System.Net.Http.HttpClient].Assembly.Location) -TypeDefinition ([IO.File]::ReadAllText($env:WARDEN_FIXTURE_SOURCE))
[Console]::Out.WriteLine('actual-CSharp-compile:end')
[Console]::Out.WriteLine('certificate-load:begin')
$ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($env:WARDEN_FIXTURE_CA)
if ($ca.Thumbprint -ne $env:WARDEN_FIXTURE_THUMBPRINT) { throw 'fixture certificate mismatch' }
[Console]::Out.WriteLine('certificate-load:end')
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
$verified = $false
try {
    [Console]::Out.WriteLine('CurrentUser store-open:begin')
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    [Console]::Out.WriteLine('CurrentUser store-open:end')
    $imported = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $ca.Thumbprint, $false)
    if ($imported.Count -ne 1) { throw 'fixture CA import not present exactly once' }
    if ([Convert]::ToBase64String($imported[0].RawData) -ne [Convert]::ToBase64String($ca.RawData)) { throw 'fixture CA imported bytes mismatch' }
    $verified = $true
    [Console]::Out.WriteLine('CurrentUser exact-CA postcondition:PASS')
    foreach ($mode in @('exact', 'redirect', 'downgrade', 'bad-digest', 'duplicate', 'truncated', 'binary-oversize', 'checksum-oversize', 'slow-headers', 'HTTP', 'untrusted')) {
        [Console]::Out.WriteLine('private-directory:begin mode='+$mode)
        $work = Join-Path $env:WARDEN_FIXTURE_ROOT $mode
        [WardenReleaseDownload]::PrivateDirectory($work)
        [Console]::Out.WriteLine('private-directory:end mode='+$mode)
        $url = $env:WARDEN_FIXTURE_ORIGIN+'/'+$mode
        if ($mode -eq 'HTTP') { $url = $env:WARDEN_FIXTURE_HTTP+'/forbidden' }
        if ($mode -eq 'untrusted') { $url = $env:WARDEN_FIXTURE_UNTRUSTED+'/untrusted' }
        $success = $false
        $clock = [Diagnostics.Stopwatch]::StartNew()
        [Console]::Out.WriteLine('actual-download:begin mode='+$mode)
        try {
            [WardenReleaseDownload]::Download($url, 'warden.exe', (Join-Path $work 'binary'), (Join-Path $work 'sums'))
            $success = $true
        } catch { Write-FixtureException $_ }
        [Console]::Out.WriteLine('actual-download:end mode='+$mode+'; success='+$success+'; seconds='+$clock.Elapsed.TotalSeconds)
        if ($success -ne ($mode -eq 'exact' -or $mode -eq 'redirect')) { throw ('unexpected native HTTPS outcome: '+$mode) }
        if ($success -and [IO.File]::ReadAllText((Join-Path $work 'binary')) -ne 'synthetic release bytes; never execute') { throw 'wrong downloaded bytes' }
        if ($mode -eq 'slow-headers' -and ($clock.Elapsed.TotalSeconds -lt 8 -or $clock.Elapsed.TotalSeconds -gt 15)) { throw '10-second establishment/header budget not exercised' }
        [Console]::Out.WriteLine('private-directory-cleanup:begin mode='+$mode)
        Remove-Item -LiteralPath $work -Recurse -Force
        [Console]::Out.WriteLine('Native HTTPS PASS: '+$mode)
    }
} finally {
    try {
        if ($verified) {
            [Console]::Out.WriteLine('CurrentUser unique-CA-remove:begin')
            $store.Remove($ca)
            if ($store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $ca.Thumbprint, $false).Count -ne 0) { throw 'fixture CA remains after main cleanup' }
            [Console]::Out.WriteLine('CurrentUser unique-CA absence:PASS')
        }
    } finally {
        $store.Close()
        [Console]::Out.WriteLine('CurrentUser store-close:end')
    }
}
`
	if err := runPS(matrixCtx, "matrix", program); err != nil {
		t.Fatalf("native trusted HTTPS: %v", err)
	}
	if goodRequests.Load() != 2 || cdnRequests.Load() != 2 {
		t.Fatalf("positive native HTTPS did not fetch both streams: exact=%d CDN=%d", goodRequests.Load(), cdnRequests.Load())
	}
	if forbiddenHTTP.Load() != 0 {
		t.Fatal("initial/downgrade HTTP received payload request")
	}
}
