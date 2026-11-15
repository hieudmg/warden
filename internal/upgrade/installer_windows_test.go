//go:build windows

package upgrade

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Native Windows PowerShell 5.1 compile/runtime check of the actual embedded C#
// helper, without installer entry-point, user environment or service effects.
// Positive platform-trusted HTTPS/complete installer execution remains separate.
func TestWindowsPowerShellInstallerPrivateFilesAndHTTPRefusal(t *testing.T) {
	shell, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Fatal("required Windows PowerShell 5.1 unavailable")
	}
	script, err := os.ReadFile("../../scripts/install-client.ps1")
	if err != nil {
		t.Fatal(err)
	}
	_, source, ok := strings.Cut(string(script), "-TypeDefinition @'\n")
	if !ok {
		t.Fatal("missing embedded downloader")
	}
	source, _, ok = strings.Cut(source, "\n'@")
	if !ok {
		t.Fatal("missing C# boundary")
	}
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "Downloader.cs")
	if err := os.WriteFile(sourcePath, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted HTTPS reached handler") }))
	defer srv.Close()
	program := `$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
Add-Type -ReferencedAssemblies ([System.Net.Http.HttpClient].Assembly.Location) -TypeDefinition ([IO.File]::ReadAllText($env:WARDEN_FIXTURE_SOURCE))
$work = Join-Path $env:WARDEN_FIXTURE_ROOT 'private'
[WardenReleaseDownload]::PrivateDirectory($work)
$one = Join-Path $work 'one'
[WardenReleaseDownload]::WritePrivate($one, 'preserve')
$acl = Get-Acl -LiteralPath $one
if (-not $acl.AreAccessRulesProtected -or $acl.Access.Count -ne 1) { throw 'nonprivate file' }
$collision = $false
try { [WardenReleaseDownload]::WritePrivate($one, 'wrong') } catch { $collision = $true }
if (-not $collision -or [IO.File]::ReadAllText($one) -ne 'preserve') { throw 'collision overwritten' }
foreach ($url in @('http://127.0.0.1:1', $env:WARDEN_FIXTURE_HTTPS)) {
    $refused = $false
    try { [WardenReleaseDownload]::Download($url, 'warden.exe', (Join-Path $work 'download'), (Join-Path $work 'SHA256SUMS')) } catch { $refused = $true }
    if (-not $refused) { throw 'unverified URL accepted' }
}
$target = Join-Path $work 'target'
[WardenReleaseDownload]::WritePrivate($target, 'old')
[WardenReleaseDownload]::Publish($one, $target)
if ([IO.File]::ReadAllText($target) -ne 'preserve') { throw 'atomic publish did not replace' }
$next = Join-Path $work 'next'
[WardenReleaseDownload]::WritePrivate($next, 'new binary')
$config = Join-Path $work 'config.json'
[WardenReleaseDownload]::WritePrivate($config, 'original config')
[IO.File]::SetAttributes($config, [IO.FileAttributes]::ReadOnly)
try {
    $refused = $false
    try { [WardenReleaseDownload]::InstallBoth($next, $target, $one, $config) } catch { $refused = $true }
    if (-not $refused -or [IO.File]::ReadAllText($target) -ne 'preserve' -or [IO.File]::ReadAllText($config) -ne 'original config') { throw 'config failure did not roll back' }
} finally { [IO.File]::SetAttributes($config, [IO.FileAttributes]::Normal) }
if (@(Get-ChildItem -LiteralPath $work -Force -Directory).Count -ne 0) { throw 'private publication stages leaked' }
`
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShellCommand(program))
	cmd.Env = append(os.Environ(), "WARDEN_FIXTURE_SOURCE="+sourcePath, "WARDEN_FIXTURE_ROOT="+dir, "WARDEN_FIXTURE_HTTPS="+srv.URL)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native helper: %v\n%s", err, output)
	}
	if ctx.Err() != nil {
		t.Fatal("native helper did not join")
	}
}
