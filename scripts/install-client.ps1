#requires -Version 5.1
# Standalone user-scope installer. Requires Windows PowerShell 5.1 and
# .NET Framework 4.7.2+; PowerShell Core is rejected, not silently downgraded.
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $env:OS -ne 'Windows_NT') {
    throw 'Use Windows PowerShell 5.1 with .NET Framework 4.7.2 or later on Windows.'
}
$Framework = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release
if ($Framework.Release -lt 461808) { throw '.NET Framework 4.7.2 or later is required.' }
Add-Type -AssemblyName System.Net.Http

# Compiled callbacks run without a PowerShell runspace: cancellation closes a
# blocked response stream and awaits the read before returning/cleaning staging.
Add-Type -ReferencedAssemblies ([System.Net.Http.HttpClient].Assembly.Location) -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.AccessControl;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

public static class WardenReleaseDownload {
    const long BinaryLimit = 256L << 20;
    const long ChecksumLimit = 1L << 20;
    const int ConnectMilliseconds = 10000;
    const int TotalMilliseconds = 300000;
    static SecurityIdentifier Owner {
        get { using (var identity = WindowsIdentity.GetCurrent()) return identity.User; }
    }

    static void CheckACL(FileSystemSecurity security) {
        if (!security.AreAccessRulesProtected || !Owner.Equals(security.GetOwner(typeof(SecurityIdentifier))))
            throw new IOException("Staging owner/DACL is not private.");
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
        if (rules.Count != 1) throw new IOException("Staging DACL is not owner-only.");
        var rule = (FileSystemAccessRule)rules[0];
        if (!Owner.Equals(rule.IdentityReference) || rule.AccessControlType != AccessControlType.Allow)
            throw new IOException("Staging DACL grants another principal.");
    }
    public static void PrivateDirectory(string path) {
        if (Directory.Exists(path) || File.Exists(path)) throw new IOException("Staging directory collision.");
        var security = new DirectorySecurity();
        security.SetOwner(Owner);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new FileSystemAccessRule(Owner, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        Directory.CreateDirectory(path, security);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse staging directory.");
        CheckACL(Directory.GetAccessControl(path));
    }
    static FileStream NewPrivateFile(string path) {
        var security = new FileSecurity();
        security.SetOwner(Owner);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new FileSystemAccessRule(Owner, FileSystemRights.FullControl, AccessControlType.Allow));
        var file = new FileStream(path, FileMode.CreateNew, FileSystemRights.FullControl,
            FileShare.None, 65536, FileOptions.None, security);
        try { CheckACL(file.GetAccessControl()); return file; }
        catch { file.Dispose(); File.Delete(path); throw; }
    }
    static Uri HTTPS(string raw) {
        Uri uri;
        if (!Uri.TryCreate(raw, UriKind.Absolute, out uri) || uri.Scheme != Uri.UriSchemeHttps ||
            String.IsNullOrEmpty(uri.Host) || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0)
            throw new IOException("Release URLs and every redirect require verified HTTPS.");
        return uri;
    }
    static async Task Fetch(HttpClient client, string raw, string path, long limit, CancellationToken operation) {
        Uri uri = HTTPS(raw);
        using (var output = NewPrivateFile(path)) {
            for (int hop = 0; hop <= 10; hop++) {
                operation.ThrowIfCancellationRequested();
                HTTPS(uri.AbsoluteUri);
                HttpResponseMessage response;
                using (var request = new HttpRequestMessage(HttpMethod.Get, uri))
                using (var headers = CancellationTokenSource.CreateLinkedTokenSource(operation)) {
                    headers.CancelAfter(ConnectMilliseconds);
                    response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, headers.Token).ConfigureAwait(false);
                }
                using (response) {
                    int status = (int)response.StatusCode;
                    if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
                        var location = response.Headers.Location;
                        if (location == null) throw new IOException("Missing redirect Location.");
                        uri = HTTPS(new Uri(uri, location).AbsoluteUri);
                        continue;
                    }
                    response.EnsureSuccessStatusCode();
                    using (var input = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                    using (operation.Register(delegate { input.Dispose(); })) {
                        long count = 0;
                        var buffer = new byte[65536];
                        while (true) {
                            int n = await input.ReadAsync(buffer, 0, (int)Math.Min(buffer.Length, limit-count+1), operation).ConfigureAwait(false);
                            if (n == 0) break;
                            count += n;
                            if (count > limit) throw new IOException("Release stream exceeds byte limit.");
                            output.Write(buffer, 0, n);
                        }
                        // Content-Length is never trusted for admission/limits.
                        if (response.Content.Headers.ContentLength.HasValue && response.Content.Headers.ContentLength.Value != count)
                            throw new IOException("Truncated release body.");
                    }
                    operation.ThrowIfCancellationRequested();
                    return;
                }
            }
            throw new IOException("Too many release redirects.");
        }
    }
    static string Digest(string path) {
        using (var hash = SHA256.Create())
        using (var file = File.OpenRead(path)) {
            return BitConverter.ToString(hash.ComputeHash(file)).Replace("-", "").ToLowerInvariant();
        }
    }
    static async Task DownloadAsync(string baseURL, string asset, string output, string sums) {
        HTTPS(baseURL);
        using (var operation = new CancellationTokenSource(TotalMilliseconds))
        using (var handler = new HttpClientHandler()) {
            handler.AllowAutoRedirect = false;
            handler.UseCookies = false;
            handler.SslProtocols = SslProtocols.Tls12;
            handler.CheckCertificateRevocationList = true;
            handler.MaxResponseHeadersLength = 128;
            // Own strict validation even if the hosting PowerShell process set
            // a permissive ServicePointManager callback. No caller hook enters.
            handler.ServerCertificateCustomValidationCallback = (request, certificate, chain, errors) =>
                errors == System.Net.Security.SslPolicyErrors.None;
            using (var client = new HttpClient(handler)) {
                client.Timeout = Timeout.InfiniteTimeSpan;
                await Fetch(client, baseURL.TrimEnd('/')+"/"+asset, output, BinaryLimit, operation.Token).ConfigureAwait(false);
                await Fetch(client, baseURL.TrimEnd('/')+"/SHA256SUMS", sums, ChecksumLimit, operation.Token).ConfigureAwait(false);
                string expected = null;
                foreach (string line in File.ReadAllLines(sums, Encoding.ASCII)) {
                    if (line.Length == 0) continue;
                    var match = Regex.Match(line, @"\A([0-9a-fA-F]{64}) [ *](.+)\z");
                    if (!match.Success) throw new IOException("Invalid SHA256SUMS entry.");
                    string name = match.Groups[2].Value;
                    if (name.StartsWith("./", StringComparison.Ordinal)) name = name.Substring(2);
                    if (name == asset) {
                        if (expected != null) throw new IOException("Ambiguous checksum entry.");
                        expected = match.Groups[1].Value.ToLowerInvariant();
                    }
                }
                if (expected == null || expected != Digest(output)) throw new IOException("Missing or incorrect release checksum.");
                operation.Token.ThrowIfCancellationRequested();
            }
        }
    }
    public static void Download(string baseURL, string asset, string output, string sums) {
        DownloadAsync(baseURL, asset, output, sums).GetAwaiter().GetResult();
    }
    sealed class Publication : IDisposable {
        readonly string target, stage, backup, work;
        bool published, retain;
        public Publication(string source, string destination) {
            target = Path.GetFullPath(destination);
            work = Path.Combine(Path.GetDirectoryName(target), ".warden-install-"+Guid.NewGuid().ToString("N"));
            PrivateDirectory(work);
            stage = Path.Combine(work, "new");
            backup = Path.Combine(work, "old");
            try {
                if (Directory.Exists(target) || (File.Exists(target) && (File.GetAttributes(target) & FileAttributes.ReparsePoint) != 0))
                    throw new IOException("Nonregular binary/config target.");
                using (var output = NewPrivateFile(stage))
                using (var input = File.OpenRead(source)) input.CopyTo(output);
            } catch { Directory.Delete(work, true); throw; }
        }
        public void Commit() {
            if (File.Exists(target)) File.Replace(stage, target, backup);
            else File.Move(stage, target);
            published = true;
        }
        public void Rollback() {
            if (!published) return;
            try {
                if (File.Exists(backup)) File.Replace(backup, target, null);
                else File.Delete(target);
                published = false;
            } catch { retain = true; throw; }
        }
        public void Dispose() {
            if (!retain) Directory.Delete(work, true);
        }
    }
    public static void Publish(string source, string target) {
        using (var publication = new Publication(source, target)) publication.Commit();
    }
    public static void InstallBoth(string binary, string binaryTarget, string config, string configTarget) {
        using (var binaryPublication = new Publication(binary, binaryTarget))
        using (var configPublication = new Publication(config, configTarget)) {
            try { binaryPublication.Commit(); configPublication.Commit(); }
            catch (Exception original) {
                var errors = new List<Exception>();
                errors.Add(original);
                try { configPublication.Rollback(); } catch (Exception error) { errors.Add(error); }
                try { binaryPublication.Rollback(); } catch (Exception error) { errors.Add(error); }
                throw new AggregateException("Installation failed; rollback errors retain private staging for recovery.", errors);
            }
        }
    }
    public static void WritePrivate(string path, string text) {
        using (var stream = NewPrivateFile(path)) {
            byte[] data = new UTF8Encoding(false).GetBytes(text);
            stream.Write(data, 0, data.Length);
        }
    }
}
'@

$Repo = if ($env:WARDEN_REPO) { $env:WARDEN_REPO } else { 'hieudmg/warden' }
$ReleaseBaseUrl = if ($env:WARDEN_RELEASE_BASE_URL) { $env:WARDEN_RELEASE_BASE_URL.TrimEnd('/') } else { "https://github.com/$Repo/releases/latest/download" }
$Asset = 'warden.exe'
$InstallDir = if ($env:WARDEN_INSTALL_DIR) { [Environment]::ExpandEnvironmentVariables($env:WARDEN_INSTALL_DIR) } else { Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Warden' }
$ConfigDir = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'warden'
$ConfigOverride = if ($env:WARDEN_CLIENT_CONFIG) { $env:WARDEN_CLIENT_CONFIG } elseif ($env:WARDEN_CLIENT_CONFIG_FILE) { $env:WARDEN_CLIENT_CONFIG_FILE } else { $null }
$ConfigFile = if ($ConfigOverride) { [Environment]::ExpandEnvironmentVariables($ConfigOverride) } else { Join-Path $ConfigDir 'client.json' }
$Work = Join-Path ([IO.Path]::GetTempPath()) ('warden-install-'+[Guid]::NewGuid().ToString('N'))
$OwnWork = $false
try {
    [WardenReleaseDownload]::PrivateDirectory($Work)
    $OwnWork = $true
    $Existing = $null
    if (Test-Path -LiteralPath $ConfigFile) {
        $Existing = Get-Content -Raw -LiteralPath $ConfigFile | ConvertFrom-Json
    }
    $DefaultEndpoint = if ($Existing -and $Existing.api_base_url) { [string]$Existing.api_base_url } else { '' }
    $Endpoint = Read-Host "Warden HTTPS API origin [$DefaultEndpoint]"
    if ([string]::IsNullOrWhiteSpace($Endpoint)) { $Endpoint = $DefaultEndpoint }
    $Endpoint = $Endpoint.Trim()
    $Parsed = $null
    if (-not [Uri]::TryCreate($Endpoint, [UriKind]::Absolute, [ref]$Parsed) -or
        $Parsed.Scheme -ne 'https' -or -not $Parsed.Host -or $Parsed.UserInfo -or
        $Parsed.Query -or $Parsed.Fragment -or $Parsed.AbsolutePath -ne '/') {
        throw 'Endpoint must be an HTTPS origin with no userinfo, path, query or fragment.'
    }
    $BinaryTemp = Join-Path $Work $Asset
    [WardenReleaseDownload]::Download($ReleaseBaseUrl, $Asset, $BinaryTemp, (Join-Path $Work 'SHA256SUMS'))
    if ($Existing) {
        $Existing.api_base_url = $Endpoint
        $ConfigObject = $Existing
    } else {
        $ConfigObject = [ordered]@{ api_base_url = $Endpoint; timeout = '30s' }
    }
    $ConfigTemp = Join-Path $Work 'client.json'
    [WardenReleaseDownload]::WritePrivate($ConfigTemp, (($ConfigObject | ConvertTo-Json -Depth 10)+"`n"))
    $ConfigParent = Split-Path -Parent $ConfigFile
    foreach ($Directory in @($InstallDir, $ConfigParent)) {
        if ($Directory -and -not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory -Force | Out-Null }
    }
    [WardenReleaseDownload]::InstallBoth($BinaryTemp, (Join-Path $InstallDir $Asset), $ConfigTemp, $ConfigFile)
    $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $PathEntries = @($UserPath -split ';' | Where-Object { $_ })
    if ($PathEntries -notcontains $InstallDir) { [Environment]::SetEnvironmentVariable('Path', (($PathEntries+$InstallDir) -join ';'), 'User') }
    [Environment]::SetEnvironmentVariable('WARDEN_CLIENT_CONFIG', $ConfigFile, 'User')
    Write-Host 'Warden client installed/updated (user scope; no administrator rights required).'
    Write-Host "  Binary: $InstallDir\$Asset"
    Write-Host "  Config: $ConfigFile"
    Write-Host 'Open a new PowerShell window. Existing config is preserved except the selected endpoint.'
} finally {
    if ($OwnWork) { Remove-Item -Recurse -Force -LiteralPath $Work }
}
