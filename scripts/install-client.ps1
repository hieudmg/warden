#
# Install or update the Windows Warden client from the latest GitHub release.
# Runs entirely in the current user's scope; administrator rights are not
# required.
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts/install-client.ps1

$ErrorActionPreference = 'Stop'

$Repo = if ($env:WARDEN_REPO) { $env:WARDEN_REPO } else { 'hieudmg/warden' }
$ReleaseBaseUrl = if ($env:WARDEN_RELEASE_BASE_URL) {
    $env:WARDEN_RELEASE_BASE_URL.TrimEnd('/')
} else {
    "https://github.com/$Repo/releases/latest/download"
}
$Asset = 'warden.exe'
$InstallDir = if ($env:WARDEN_INSTALL_DIR) {
    [Environment]::ExpandEnvironmentVariables($env:WARDEN_INSTALL_DIR)
} else {
    Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Warden'
}
$ConfigDir = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'warden'
$ConfigPathOverride = if ($env:WARDEN_CLIENT_CONFIG) {
    $env:WARDEN_CLIENT_CONFIG
} elseif ($env:WARDEN_CLIENT_CONFIG_FILE) {
    $env:WARDEN_CLIENT_CONFIG_FILE
} else {
    $null
}
$ConfigFile = if ($ConfigPathOverride) {
    [Environment]::ExpandEnvironmentVariables($ConfigPathOverride)
} else {
    Join-Path $ConfigDir 'client.json'
}
$Work = Join-Path ([IO.Path]::GetTempPath()) ("warden-client-install-" + [Guid]::NewGuid().ToString('N'))

function Fail([string] $Message) {
    throw "ERROR: $Message"
}

function Download-AndVerify([string] $Name, [string] $OutputPath) {
    $Checksums = Join-Path $Work 'SHA256SUMS'
    Invoke-WebRequest -Uri "$ReleaseBaseUrl/$Name" -OutFile $OutputPath
    Invoke-WebRequest -Uri "$ReleaseBaseUrl/SHA256SUMS" -OutFile $Checksums

    $ChecksumLine = Get-Content $Checksums | Where-Object {
        $Parts = $_ -split '\s+'
        $Parts.Count -ge 2 -and (
            $Parts[1] -eq $Name -or
            $Parts[1] -eq "./$Name" -or
            $Parts[1] -eq "*$Name"
        )
    } | Select-Object -First 1
    if (-not $ChecksumLine) {
        Fail "checksum for $Name not found in SHA256SUMS"
    }
    $Expected = ($ChecksumLine -split '\s+')[0].ToLowerInvariant()
    $Actual = (Get-FileHash -Algorithm SHA256 -Path $OutputPath).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected) {
        Fail "checksum verification failed for $Name"
    }
}

function Publish-Binary([string] $Source, [string] $Destination) {
    if (-not ('WardenInstallerPublication' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class WardenInstallerPublication {
    private const uint ReadAttributes = 0x80, Delete = 0x10000;
    private const uint ShareRead = 1, ShareAll = 7, CreateNew = 1, OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000, BackupSemantics = 0x02000000, DeleteOnClose = 0x04000000;
    private const int FileNotFound = 2;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint capacity, uint flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTag {
        public uint Attributes, ReparseTag;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int infoClass, out FileAttributeTag info, uint size);

    public static string CanonicalTarget(string destination) {
        // Attribute-only access with full sharing also works while the updater
        // guards the executable against writes and deletes.
        using (var file = CreateFileW(destination, ReadAttributes, ShareAll, IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero)) {
            if (!file.IsInvalid) {
                FileAttributeTag info;
                if (!GetFileInformationByHandleEx(file, 9, out info, 8)) // FileAttributeTagInfo
                    throw Error("inspect " + destination, Marshal.GetLastWin32Error());
                if ((info.Attributes & 0x410) != 0) // directory or reparse point
                    throw new IOException("expected a regular executable at " + destination);
                string path = FinalPath(file, destination);
                // An 8.3 alias of the executable itself could disappear during
                // the move, changing which sidecar another installer would use.
                if (!String.Equals(Path.GetFileName(path), Path.GetFileName(destination), StringComparison.OrdinalIgnoreCase))
                    throw new IOException("binary destination must use the executable's actual name: " + destination);
                return path;
            }
            int error = Marshal.GetLastWin32Error();
            if (error != FileNotFound) throw Error("open " + destination, error);
        }
        // A first install has no target handle. Resolve the directory instead
        // so aliases still contend for the same pathname as subsequent upgrades.
        string parent = Path.GetDirectoryName(destination);
        using (var directory = CreateFileW(parent, ReadAttributes, ShareAll, IntPtr.Zero, OpenExisting, BackupSemantics, IntPtr.Zero)) {
            if (directory.IsInvalid) throw Error("open " + parent, Marshal.GetLastWin32Error());
            return FinalPath(directory, parent).TrimEnd('\\') + "\\" + Path.GetFileName(destination);
        }
    }

    public static SafeFileHandle AcquireLock(string canonicalTarget) {
        // Match internal/upgrade/replace_windows.go. Never check, remove, or
        // reuse an existing sidecar; the kernel deletes our file on last close.
        var handle = CreateFileW(canonicalTarget + ".upgrade.lock", Delete, ShareRead, IntPtr.Zero,
            CreateNew, DeleteOnClose | OpenReparsePoint, IntPtr.Zero);
        if (!handle.IsInvalid) return handle;
        int error = Marshal.GetLastWin32Error();
        handle.Dispose();
        throw Error("acquire upgrade lock for " + canonicalTarget + " (if an install or upgrade is running, wait and retry)", error);
    }

    private static string FinalPath(SafeFileHandle file, string original) {
        var path = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandleW(file, path, (uint)path.Capacity, 0); // normalized DOS path
        if (length == 0) throw Error("resolve " + original, Marshal.GetLastWin32Error());
        if (length >= path.Capacity) throw new PathTooLongException(original);
        return path.ToString();
    }

    private static Win32Exception Error(string operation, int error) {
        return new Win32Exception(error, operation + ": " + new Win32Exception(error).Message);
    }
}
'@
    }

    $Provider = $null
    $Drive = $null
    $Target = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination, [ref]$Provider, [ref]$Drive)
    if ($Provider.Name -ne 'FileSystem') {
        Fail 'binary destination must be a filesystem path'
    }
    $Canonical = [WardenInstallerPublication]::CanonicalTarget($Target)
    $Lock = [WardenInstallerPublication]::AcquireLock($Canonical)
    try {
        if (-not [string]::Equals($Canonical, [WardenInstallerPublication]::CanonicalTarget($Target), [StringComparison]::Ordinal)) {
            Fail 'binary destination changed while acquiring the upgrade lock; retry the installer'
        }
        Move-Item -Force -LiteralPath $Source -Destination $Target
    } finally {
        $Lock.Dispose()
    }
}

try {
    $ConfigParent = Split-Path -Parent $ConfigFile
    $Directories = @($Work, $InstallDir, $ConfigDir)
    if ($ConfigParent) {
        $Directories += $ConfigParent
    }
    New-Item -ItemType Directory -Force -Path $Directories | Out-Null

    $Existing = $null
    if (Test-Path -LiteralPath $ConfigFile) {
        try {
            $Existing = Get-Content -Raw -LiteralPath $ConfigFile | ConvertFrom-Json
        } catch {
            Fail "cannot read existing client config $ConfigFile`: $($_.Exception.Message)"
        }
    }

    $DefaultEndpoint = if ($Existing -and $Existing.api_base_url) {
        [string]$Existing.api_base_url
    } else {
        'http://127.0.0.1:8080'
    }
    $Endpoint = Read-Host "Warden API endpoint [$DefaultEndpoint]"
    if ([string]::IsNullOrWhiteSpace($Endpoint)) {
        $Endpoint = $DefaultEndpoint
    }
    $Endpoint = $Endpoint.Trim()
    $ParsedEndpoint = $null
    if (-not [Uri]::TryCreate($Endpoint, [UriKind]::Absolute, [ref]$ParsedEndpoint) -or
        ($ParsedEndpoint.Scheme -ne 'http' -and $ParsedEndpoint.Scheme -ne 'https') -or
        [string]::IsNullOrEmpty($ParsedEndpoint.Host) -or
        $ParsedEndpoint.Query -or $ParsedEndpoint.Fragment) {
        Fail 'endpoint must be an http or https URL without query or fragment'
    }

    $BinaryTemp = Join-Path $Work $Asset
    Download-AndVerify $Asset $BinaryTemp
    Publish-Binary $BinaryTemp (Join-Path $InstallDir $Asset)

    if ($Existing) {
        $Existing.api_base_url = $Endpoint
        $ConfigObject = $Existing
    } else {
        $ConfigObject = [ordered]@{
            api_base_url = $Endpoint
            timeout = '30s'
        }
    }
    $ConfigJson = $ConfigObject | ConvertTo-Json -Depth 10
    $ConfigTemp = Join-Path $Work 'client.json'
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($ConfigTemp, "$ConfigJson`n", $Utf8NoBom)
    Move-Item -Force -Path $ConfigTemp -Destination $ConfigFile

    $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $PathEntries = @($UserPath -split ';' | Where-Object { $_ })
    if ($PathEntries -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable('Path', (($PathEntries + $InstallDir) -join ';'), 'User')
    }
    [Environment]::SetEnvironmentVariable('WARDEN_CLIENT_CONFIG', $ConfigFile, 'User')

    Write-Host ''
    Write-Host 'Warden client installed/updated (user scope; no administrator rights required).'
    Write-Host "  Binary: $InstallDir\$Asset"
    Write-Host "  Config: $ConfigFile"
    Write-Host ''
    Write-Host 'Open a new PowerShell window, or use these current-session commands:'
    Write-Host "  `$env:Path += `";$InstallDir`""
    Write-Host "  `$env:WARDEN_CLIENT_CONFIG = `"$ConfigFile`""
    Write-Host ''
    Write-Host 'To update, rerun this installer; existing client config is preserved except endpoint.'
} finally {
    if (Test-Path -LiteralPath $Work) {
        Remove-Item -Recurse -Force -LiteralPath $Work
    }
}
