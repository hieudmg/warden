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
    Move-Item -Force -Path $BinaryTemp -Destination (Join-Path $InstallDir $Asset)

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
