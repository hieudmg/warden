$ErrorActionPreference = 'Stop'

# Keep all writes in the disposable fixture, and never reach the real config
# publication or user environment updates. The binary move itself is real.
function New-Item($ItemType, [switch] $Force, [string[]] $Path) {
    foreach ($Directory in $Path) {
        if ($Directory.StartsWith((Join-Path $env:TEMP 'warden-client-install-'), [StringComparison]::OrdinalIgnoreCase)) {
            Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $Directory
        }
    }
}

function Read-Host($Prompt) { 'https://fixture.invalid' }

function Invoke-WebRequest($Uri, $OutFile) {
    $Contents = switch ($Uri) {
        'https://fixture.invalid/warden.exe' { 'verified installer binary' }
        'https://fixture.invalid/SHA256SUMS' { "$env:WARDEN_TEST_INSTALLER_HASH  warden.exe" }
        default { throw "unexpected fixture download: $Uri" }
    }
    [IO.File]::WriteAllText($OutFile, $Contents)
}

function Invoke-Contender {
    $env:WARDEN_TEST_INSTALLER_CONTENDER_ACTIVE = '1'
    & $env:WARDEN_TEST_INSTALLER_CONTENDER '-test.run=^TestWindowsInstallerPublicationLockContender$'
    if ($LASTEXITCODE -ne 0) { throw 'updater contender failed' }
}

function Move-Item([switch] $Force, $Path, $LiteralPath, $Destination) {
    $Source = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ([IO.Path]::GetFileName($Source) -ne 'warden.exe') { throw 'unexpected non-binary move' }
    [Console]::WriteLine('fixture entered binary move')
    if ($env:WARDEN_TEST_INSTALLER_PROBE) {
        $Result = (Invoke-Contender) -join "`n"
        if ($Result -notmatch 'contender error: acquire upgrade lock') {
            throw "updater did not observe installer lock: $Result"
        }
        [Console]::WriteLine('fixture contender observed installer lock')
    }
    Microsoft.PowerShell.Management\Move-Item -Force -LiteralPath $Source -Destination $Destination
    throw 'fixture published binary'
}

try {
    & $env:WARDEN_TEST_INSTALLER
    throw 'installer returned without fixture intercepting publication'
} catch {
    $Message = $_.Exception.GetBaseException().Message
    [Console]::WriteLine($Message)
    if ($Message -eq 'fixture published binary') { Invoke-Contender }
}
