# Native execution only on a disposable GitHub-hosted Windows runner.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') { throw 'Disposable hosted Windows fixture only.' }
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'Windows PowerShell Desktop 5.1 is required (not pwsh).'
}
$Framework = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release
if ($Framework.Release -lt 461808) { throw '.NET Framework 4.7.2+ is required.' }
$Go = & go env GOVERSION
if ($LASTEXITCODE -ne 0 -or $Go -ne 'go1.26.11') { throw 'Exact Go1.26.11 is required.' }
Write-Host "Native OS: $([Environment]::OSVersion.VersionString); PS: $($PSVersionTable.PSVersion); .NET release: $($Framework.Release); Go: $Go"
$Work = Join-Path 'C:\w16' ([Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $Work -Force | Out-Null
$env:TEMP = $Work
$env:TMP = $Work
$env:TMPDIR = $Work
$Logs = Join-Path $env:RUNNER_TEMP 'native-security-logs'
New-Item -ItemType Directory -Path $Logs -Force | Out-Null
$Matrix = [ordered]@{
    './internal/client/agent' = @(
        'TestPipeSquatterCannotCollectSecrets',
        'TestAgentTLSRejectsWrongStaleExpiredCertificateAndTimeout',
        'TestAgentTLSRelayCannotReadPayload',
        'TestRuntimeWindowsReaderBlocksStagingUnlink',
        'TestRuntimeACLProtectsNamedPipe',
        'TestRuntimeACLRejectsOtherUser',
        'TestRuntimeWindowsReparseAndReconnect'
    )
    './internal/client/sftp' = @(
        'TestWindowsStagingOwnerACLBeforeFirstWrite',
        'TestWindowsCopyNativePathContainment',
        'TestWindowsCopyRootSourceSpellingContentsTarget',
        'TestRemoteEntryNamesRejectedBeforeJoin',
        'TestActualSFTPHostileListingRejectedBeforeJoin'
    )
    './internal/upgrade' = @(
        'TestUpgradeWindowsPrivateStageAndCollision',
        'TestWindowsHelperAtomicReplacementAndFailureCleanup',
        'TestWindowsPowerShellInstallerPrivateFilesAndHTTPRefusal',
        'TestWindowsPowerShellTrustedHTTPSReleaseMatrix'
    )
}
try {
    foreach ($Package in $Matrix.Keys) {
        $Expected = @($Matrix[$Package])
        $Pattern = '^(' + (($Expected | ForEach-Object { [Regex]::Escape($_) }) -join '|') + ')$'
        $Listed = @(& go test $Package -list $Pattern)
        if ($LASTEXITCODE -ne 0) { throw "Discovery failed: $Package" }
        $Names = @($Listed | Where-Object { $_ -match '^Test' })
        if (@(Compare-Object $Expected $Names).Count -ne 0) { throw "Missing/extra native test names: $Package; listed=$Names" }
        $Name = Split-Path -Leaf $Package
        $Log = Join-Path $Logs ($Name + '.jsonl')
        & go test $Package -run $Pattern -count=1 -timeout=5m -json | Out-File -Encoding utf8 -LiteralPath $Log
        if ($LASTEXITCODE -ne 0) { Get-Content -LiteralPath $Log; throw "Native tests failed: $Package" }
        $Events = @(Get-Content -LiteralPath $Log | ForEach-Object { $_ | ConvertFrom-Json })
        if (@($Events | Where-Object { $_.Action -eq 'skip' }).Count -ne 0) { throw "Native test skipped: $Package (not acceptance)" }
        foreach ($Test in $Expected) {
            $Passed = @($Events | Where-Object { $_.Action -eq 'pass' -and $_.Test -eq $Test })
            if ($Passed.Count -ne 1) { throw "Expected exactly one native pass: $Test" }
        }
        Write-Host "Native PASS: $Package; $($Expected.Count) named tests, zero skips"
    }
} finally {
    Remove-Item -LiteralPath $Work -Recurse -Force
}
