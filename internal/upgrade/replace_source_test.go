package upgrade

import (
	"strings"
	"testing"
)

// windowsHelperDiagnosticProgram adds disposable argument/control probes and
// failure output. Production stays unchanged until the native backup argument
// is observed, rather than inferred solely from an invalid-path exception.
func windowsHelperDiagnosticProgram(t *testing.T) string {
	t.Helper()
	const boundary = "    } catch {\n        Start-Sleep -Milliseconds 250"
	if strings.Count(windowsHelperProgram, boundary) != 1 {
		t.Fatal("cannot instrument the actual replacement catch uniquely")
	}
	return windowsHelperArgumentProbe + strings.Replace(windowsHelperProgram, boundary, windowsHelperFailureDiagnostic, 1)
}

// Probe the same three-string .NET boundary on copies of the actual fixture
// files. No paths or ambient environment are logged, and the real helper's
// source/target stay untouched. C# literal null is independent of PS coercion.
const windowsHelperArgumentProbe = `$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.IO;
public static class WardenHelperArgumentProbe {
    public static void CheckPaths(string source, string target) {
        if (source != Environment.GetEnvironmentVariable("WARDEN_UPGRADE_SOURCE") ||
            target != Environment.GetEnvironmentVariable("WARDEN_UPGRADE_TARGET"))
            throw new IOException("Helper arguments differ from fixture environment.");
        Path.GetFullPath(source);
        Path.GetFullPath(target);
        if (!File.Exists(source) || !File.Exists(target)) throw new IOException("Helper fixture paths absent.");
        Console.WriteLine("Native helper paths: exact environment matches; legal existing files");
    }
    public static string ReplaceProbe(string source, string target, string backup) {
        if (backup != null && backup.Length != 0) throw new IOException("Refuse nonempty probe backup path.");
        Console.WriteLine("Native helper backup argument: "+(backup == null ? "null" : "empty"));
        string stage = source+".binding-control", destination = target+".binding-control";
        bool ownStage = false, ownDestination = false;
        try {
            File.Copy(source, stage, false); ownStage = true;
            File.Copy(target, destination, false); ownDestination = true;
            try {
                File.Replace(stage, destination, backup);
                if (File.Exists(stage) || File.ReadAllText(destination) != File.ReadAllText(source))
                    throw new IOException("Probe replacement bytes or cleanup differ.");
                return "replaced";
            } catch (ArgumentException error) {
                if (File.ReadAllText(destination) != File.ReadAllText(target) || !File.Exists(stage))
                    throw new IOException("Refused probe changed its files.");
                Console.WriteLine("Native helper probe: "+error.GetType().FullName+"; HRESULT="+error.HResult);
                return "argument-refused";
            }
        } finally {
            if (ownStage) File.Delete(stage);
            if (ownDestination) File.Delete(destination);
        }
    }
    public static void LiteralNullControl(string source, string target) {
        if (ReplaceProbe(source, target, null) != "replaced") throw new IOException("C# null control failed.");
        Console.WriteLine("Native helper C# literal-null control: PASS");
    }
}
'@
[WardenHelperArgumentProbe]::CheckPaths($env:WARDEN_UPGRADE_SOURCE, $env:WARDEN_UPGRADE_TARGET)
[WardenHelperArgumentProbe]::LiteralNullControl($env:WARDEN_UPGRADE_SOURCE, $env:WARDEN_UPGRADE_TARGET)
$probeOutcome = [WardenHelperArgumentProbe]::ReplaceProbe($env:WARDEN_UPGRADE_SOURCE, $env:WARDEN_UPGRADE_TARGET, $null)
[Console]::Out.WriteLine('Native helper PowerShell $null outcome: '+$probeOutcome)
$probeOutcome = [WardenHelperArgumentProbe]::ReplaceProbe($env:WARDEN_UPGRADE_SOURCE, $env:WARDEN_UPGRADE_TARGET, [System.Management.Automation.Language.NullString]::Value)
if ($probeOutcome -ne 'replaced') { throw 'PowerShell true-null control failed' }
[Console]::Out.WriteLine('Native helper PowerShell NullString control: PASS')
`

// Only the first failure is reported, and only its exception chain. Paths in
// this fixture are synthetic; no environment dump, credentials or stack traces.
const windowsHelperFailureDiagnostic = `    } catch {
        if (-not $wardenReplaceFailureReported) {
            $wardenReplaceFailureReported = $true
            $cause = $_.Exception
            for ($depth = 0; $null -ne $cause -and $depth -lt 4; $depth++) {
                [Console]::Out.WriteLine('Native replacement exception: '+$cause.GetType().FullName+'; HRESULT='+$cause.HResult+'; '+$cause.Message)
                $cause = $cause.InnerException
            }
        }
        Start-Sleep -Milliseconds 250`

func TestWindowsHelperDiagnosticPreservesProgram(t *testing.T) {
	instrumented := windowsHelperDiagnosticProgram(t)
	if !strings.HasPrefix(instrumented, windowsHelperArgumentProbe) {
		t.Fatal("missing native argument/control probes")
	}
	instrumented = strings.TrimPrefix(instrumented, windowsHelperArgumentProbe)
	const boundary = "    } catch {\n        Start-Sleep -Milliseconds 250"
	if got := strings.Replace(instrumented, windowsHelperFailureDiagnostic, boundary, 1); got != windowsHelperProgram {
		t.Fatal("diagnostics altered actual replacement behavior")
	}
	if strings.Count(instrumented, windowsHelperFailureDiagnostic) != 1 {
		t.Fatal("diagnostics missing or duplicated")
	}
}
