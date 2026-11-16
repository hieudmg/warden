package upgrade

import (
	"strings"
	"testing"
)

// windowsHelperDiagnosticProgram adds failure output only to the disposable
// native fixture. Production intentionally retains its original helper until
// the suppressed native exception establishes the cause of replacement failure.
func windowsHelperDiagnosticProgram(t *testing.T) string {
	t.Helper()
	const boundary = "    } catch {\n        Start-Sleep -Milliseconds 250"
	if strings.Count(windowsHelperProgram, boundary) != 1 {
		t.Fatal("cannot instrument the actual replacement catch uniquely")
	}
	return strings.Replace(windowsHelperProgram, boundary, windowsHelperFailureDiagnostic, 1)
}

// Only the first failure is reported, and only its exception chain. Paths in
// this fixture are synthetic; no environment dump, credentials or stack traces.
const windowsHelperFailureDiagnostic = `    } catch {
        if (-not $wardenReplaceFailureReported) {
            $wardenReplaceFailureReported = $true
            $cause = $_.Exception
            for ($depth = 0; $null -ne $cause -and $depth -lt 4; $depth++) {
                Write-Host ('Native replacement exception: '+$cause.GetType().FullName+'; HRESULT='+$cause.HResult+'; '+$cause.Message)
                $cause = $cause.InnerException
            }
        }
        Start-Sleep -Milliseconds 250`

func TestWindowsHelperDiagnosticPreservesProgram(t *testing.T) {
	instrumented := windowsHelperDiagnosticProgram(t)
	const boundary = "    } catch {\n        Start-Sleep -Milliseconds 250"
	if got := strings.Replace(instrumented, windowsHelperFailureDiagnostic, boundary, 1); got != windowsHelperProgram {
		t.Fatal("diagnostics altered actual replacement behavior")
	}
	if strings.Count(instrumented, windowsHelperFailureDiagnostic) != 1 {
		t.Fatal("diagnostics missing or duplicated")
	}
}
