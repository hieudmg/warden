//go:build windows

package upgrade

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Runs the real encoded helper only against disposable ordinary files, never a
// running Warden install. No synthetic downloaded executable is ever executed.
func TestWindowsHelperAtomicReplacementAndFailureCleanup(t *testing.T) {
	shell, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Fatal("required native Windows PowerShell is unavailable")
	}
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "replace", true: "locked failure"}[blocked], func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "warden.exe")
			if err := os.WriteFile(target, []byte("old fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			stage, err := createUpgradeTemp(dir, ".verified-")
			if err != nil {
				t.Fatal(err)
			}
			source := stage.Name()
			if _, err := stage.Write([]byte("new fixture")); err != nil {
				t.Fatal(err)
			}
			if err := stage.Close(); err != nil {
				t.Fatal(err)
			}
			if blocked {
				native, err := windows.UTF16PtrFromString(target)
				if err != nil {
					t.Fatal(err)
				}
				handle, err := windows.CreateFile(native, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer windows.CloseHandle(handle)
			}
			// Same production program; only its retry duration is shortened for a test.
			program := strings.Replace(windowsHelperProgram, "AddSeconds(90)", "AddSeconds(1)", 1)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShellCommand(program))
			cmd.Env = append(os.Environ(), windowsHelperEnv(source, target, 2147483647)...)
			output, err := cmd.CombinedOutput()
			if blocked {
				if err == nil {
					t.Fatal("helper replaced a delete-locked target")
				}
				assertFileContent(t, target, "old fixture")
			} else {
				if err != nil {
					t.Fatalf("%v: %s", err, output)
				}
				assertFileContent(t, target, "new fixture")
			}
			if ctx.Err() != nil {
				t.Fatal("helper did not terminate/join")
			}
			if _, err := os.Stat(source); !os.IsNotExist(err) {
				t.Fatalf("helper stage not cleaned: %v", err)
			}
			assertDirEntries(t, dir, "warden.exe")
		})
	}
}
