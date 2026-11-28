package upgrade

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

//go:embed install_client_windows_test.ps1
var windowsInstallerFixtureScript string

func TestWindowsInstallerPublicationLock(t *testing.T) {
	for _, tc := range []struct {
		name, binaryName       string
		updaterOwnsLock        bool
		pauseUpdaterBeforeLock bool
	}{
		{name: "updater blocks installer through case and dot variants", binaryName: "Warden.EXE", updaterOwnsLock: true},
		{name: "installer blocks updater during publication", binaryName: "Warden.EXE"},
		{name: "pre-lock updater cannot block installer", binaryName: "Warden.EXE", pauseUpdaterBeforeLock: true},
		{name: "first install"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			install := filepath.Join(root, "Warden [Fixture]")
			if err := os.Mkdir(install, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(install, "warden.exe")
			if tc.binaryName != "" {
				target = filepath.Join(install, tc.binaryName)
				if err := os.WriteFile(target, []byte("original binary"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.updaterOwnsLock {
				plan, err := prepareReplacement(target)
				if err != nil {
					t.Fatal(err)
				}
				defer plan.close()
			}

			script, err := filepath.Abs("../../scripts/install-client.ps1")
			if err != nil {
				t.Fatal(err)
			}
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			systemDir, err := windows.GetSystemDirectory()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "powershell.exe"),
				"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePowerShellCommand(windowsInstallerFixtureScript))
			cmd.Env = append(os.Environ(),
				"TEMP="+root, "TMP="+root,
				"WARDEN_INSTALL_DIR="+filepath.Join(root, "wArDeN [fixture]")+`\.`,
				"WARDEN_CLIENT_CONFIG="+filepath.Join(root, "unused-client.json"),
				"WARDEN_RELEASE_BASE_URL=https://fixture.invalid",
				"WARDEN_TEST_INSTALLER="+script, "WARDEN_TEST_INSTALLER_CONTENDER="+self,
				"WARDEN_TEST_INSTALLER_TARGET="+target, "WARDEN_TEST_INSTALLER_HASH="+sha256Hex("verified installer binary"))
			if tc.binaryName != "" && !tc.updaterOwnsLock {
				cmd.Env = append(cmd.Env, "WARDEN_TEST_INSTALLER_PROBE=1")
			} else {
				cmd.Env = append(cmd.Env, "WARDEN_TEST_INSTALLER_PROBE=")
			}
			var out []byte
			var prepareErr error
			if tc.pauseUpdaterBeforeLock {
				// Keep updater preparation on the stack at the lock boundary
				// across the installer's actual binary move.
				var installerRan bool
				plan, prepErr := prepareWindowsReplacement(target, func() {
					installerRan = true
					out, err = cmd.CombinedOutput()
				})
				prepareErr = prepErr
				if prepareErr == nil {
					plan.close()
				}
				if !installerRan {
					t.Fatalf("updater never reached the lock boundary: %v", prepareErr)
				}
			} else {
				out, err = cmd.CombinedOutput()
			}
			if err != nil {
				t.Fatalf("PowerShell fixture failed: %v\n%s", err, out)
			}
			if tc.updaterOwnsLock {
				if !strings.Contains(string(out), "acquire upgrade lock") || strings.Contains(string(out), "fixture entered binary move") {
					t.Fatalf("want installer to refuse busy before attempting publication, got:\n%s", out)
				}
				assertFileContent(t, target, "original binary")
				return
			}
			if tc.pauseUpdaterBeforeLock {
				t.Logf("installer fixture:\n%s", out)
				if !strings.Contains(string(out), "fixture contender observed installer lock") {
					t.Fatalf("fixture did not demonstrate installer lock ownership:\n%s", out)
				}
			}
			if !strings.Contains(string(out), "fixture published binary") {
				t.Fatalf("installer did not publish binary:\n%s", out)
			}
			assertFileContent(t, target, "verified installer binary")
			if !strings.Contains(string(out), "contender acquired lock") {
				t.Fatalf("installer did not release its lock after publication:\n%s", out)
			}
			if tc.pauseUpdaterBeforeLock {
				if prepareErr == nil || !strings.Contains(prepareErr.Error(), "executable identity changed") {
					t.Fatalf("paused updater should reject the newly installed target, got %v", prepareErr)
				}
				if _, err := os.Lstat(target + ".upgrade.lock"); !os.IsNotExist(err) {
					t.Fatalf("updater did not clean up its sidecar after rejecting the changed target: %v", err)
				}
			}
		})
	}
}

func TestWindowsInstallerPublicationLockContender(t *testing.T) {
	if os.Getenv("WARDEN_TEST_INSTALLER_CONTENDER_ACTIVE") != "1" {
		return
	}
	plan, err := prepareReplacement(os.Getenv("WARDEN_TEST_INSTALLER_TARGET"))
	if err != nil {
		fmt.Printf("contender error: %v\n", err)
		return
	}
	plan.close()
	fmt.Println("contender acquired lock")
}
