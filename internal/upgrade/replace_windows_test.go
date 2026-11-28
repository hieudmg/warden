package upgrade

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestWindowsUpgradeFixture is also the disposable executable image used by
// the native tests. It never reads client state or launches a real agent.
func TestWindowsUpgradeFixture(t *testing.T) {
	switch os.Getenv("WARDEN_TEST_UPGRADE_FIXTURE") {
	case "hold":
		fmt.Println("ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
	case "upgrade", "upgrade-hold":
		result, err := Upgrade(context.Background(), Client, Options{ReleaseBaseURL: os.Getenv("WARDEN_TEST_RELEASE")})
		if err != nil {
			fmt.Printf("error: %v\n", err)
			return
		}
		fmt.Printf("scheduled: %t\n", result.Scheduled)
		if os.Getenv("WARDEN_TEST_UPGRADE_FIXTURE") == "upgrade-hold" {
			_, _ = io.Copy(io.Discard, os.Stdin)
		}
	}
}

type windowsUpgradeFixture struct {
	path, other, oldHash, release, payload string
}

func newWindowsUpgradeFixture(t *testing.T, goodChecksum bool) windowsUpgradeFixture {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "installation [test] & % ' ü")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target, unrelated := filepath.Join(dir, "warden.exe"), filepath.Join(t.TempDir(), "warden.exe")
	for _, file := range []string{target, unrelated} {
		if err := os.WriteFile(file, image, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	payload := string(image) + "separate verified release fixture"
	expected := sha256Hex(payload)
	if !goodChecksum {
		expected = sha256Hex("not the downloaded release")
	}
	srv, _ := releaseServer(t, map[string]string{"/warden.exe": payload, "/" + checksumFile: expected + "  warden.exe\n"})
	return windowsUpgradeFixture{target, unrelated, sha256Hex(string(image)), srv.URL, payload}
}

func startWindowsUpgradeFixture(t *testing.T, path, mode, release string) (string, <-chan struct{}, io.Closer) {
	t.Helper()
	cmd := exec.Command(path, "-test.run=^TestWindowsUpgradeFixture$")
	cmd.Env = append(os.Environ(), "WARDEN_TEST_UPGRADE_FIXTURE="+mode, "WARDEN_TEST_RELEASE="+release)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		reader := bufio.NewReader(output)
		first, err := reader.ReadString('\n')
		if err != nil {
			first += " (" + err.Error() + ")"
		}
		line <- strings.TrimSpace(first)
		_, _ = io.Copy(io.Discard, reader)
		_ = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		_ = input.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill() // This exact process was launched by the test.
			<-done
		}
	})
	select {
	case first := <-line:
		return first, done, input
	case <-time.After(15 * time.Second):
		t.Fatal("fixture did not report readiness")
		return "", nil, nil
	}
}

func assertWindowsFixtureRunning(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		t.Fatal("fixture exited unexpectedly")
	default:
	}
}

func readWindowsUpgradeLog(t *testing.T, target string) string {
	t.Helper()
	dir := filepath.Dir(target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".warden.exe.upgrade-") && strings.HasSuffix(entry.Name(), ".log") {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			return string(data)
		}
	}
	return ""
}

func assertWindowsScheduled(t *testing.T, target, line string) {
	t.Helper()
	if line != "scheduled: true" {
		t.Fatalf("%s\nreplacement log: %q", line, readWindowsUpgradeLog(t, target))
	}
}

func windowsUpgradeLog(t *testing.T, target string, timeout time.Duration, markers ...string) string {
	t.Helper()
	if len(markers) == 0 {
		markers = []string{"Replacement complete", "Replacement failed"}
	}
	deadline := time.Now().Add(timeout)
	var log string
	for time.Now().Before(deadline) {
		log = readWindowsUpgradeLog(t, target)
		for _, marker := range markers {
			if strings.Contains(log, marker) {
				return log
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no replacement status %q after %v: %q", markers, timeout, log)
	return ""
}

func windowsStagingFiles(t *testing.T, target string) []string {
	t.Helper()
	dir := filepath.Dir(target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".warden.exe.upgrade-") && !strings.HasSuffix(entry.Name(), ".log") {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	return files
}

func TestWindowsUpgradeStopsOnlyExactImage(t *testing.T) {
	fx := newWindowsUpgradeFixture(t, true)
	if line, _, _ := startWindowsUpgradeFixture(t, fx.path, "hold", ""); line != "ready" {
		t.Fatal(line)
	}
	line, unrelated, _ := startWindowsUpgradeFixture(t, fx.other, "hold", "")
	if line != "ready" {
		t.Fatal(line)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(fx.path), "client.json"), []byte("fixture configuration"), 0o600); err != nil {
		t.Fatal(err)
	}
	line, _, _ = startWindowsUpgradeFixture(t, fx.path, "upgrade", fx.release)
	assertWindowsScheduled(t, fx.path, line)

	// Check the actual installed digest first, so running against the old helper
	// exposes the held image, not merely its lack of a status log.
	deadline := time.Now().Add(20 * time.Second)
	want := sha256Hex(fx.payload)
	for {
		got, err := fileSHA256(fx.path)
		if err == nil && got == want {
			break
		}
		if os.IsNotExist(err) {
			t.Fatal("installed executable disappeared during replacement")
		}
		if time.Now().After(deadline) {
			t.Fatalf("same-image fixture prevented replacement: digest %q, err %v\nreplacement log: %q", got, err, readWindowsUpgradeLog(t, fx.path))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if log := windowsUpgradeLog(t, fx.path, 5*time.Second); !strings.Contains(log, "Replacement complete") {
		t.Fatalf("unexpected status: %s", log)
	}
	assertWindowsFixtureRunning(t, unrelated)
	if staged := windowsStagingFiles(t, fx.path); len(staged) != 0 {
		t.Fatalf("staging left after successful swap: %v", staged)
	}
	assertFileContent(t, filepath.Join(filepath.Dir(fx.path), "client.json"), "fixture configuration")
	if got, err := fileSHA256(fx.other); err != nil || got != fx.oldHash {
		t.Fatalf("unrelated copy changed: digest %s, error %v", got, err)
	}
}

func TestWindowsUpgradeRejectsReadOnlyTargetWithoutStoppingProcesses(t *testing.T) {
	fx := newWindowsUpgradeFixture(t, true)
	if err := os.Chmod(fx.path, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fx.path, 0o700) })
	line, same, _ := startWindowsUpgradeFixture(t, fx.path, "hold", "")
	if line != "ready" {
		t.Fatal(line)
	}
	if line, _, _ := startWindowsUpgradeFixture(t, fx.path, "upgrade", fx.release); !strings.Contains(line, "read-only") {
		t.Fatalf("want read-only rejection, got %q", line)
	}
	assertWindowsFixtureRunning(t, same)
	assertDirEntries(t, filepath.Dir(fx.path), "warden.exe")
	if got, err := fileSHA256(fx.path); err != nil || got != fx.oldHash {
		t.Fatalf("read-only executable changed: digest %s, error %v", got, err)
	}
}

func TestWindowsUpgradeChecksumFailureDoesNotStopProcesses(t *testing.T) {
	fx := newWindowsUpgradeFixture(t, false)
	line, same, _ := startWindowsUpgradeFixture(t, fx.path, "hold", "")
	if line != "ready" {
		t.Fatal(line)
	}
	if line, _, _ := startWindowsUpgradeFixture(t, fx.path, "upgrade", fx.release); !strings.Contains(line, "checksum mismatch") {
		t.Fatalf("want checksum rejection, got %q", line)
	}
	assertWindowsFixtureRunning(t, same)
	assertDirEntries(t, filepath.Dir(fx.path), "warden.exe")
}

func TestWindowsUpgradeReportsLockedTargetAndRetainsStaging(t *testing.T) {
	fx := newWindowsUpgradeFixture(t, true)
	path, err := windows.UTF16PtrFromString(fx.path)
	if err != nil {
		t.Fatal(err)
	}
	// Not an executable process: the helper must time out rather than removing
	// the destination first or deleting its verified staging file.
	handle, err := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	line, _, _ := startWindowsUpgradeFixture(t, fx.path, "upgrade", fx.release)
	assertWindowsScheduled(t, fx.path, line)
	log := windowsUpgradeLog(t, fx.path, 25*time.Second)
	if !strings.Contains(log, "Replacement failed") || !strings.Contains(log, "timed out") || strings.Contains(log, "Replacement complete") {
		t.Fatalf("unexpected status: %s", log)
	}
	if got, err := fileSHA256(fx.path); err != nil || got != fx.oldHash {
		t.Fatalf("old executable lost: digest %s, error %v", got, err)
	}
	staged := windowsStagingFiles(t, fx.path)
	if len(staged) != 1 {
		t.Fatalf("want one retained staging file, got %v", staged)
	}
	if got, err := fileSHA256(staged[0]); err != nil || got != sha256Hex(fx.payload) {
		t.Fatalf("verified staging lost: digest %s, error %v", got, err)
	}
}

func TestWindowsUpgradeRejectsChangedTargetBetweenRetries(t *testing.T) {
	fx := newWindowsUpgradeFixture(t, true)
	path, err := windows.UTF16PtrFromString(fx.path)
	if err != nil {
		t.Fatal(err)
	}
	// Legacy replace cannot overwrite an open target. The test's POSIX
	// replace can, but only if this handle grants delete sharing.
	original, err := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(original)
	other := filepath.Join(filepath.Dir(fx.path), "external-replacement.exe")
	const replacement = "external replacement: do not overwrite"
	if err := os.WriteFile(other, []byte(replacement), 0o700); err != nil {
		t.Fatal(err)
	}
	line, _, _ := startWindowsUpgradeFixture(t, fx.path, "upgrade", fx.release)
	assertWindowsScheduled(t, fx.path, line)
	windowsUpgradeLog(t, fx.path, 5*time.Second, "Publishing the verified executable.")

	// Simulate an external writer deliberately replacing an open file via
	// NTFS POSIX semantics. The helper's ordinary rename cannot succeed while
	// original is open; once the name changes, the next attempt must fail.
	if err := replaceOpenWindowsTargetForTest(other, fx.path); err != nil {
		t.Fatalf("fixture could not replace the open target using POSIX rename: %v", err)
	}
	log := windowsUpgradeLog(t, fx.path, 10*time.Second)
	if !strings.Contains(log, "Replacement failed: executable identity changed") {
		t.Fatalf("unexpected status: %s", log)
	}
	assertFileContent(t, fx.path, replacement)
	stage := windowsStagingFiles(t, fx.path)
	if len(stage) != 1 {
		t.Fatalf("want one retained staging file, got %v", stage)
	}
	if got, err := fileSHA256(stage[0]); err != nil || got != sha256Hex(fx.payload) {
		t.Fatalf("verified staging lost: digest %s, error %v", got, err)
	}
}

func replaceOpenWindowsTargetForTest(source, destination string) error {
	handle, err := openUpgradeFile(source, windows.DELETE, windows.OPEN_EXISTING, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	name, err := windows.UTF16FromString(destination)
	if err != nil {
		return err
	}
	const nameLengthOffset = 2 * int(unsafe.Sizeof(uintptr(0)))
	buf := make([]byte, nameLengthOffset+4+len(name)*2)
	binary.LittleEndian.PutUint32(buf, 3) // REPLACE_IF_EXISTS | POSIX_SEMANTICS
	binary.LittleEndian.PutUint32(buf[nameLengthOffset:], uint32(2*(len(name)-1)))
	for i, unit := range name {
		binary.LittleEndian.PutUint16(buf[nameLengthOffset+4+2*i:], unit)
	}
	return windows.SetFileInformationByHandle(handle, windows.FileRenameInfoEx, &buf[0], uint32(len(buf)))
}

func TestWindowsUpgradeSurfacesPowerShellParserFailure(t *testing.T) {
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	ready, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(ready)
	path := filepath.Join(t.TempDir(), "replacement.log")
	log, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command(filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "powershell.exe"),
		"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "if (")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	err = startWindowsHelper(cmd, ready, 0, log)
	var exited *exec.ExitError
	if !errors.As(err, &exited) || !strings.Contains(err.Error(), "before readiness") {
		t.Fatalf("want helper startup exit error, got %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ParserError") {
		t.Fatalf("missing PowerShell parser diagnostics: %q", data)
	}
}

func TestWindowsUpgradeWaitsForParentAndRejectsConcurrentUpgrade(t *testing.T) {
	fx := newWindowsUpgradeFixture(t, true)
	line, same, _ := startWindowsUpgradeFixture(t, fx.path, "hold", "")
	if line != "ready" {
		t.Fatal(line)
	}
	line, parent, parentInput := startWindowsUpgradeFixture(t, fx.path, "upgrade-hold", fx.release)
	assertWindowsScheduled(t, fx.path, line)
	if log := readWindowsUpgradeLog(t, fx.path); !strings.Contains(log, "Helper ready; waiting for upgrade command to exit.") {
		t.Fatalf("helper must log readiness while its parent is still running: %q", log)
	}
	if line, _, _ := startWindowsUpgradeFixture(t, fx.path, "upgrade", fx.release); !strings.Contains(line, "lock") {
		t.Fatalf("expected concurrent upgrade to be rejected, got %q", line)
	}
	assertWindowsFixtureRunning(t, parent)
	assertWindowsFixtureRunning(t, same)
	staged := windowsStagingFiles(t, fx.path)
	if len(staged) != 1 {
		t.Fatalf("want one pinned staging file, got %v", staged)
	}
	if file, err := os.OpenFile(staged[0], os.O_WRONLY, 0); err == nil {
		_ = file.Close()
		t.Fatal("verified staging could be opened for writing before publication")
	}
	if got, err := fileSHA256(fx.path); err != nil || got != fx.oldHash {
		t.Fatalf("target changed before parent exit: digest %s, error %v", got, err)
	}
	if err := parentInput.Close(); err != nil {
		t.Fatal(err)
	}
	if log := windowsUpgradeLog(t, fx.path, 20*time.Second); !strings.Contains(log, "Replacement complete") {
		t.Fatalf("unexpected status: %s", log)
	}
	if got, err := fileSHA256(fx.path); err != nil || got != sha256Hex(fx.payload) {
		t.Fatalf("replacement not installed: digest %s, error %v", got, err)
	}
}
