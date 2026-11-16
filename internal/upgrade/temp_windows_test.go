//go:build windows

package upgrade

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

// Must run on Windows: compile-only does not establish ACL or helper behavior.
func TestUpgradeWindowsPrivateStageAndCollision(t *testing.T) {
	dir := t.TempDir()
	file, err := createUpgradeTemp(dir, ".warden.upgrade-")
	if err != nil {
		t.Fatal(err)
	}
	name := file.Name()
	defer os.Remove(name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatal("stage not empty before first write")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	actual, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateUpgradeACL(actual, user.User.Sid); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("private staged bytes")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "collision")
	if err := os.WriteFile(old, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := createPrivateStage(old); err == nil {
		other.Close()
		t.Fatal("accepted file collision")
	}
	assertFileContent(t, old, "preserve")
}
