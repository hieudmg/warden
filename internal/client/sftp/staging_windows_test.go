//go:build windows

package sftp

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Native execution is required; cross-compilation does not prove ACL behavior.
func TestWindowsStagingOwnerACLBeforeFirstWrite(t *testing.T) {
	name := filepath.Join(t.TempDir(), "stage")
	writer, err := NewLocalFilesystem().Create(name)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	file, ok := writer.(*os.File)
	if !ok {
		t.Fatal("not an OS file")
	}
	info, err := file.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatalf("prewrite stat=%v err=%v", info, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(user.User.Sid) {
		t.Fatal("stage not owned by current user")
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("stage DACL is inheritable")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		t.Fatal("expected single owner ACE")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
		t.Fatal("stage grants access beyond current owner")
	}
}

func TestWindowsCopyNativePathContainment(t *testing.T) {
	fs := NewLocalFilesystem()
	root := t.TempDir()
	for _, name := range []string{`C:escape`, `C:\escape`, `\rooted`, `\\host\share`, `file:stream`, `NUL.txt`, `alias.`, `alias `} {
		if _, err := containedChild(fs, root, name); err == nil {
			t.Errorf("unsafe native child %q accepted", name)
		}
	}
	for _, name := range []string{"ordinary.txt", ".hidden", "..child", "日本語.txt"} {
		child, err := containedChild(fs, filepath.Join(root, "unused", ".."), name)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(root, child)
		if err != nil || rel != name {
			t.Errorf("native rel=%q err=%v", rel, err)
		}
	}
	src := filepath.Join(t.TempDir(), "source")
	dst := filepath.Join(root, "target")
	if err := os.WriteFile(src, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Copy(Endpoint{FS: fs, Path: src, Identity: "local"}, Endpoint{FS: fs, Path: dst, Identity: "local"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dst)
	if err != nil || string(data) != "new" {
		t.Fatalf("replacement=%q err=%v", data, err)
	}
}
