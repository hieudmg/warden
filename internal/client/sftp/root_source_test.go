package sftp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// All source I/O is fake, including CheckPath. Only path operations delegate to
// the supplied adapter; no test may enumerate or modify a real drive/UNC root.
type rootSourceFilesystem struct {
	Filesystem
	operand, checked, statted, listed string
	info                              os.FileInfo
	entries                           []os.FileInfo
	joined                            bool
}

func (f *rootSourceFilesystem) CheckPath(p string) error {
	f.checked = p
	if p != f.operand {
		return fmt.Errorf("unexpected source check %q", p)
	}
	return nil
}
func (f *rootSourceFilesystem) Lstat(p string) (os.FileInfo, error) {
	f.statted = p
	return f.Stat(p)
}
func (f *rootSourceFilesystem) Stat(p string) (os.FileInfo, error) {
	if p != f.operand {
		return nil, fmt.Errorf("operational root spelling changed to %q", p)
	}
	return f.info, nil
}
func (f *rootSourceFilesystem) ReadDir(p string) ([]os.FileInfo, error) {
	f.listed = p
	if p != f.operand {
		return nil, fmt.Errorf("operational root spelling changed to %q", p)
	}
	return f.entries, nil
}
func (*rootSourceFilesystem) Open(string) (io.ReadCloser, error) {
	return nil, errors.New("unexpected source Open")
}
func (*rootSourceFilesystem) Create(string) (io.WriteCloser, error) {
	return nil, errors.New("unexpected source Create")
}
func (*rootSourceFilesystem) MkdirAll(string, os.FileMode) error {
	return errors.New("unexpected source MkdirAll")
}
func (*rootSourceFilesystem) Chmod(string, os.FileMode) error {
	return errors.New("unexpected source Chmod")
}
func (*rootSourceFilesystem) Rename(string, string) error {
	return errors.New("unexpected source Rename")
}
func (*rootSourceFilesystem) Remove(string) error {
	return errors.New("unexpected source Remove")
}
func (f *rootSourceFilesystem) Join(parts ...string) string {
	f.joined = true
	return f.Filesystem.Join(parts...)
}

// Destination metadata checks must not stat real drive roots either. Directory
// creation, chmod and assertions operate only in this test's disposable target.
type rootTargetFilesystem struct {
	Filesystem
	info os.FileInfo
}

func (f rootTargetFilesystem) CheckPath(string) error            { return nil }
func (f rootTargetFilesystem) Lstat(string) (os.FileInfo, error) { return f.info, nil }

// Deterministic Windows path-operation results, not a Windows path parser.
// The Windows-only companion test uses the actual native filepath operations.
type rootSpellingPaths struct {
	Filesystem
	clean, parent, base string
}

func (f rootSpellingPaths) Clean(string) (string, error) { return f.clean, nil }
func (f rootSpellingPaths) Dir(p string) string {
	if p == `/` || p == `\` {
		return `\` // Native Dir keeps an unqualified root; Abs supplies a drive.
	}
	return f.parent
}
func (f rootSpellingPaths) Base(string) string { return f.base }

var windowsRootSpellings = []struct {
	name, operand, clean string
}{
	{"drive-forward", `C:/`, `C:\`},
	{"drive-backward", `C:\`, `C:\`},
	{"drive-mixed-final-backslash", `C:/\`, `C:\`},
	{"drive-mixed-final-slash", `C:\//`, `C:\`},
	{"rooted-forward", `/`, `C:\`},
	{"rooted-backward", `\`, `C:\`},
	{"unc-no-trailing-separator", `\\host\share`, `\\host\share`},
	{"unc-forward", `//host/share/`, `\\host\share\`},
	{"unc-backward", `\\host\share\`, `\\host\share\`},
	{"unc-mixed-final-backslash", `//host/share\`, `\\host\share\`},
}

func checkCopyRootSourceContentsTarget(t *testing.T, paths Filesystem, operand string) {
	t.Helper()
	for _, entry := range []string{"", ".", "..", `\`, "/", "C:escape"} {
		t.Run("entry="+entry, func(t *testing.T) {
			destination := t.TempDir()
			info, err := os.Stat(destination)
			if err != nil {
				t.Fatal(err)
			}
			source := &rootSourceFilesystem{Filesystem: paths, operand: operand, info: info}
			if entry != "" {
				source.entries = []os.FileInfo{namedEntry{info, entry}}
			}
			target := rootTargetFilesystem{Filesystem: NewLocalFilesystem(), info: info}
			err = Copy(Endpoint{FS: source, Path: operand, Identity: "source"}, Endpoint{FS: target, Path: destination, Identity: "destination"})
			if entry == "" && err != nil {
				t.Errorf("root contents copy failed: %v", err)
			}
			if entry != "" && (err == nil || !strings.Contains(err.Error(), "unsafe entry")) {
				t.Errorf("root exception bypassed entry rejection: %v", err)
			}
			if source.checked != operand || source.statted != operand || source.listed != operand || source.joined {
				t.Errorf("root dispatch changed operational path or joined a root/entry: check=%q stat=%q list=%q joined=%v want=%q", source.checked, source.statted, source.listed, source.joined, operand)
			}
			children, err := os.ReadDir(destination)
			if err != nil || len(children) != 0 {
				t.Errorf("root contents target gained a child: %v %v", children, err)
			}
		})
	}
}

func TestCopyRootSourceSpellingContentsTarget(t *testing.T) {
	for _, tc := range windowsRootSpellings {
		t.Run(tc.name, func(t *testing.T) {
			paths := rootSpellingPaths{Filesystem: NewLocalFilesystem(), clean: tc.clean, parent: tc.clean, base: `\`}
			checkCopyRootSourceContentsTarget(t, paths, tc.operand)
		})
	}
}

func TestCopyNonRootSourceSpellingStillAppendsBasename(t *testing.T) {
	destination := t.TempDir()
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	paths := rootSpellingPaths{Filesystem: NewLocalFilesystem(), clean: `C:\folder`, parent: `C:\`, base: "folder"}
	source := &rootSourceFilesystem{Filesystem: paths, operand: `C:/folder/`, info: info}
	target := rootTargetFilesystem{Filesystem: NewLocalFilesystem(), info: info}
	if err := Copy(Endpoint{FS: source, Path: source.operand, Identity: "source"}, Endpoint{FS: target, Path: destination, Identity: "destination"}); err != nil {
		t.Fatal(err)
	}
	if source.listed != source.operand {
		t.Errorf("operational source changed: %q", source.listed)
	}
	children, err := os.ReadDir(destination)
	if err != nil || len(children) != 1 || children[0].Name() != "folder" || !children[0].IsDir() {
		t.Fatalf("ordinary source lost basename placement: %v %v", children, err)
	}
	if _, err := os.Stat(filepath.Join(destination, "folder")); err != nil {
		t.Fatal(err)
	}
}
