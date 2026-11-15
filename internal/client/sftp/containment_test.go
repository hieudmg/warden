package sftp

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type directoryReadGuard struct {
	Filesystem
	read bool
}

func (f *directoryReadGuard) ReadDir(string) ([]os.FileInfo, error) {
	f.read = true
	return nil, errors.New("test guard: self-copy reached recursive reads")
}
func TestCopyExplicitDotSourcePreservesContentsTarget(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("copy"), 0600); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := Copy(Endpoint{FS: NewLocalFilesystem(), Path: ".", Identity: "local"}, Endpoint{FS: NewLocalFilesystem(), Path: destination, Identity: "local"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(destination, "file"))
	if err != nil || string(data) != "copy" {
		t.Fatalf("contents target moved: %q %v", data, err)
	}
}

func TestCopySourceOperandIdentity(t *testing.T) {
	for _, adapter := range []string{"local", "local-relative", "actual-sftp"} {
		for _, suffix := range []string{"/../file", "/", "/.", "/./"} {
			t.Run(adapter+suffix, func(t *testing.T) {
				root := t.TempDir()
				work, data := filepath.Join(root, "work"), filepath.Join(root, "data")
				for _, dir := range []string{work, filepath.Join(data, "nested")} {
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
				}
				for name, contents := range map[string]string{filepath.Join(work, "file"): "lexically substituted bytes", filepath.Join(data, "file"): "operational bytes", filepath.Join(data, "nested", "child"): "child"} {
					if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
						t.Fatal(err)
					}
				}
				link := filepath.Join(work, "link")
				if err := os.Symlink(filepath.Join(data, "nested"), link); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				fs := NewLocalFilesystem()
				if adapter == "actual-sftp" {
					fs, _ = newAdapterSFTP(t, root)
				}
				// Do not Join: collapsing link/.. would erase the regression.
				operand := filepath.ToSlash(link) + suffix
				if adapter == "local-relative" {
					t.Chdir(work)
					operand = "link" + suffix
				}
				if suffix == "/../file" && runtime.GOOS != "windows" {
					reader, err := fs.Open(operand)
					if err != nil {
						t.Fatal(err)
					}
					contents, readErr := io.ReadAll(reader)
					closeErr := reader.Close()
					if readErr != nil || closeErr != nil || string(contents) != "operational bytes" {
						t.Fatalf("fixture lost operational identity: %q %v %v", contents, readErr, closeErr)
					}
				}
				destination := filepath.Join(t.TempDir(), "target")
				err := Copy(Endpoint{FS: fs, Path: operand}, Endpoint{FS: NewLocalFilesystem(), Path: destination})
				if err == nil || !strings.Contains(err.Error(), "symlink") {
					t.Errorf("source alias was not explicitly rejected: %v", err)
				}
				if _, err := os.Lstat(destination); !os.IsNotExist(err) {
					t.Errorf("source alias created a destination: %v", err)
				}
				stages, err := filepath.Glob(destination + ".warden-cp-*")
				if err != nil || len(stages) != 0 {
					t.Errorf("source alias left stages: %v %v", stages, err)
				}
			})
		}
	}
}

type sourcePathObservation struct {
	Filesystem
	statted, opened string
}

func (f *sourcePathObservation) Lstat(p string) (os.FileInfo, error) {
	f.statted = p
	return f.Filesystem.Lstat(p)
}
func (f *sourcePathObservation) Open(p string) (io.ReadCloser, error) {
	f.opened = p
	return f.Filesystem.Open(p)
}

func TestCopySourceOperationalSpellingPreserved(t *testing.T) {
	for _, adapter := range []string{"local", "actual-sftp"} {
		t.Run(adapter, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "file"), []byte("source"), 0600); err != nil {
				t.Fatal(err)
			}
			fs := NewLocalFilesystem()
			if adapter == "actual-sftp" {
				fs, _ = newAdapterSFTP(t, root)
			}
			source := &sourcePathObservation{Filesystem: fs}
			operand := filepath.ToSlash(root) + "/nested/../file"
			target := filepath.Join(root, "target")
			if err := Copy(Endpoint{FS: source, Path: operand}, Endpoint{FS: NewLocalFilesystem(), Path: target}); err != nil {
				t.Fatal(err)
			}
			if source.statted != operand || source.opened != operand {
				t.Errorf("operational operand changed: Lstat=%q Open=%q want=%q", source.statted, source.opened, operand)
			}
			contents, err := os.ReadFile(target)
			if err != nil || string(contents) != "source" {
				t.Errorf("copied bytes=%q err=%v", contents, err)
			}
		})
	}
}

func TestCopySourceInvalidUncleanedOperand(t *testing.T) {
	for _, adapter := range []string{"local", "actual-sftp"} {
		for _, prefix := range []string{"missing", "not-directory"} {
			t.Run(adapter+"/"+prefix, func(t *testing.T) {
				root := t.TempDir()
				for _, name := range []string{"file", "not-directory", "target"} {
					if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0600); err != nil {
						t.Fatal(err)
					}
				}
				fs := NewLocalFilesystem()
				if adapter == "actual-sftp" {
					fs, _ = newAdapterSFTP(t, root)
				}
				operand := filepath.ToSlash(root) + "/" + prefix + "/../file"
				if _, err := fs.Lstat(operand); err == nil {
					t.Skip("native/server path resolution accepts this spelling")
				}
				target := filepath.Join(root, "target")
				if err := Copy(Endpoint{FS: fs, Path: operand}, Endpoint{FS: NewLocalFilesystem(), Path: target}); err == nil {
					t.Error("invalid operational source was lexically substituted")
				}
				contents, err := os.ReadFile(target)
				if err != nil || string(contents) != "target" {
					t.Errorf("old target changed: %q %v", contents, err)
				}
			})
		}
	}
}

func TestCopyDestinationOperandIdentity(t *testing.T) {
	for _, adapter := range []string{"local", "actual-sftp"} {
		for _, prefix := range []string{"link", "missing", "not-directory"} {
			t.Run(adapter+"/"+prefix, func(t *testing.T) {
				root := t.TempDir()
				work, data := filepath.Join(root, "work"), filepath.Join(root, "data")
				for _, dir := range []string{work, filepath.Join(data, "nested")} {
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
				}
				for _, name := range []string{filepath.Join(work, "file"), filepath.Join(data, "file"), filepath.Join(work, "not-directory"), filepath.Join(root, "source")} {
					if err := os.WriteFile(name, []byte(name), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(filepath.Join(data, "nested"), filepath.Join(work, "link")); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				fs := NewLocalFilesystem()
				if adapter == "actual-sftp" {
					fs, _ = newAdapterSFTP(t, root)
				}
				operand := filepath.ToSlash(work) + "/" + prefix + "/../file"
				if err := Copy(Endpoint{FS: NewLocalFilesystem(), Path: filepath.Join(root, "source")}, Endpoint{FS: fs, Path: operand}); err == nil {
					t.Error("unsafe destination was lexically substituted")
				}
				for _, name := range []string{filepath.Join(work, "file"), filepath.Join(data, "file")} {
					contents, err := os.ReadFile(name)
					if err != nil || string(contents) != name {
						t.Errorf("old target changed: %q %v", contents, err)
					}
					stages, err := filepath.Glob(name + ".warden-cp-*")
					if err != nil || len(stages) != 0 {
						t.Errorf("unexpected stages: %v %v", stages, err)
					}
				}
			})
		}
	}
}

func TestCopySourceAncestorAliasRejectsDescendant(t *testing.T) {
	for _, adapter := range []string{"local", "actual-sftp"} {
		for _, suffix := range []string{"/source", "/nested/../source", "/./source/"} {
			t.Run(adapter+suffix, func(t *testing.T) {
				root := t.TempDir()
				data := filepath.Join(root, "data")
				for _, dir := range []string{filepath.Join(data, "source", "sub"), filepath.Join(data, "nested")} {
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
				}
				link := filepath.Join(root, "link")
				if err := os.Symlink(data, link); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				fs := NewLocalFilesystem()
				if adapter == "actual-sftp" {
					fs, _ = newAdapterSFTP(t, root)
				}
				source := &directoryReadGuard{Filesystem: fs}
				target := filepath.Join(data, "source", "sub")
				err := Copy(Endpoint{FS: source, Path: filepath.ToSlash(link) + suffix, Identity: "same"}, Endpoint{FS: fs, Path: filepath.ToSlash(target), Identity: "same"})
				if err == nil || !strings.Contains(err.Error(), "symlink") || source.read {
					t.Errorf("source alias reached recursive copy: read=%v err=%v", source.read, err)
				}
				if _, err := os.Stat(filepath.Join(target, "source")); !os.IsNotExist(err) {
					t.Errorf("source alias created descendant before rejection: %v", err)
				}
			})
		}
	}
}

func TestCopyTargetContainmentRelativeSourceAbsoluteDescendant(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.MkdirAll(filepath.Join(root, "source", "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	source := &directoryReadGuard{Filesystem: NewLocalFilesystem()}
	err := Copy(Endpoint{FS: source, Path: "source", Identity: "local"}, Endpoint{FS: NewLocalFilesystem(), Path: filepath.Join(root, "source", "sub"), Identity: "local"})
	if err == nil || !strings.Contains(err.Error(), "into itself") || source.read {
		t.Fatalf("self-copy guard: read=%v err=%v", source.read, err)
	}
	if _, err := os.Stat(filepath.Join(root, "source", "sub", "source")); !os.IsNotExist(err) {
		t.Errorf("self-copy created target before rejection: %v", err)
	}
}
