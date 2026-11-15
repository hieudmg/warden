package sftp

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type namedEntry struct {
	os.FileInfo
	name string
}

func (e namedEntry) Name() string { return e.name }

type entrySource struct {
	Filesystem
	entries []os.FileInfo
	joined  bool
}

func (s *entrySource) ReadDir(string) ([]os.FileInfo, error) { return s.entries, nil }
func (s *entrySource) Lstat(p string) (os.FileInfo, error) {
	if s.joined {
		return nil, errors.New("test guard: unsafe name reached Join")
	}
	return s.Filesystem.Lstat(p)
}
func (s *entrySource) Join(parts ...string) string {
	s.joined = true
	return s.Filesystem.Join(parts...)
}

func TestRemoteEntryNamesRejectedBeforeJoin(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../escape", "a/b", `a\b`, `/root`, `\root`, `\\host\share`, `C:\root`, `C:relative`, "file:stream", "a.", "a ", "NUL", "con.txt", "LPT1", "COM9.log", "CONIN$", "COM¹", "a\x00b", "a?b", "a*b", `a"b`, "a<b", "a>b", "a|b", "invalid-\xff"} {
		t.Run(name, func(t *testing.T) {
			src := t.TempDir()
			dst := filepath.Join(t.TempDir(), "destination")
			info, err := os.Stat(src)
			if err != nil {
				t.Fatal(err)
			}
			source := &entrySource{Filesystem: NewLocalFilesystem(), entries: []os.FileInfo{namedEntry{info, name}}}
			err = Copy(Endpoint{FS: source, Path: src, Identity: "remote"}, Endpoint{FS: NewLocalFilesystem(), Path: dst, Identity: "local"})
			if err == nil {
				t.Error("unsafe entry accepted")
			}
			if source.joined {
				t.Error("unsafe entry reached source Join before rejection")
			}
		})
	}
}

type escapingDestination struct {
	Filesystem
	escape string
}

func (f escapingDestination) Join(parts ...string) string {
	if len(parts) > 1 {
		return f.escape
	}
	return f.Filesystem.Join(parts...)
}
func TestCopyTargetContainment(t *testing.T) {
	t.Run("reject escaped join", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(src, []byte("new"), 0600); err != nil {
			t.Fatal(err)
		}
		dst := t.TempDir()
		escape := filepath.Join(t.TempDir(), "escape")
		err := Copy(Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "a"}, Endpoint{FS: escapingDestination{NewLocalFilesystem(), escape}, Path: dst, Identity: "b"})
		if err == nil {
			t.Error("escaped target accepted")
		}
		if _, err := os.Stat(escape); !os.IsNotExist(err) {
			t.Errorf("outside write: %v", err)
		}
	})
	t.Run("file through symlink ancestor", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "source")
		if err := os.WriteFile(src, []byte("new"), 0600); err != nil {
			t.Fatal(err)
		}
		outside := t.TempDir()
		parent := t.TempDir()
		link := filepath.Join(parent, "link")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		err := Copy(Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "a"}, Endpoint{FS: NewLocalFilesystem(), Path: filepath.Join(link, "file"), Identity: "b"})
		if err == nil {
			t.Error("symlinked file destination accepted")
		}
		entries, err := os.ReadDir(outside)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Error("wrote through symlink ancestor")
		}
	})
	t.Run("cleaned ordinary target", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "report.txt")
		if err := os.WriteFile(src, []byte("new"), 0600); err != nil {
			t.Fatal(err)
		}
		dst := t.TempDir()
		if err := Copy(Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "a"}, Endpoint{FS: NewLocalFilesystem(), Path: filepath.Join(dst, "unused", ".."), Identity: "b"}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dst, "report.txt"))
		if err != nil || string(data) != "new" {
			t.Fatalf("data=%q err=%v", data, err)
		}
	})
}

func TestPosixRelRetainsDotTargetComponent(t *testing.T) {
	for _, tc := range []struct{ base, target, want string }{{"a", ".", "../."}, {"a/b", ".", "../../."}, {"/a", "/", ".."}, {"C:/a", "C:/b", "../b"}, {"/a", "/a/child", "child"}} {
		got, err := posixRel(tc.base, tc.target)
		if err != nil || got != tc.want {
			t.Errorf("Rel(%q,%q)=%q,%v want %q", tc.base, tc.target, got, err, tc.want)
		}
	}
}

var errCopyBoundary = errors.New("injected copy boundary failure")

type closeFaultReader struct {
	io.ReadCloser
	fault string
}

func (r closeFaultReader) Read(b []byte) (int, error) {
	if r.fault == "copy" {
		return 0, errCopyBoundary
	}
	if r.fault == "cancel" {
		return 0, context.Canceled
	}
	return r.ReadCloser.Read(b)
}
func (r closeFaultReader) Close() error {
	err := r.ReadCloser.Close()
	if r.fault == "source-close" {
		return errors.Join(err, errCopyBoundary)
	}
	return err
}

// A cancellation error from an already opened source must follow the same owned-stage cleanup path.
type faultSource struct {
	Filesystem
	fault string
}

func (f faultSource) Open(p string) (io.ReadCloser, error) {
	r, e := f.Filesystem.Open(p)
	if e != nil {
		return nil, e
	}
	return closeFaultReader{r, f.fault}, nil
}

type partialWriteFault struct{ io.WriteCloser }

func (w partialWriteFault) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := w.WriteCloser.Write(p[:1])
	return n, errors.Join(err, errCopyBoundary)
}

type closeFaultWriter struct{ io.WriteCloser }

func (w closeFaultWriter) Close() error { return errors.Join(w.WriteCloser.Close(), errCopyBoundary) }

type faultDestination struct {
	Filesystem
	fault string
}

func (f faultDestination) Create(p string) (io.WriteCloser, error) {
	w, e := f.Filesystem.Create(p)
	if e != nil {
		return nil, e
	}
	if f.fault == "write-close" {
		return closeFaultWriter{w}, nil
	}
	if f.fault == "write" {
		return partialWriteFault{w}, nil
	}
	return w, nil
}
func (f faultDestination) Chmod(p string, m os.FileMode) error {
	if f.fault == "chmod" {
		return errCopyBoundary
	}
	return f.Filesystem.Chmod(p, m)
}
func (f faultDestination) Rename(a, b string) error {
	if f.fault == "rename" {
		return errCopyBoundary
	}
	return f.Filesystem.Rename(a, b)
}
func TestCopyFailurePreservesOldTargetAndCleansStage(t *testing.T) {
	for _, adapter := range []string{"local", "actual-sftp"} {
		t.Run(adapter, func(t *testing.T) {
			for _, fault := range []string{"copy", "write", "cancel", "source-close", "write-close", "chmod", "rename"} {
				t.Run(fault, func(t *testing.T) {
					src := filepath.Join(t.TempDir(), "source")
					dst := filepath.Join(t.TempDir(), "target")
					if err := os.WriteFile(src, []byte("new"), 0644); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(dst, []byte("old"), 0600); err != nil {
						t.Fatal(err)
					}
					source := NewLocalFilesystem()
					if fault == "copy" || fault == "cancel" || fault == "source-close" {
						source = faultSource{source, fault}
					}
					destFS := NewLocalFilesystem()
					if adapter == "actual-sftp" {
						destFS, _ = newAdapterSFTP(t, filepath.Dir(dst))
					}
					destination := faultDestination{destFS, fault}
					copyErr := Copy(Endpoint{FS: source, Path: src, Identity: "a"}, Endpoint{FS: destination, Path: dst, Identity: "b"})
					wantErr := errCopyBoundary
					if fault == "cancel" {
						wantErr = context.Canceled
					}
					if !errors.Is(copyErr, wantErr) {
						t.Fatalf("error=%v want %v", copyErr, wantErr)
					}
					data, err := os.ReadFile(dst)
					if err != nil || string(data) != "old" {
						t.Fatalf("old target=%q err=%v", data, err)
					}
					entries, err := os.ReadDir(filepath.Dir(dst))
					if err != nil {
						t.Fatal(err)
					}
					for _, entry := range entries {
						if strings.Contains(entry.Name(), ".warden-cp-") {
							t.Errorf("left stage %s", entry.Name())
						}
					}
				})
			}
		})
	}
}
