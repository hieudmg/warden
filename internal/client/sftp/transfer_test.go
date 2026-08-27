package sftp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalFilesystemPathOperations(t *testing.T) {
	fs := NewLocalFilesystem()

	if got := fs.Join("root", "child"); got != filepath.Join("root", "child") {
		t.Fatalf("Join: got %q, want %q", got, filepath.Join("root", "child"))
	}
	if got := fs.Base(filepath.Join("root", "child")); got != "child" {
		t.Fatalf("Base: got %q, want %q", got, "child")
	}
	if got := fs.Dir(filepath.Join("root", "child")); got != filepath.Dir(filepath.Join("root", "child")) {
		t.Fatalf("Dir: got %q, want %q", got, filepath.Dir(filepath.Join("root", "child")))
	}
	rel, err := fs.Rel("root", filepath.Join("root", "child"))
	if err != nil {
		t.Fatalf("Rel: unexpected error: %v", err)
	}
	if rel != "child" {
		t.Fatalf("Rel: got %q, want %q", rel, "child")
	}
	if _, err := fs.Rel("/a/b", "c"); err == nil {
		t.Fatal("Rel: expected error for mixed absolute/relative paths, got nil")
	}
}

func TestLocalFilesystemLstatSeesSymlink(t *testing.T) {
	fs := NewLocalFilesystem()
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	info, err := fs.Lstat(link)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("Lstat: expected ModeSymlink, got %v", info.Mode())
	}
}

func TestLocalFilesystemReadDirReturnsDirectChildren(t *testing.T) {
	fs := NewLocalFilesystem()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "nested.txt"), []byte("n"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("ReadDir: got %d entries, want 2", len(entries))
	}
	names := make(map[string]bool, len(entries))
	for _, e := range entries {
		names[e.Name()] = true
	}
	if !names["a.txt"] || !names["sub"] {
		t.Fatalf("ReadDir: unexpected children %v", names)
	}
}

func TestLocalFilesystemCreateChmodOpen(t *testing.T) {
	fs := NewLocalFilesystem()
	root := t.TempDir()
	p := filepath.Join(root, "file.txt")

	w, err := fs.Create(p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if err := fs.Chmod(p, 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	info, err := fs.Stat(p)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("Chmod: got mode %v, want 0600", info.Mode().Perm())
	}

	r, err := fs.Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("Open: got %q, want %q", data, "hello")
	}
}

func TestLocalFilesystemMkdirAllRenameRemove(t *testing.T) {
	fs := NewLocalFilesystem()
	root := t.TempDir()
	dir := filepath.Join(root, "a", "b")

	if err := fs.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	info, err := fs.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("MkdirAll: directory not created: %v", err)
	}

	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.Rename(src, dst); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := fs.Stat(dst); err != nil {
		t.Fatalf("Rename: destination missing: %v", err)
	}

	if err := fs.Remove(dst); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := fs.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("Remove: destination still exists, err=%v", err)
	}
}

func TestPosixRelMatchesFilepathRel(t *testing.T) {
	cases := [][2]string{
		{"/", "/a"},
		{"/a", "/"},
		{"/a/b", "/a/b"},
		{"/a/b", "/a/b/c"},
		{"/a/b", "/a"},
		{"/a", "/b"},
		{"/a/b", "/a/c/d"},
		{"a", "a/b"},
		{"a/b", "a"},
		{"a", "b"},
		{".", "a"},
		{"a", "."},
		{"/a/b", "c"},
		{"a/b", "/c"},
		{"/a/b/c", "/a/b/c/d/e"},
		{"/a/b/c", "/a/x"},
		{"../a", "b"},
	}
	for _, c := range cases {
		want, wantErr := filepath.Rel(c[0], c[1])
		got, gotErr := posixRel(c[0], c[1])
		if (wantErr == nil) != (gotErr == nil) || got != want {
			t.Fatalf("posixRel(%q, %q) = %q, %v; want %q, %v", c[0], c[1], got, gotErr, want, wantErr)
		}
	}
}

func TestEndpointCarriesIdentity(t *testing.T) {
	fs := NewLocalFilesystem()
	ep := Endpoint{FS: fs, Path: "/tmp/source", Identity: "local"}
	if ep.Identity != "local" {
		t.Fatalf("Identity: got %q, want %q", ep.Identity, "local")
	}
	if ep.FS == nil {
		t.Fatal("FS: expected non-nil filesystem")
	}
	if ep.Path != "/tmp/source" {
		t.Fatalf("Path: got %q, want %q", ep.Path, "/tmp/source")
	}
}

func TestCopyFileOverwritesDestination(t *testing.T) {
	cases := []struct {
		name    string
		srcData string
		dstData string // pre-existing destination content; "" means destination missing
		want    string
	}{
		{name: "missing destination is created", srcData: "new content", dstData: "", want: "new content"},
		{name: "existing destination is overwritten", srcData: "new content", dstData: "old content", want: "new content"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "source.txt")
			dst := filepath.Join(t.TempDir(), "destination.txt")
			if err := os.WriteFile(src, []byte(tc.srcData), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.dstData != "" {
				if err := os.WriteFile(dst, []byte(tc.dstData), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			source := Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "local"}
			destination := Endpoint{FS: NewLocalFilesystem(), Path: dst, Identity: "local"}
			if err := Copy(source, destination); err != nil {
				t.Fatalf("Copy: %v", err)
			}
			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("destination content: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCopyDirectoryIntoExistingDirectoryUsesSourceBase(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	dstDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "deep.txt"), []byte("deep"), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dstDir, "marker.txt")
	if err := os.WriteFile(marker, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	source := Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "local"}
	destination := Endpoint{FS: NewLocalFilesystem(), Path: dstDir, Identity: "local"}
	if err := Copy(source, destination); err != nil {
		t.Fatalf("Copy: %v", err)
	}

	want := map[string]string{
		filepath.Join(dstDir, "src", "hello.txt"):       "hi",
		filepath.Join(dstDir, "src", "sub", "deep.txt"): "deep",
	}
	for p, content := range want {
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("expected %s: %v", p, err)
		}
		if string(got) != content {
			t.Fatalf("content of %s: got %q, want %q", p, got, content)
		}
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("pre-existing destination entries must be preserved: %v", err)
	}
}

func TestCopyDirectoryToMissingDestinationCreatesRoot(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string // slash-relative path -> content
	}{
		{name: "nested file", files: map[string]string{"sub/deep.txt": "deep"}},
		{name: "deep tree", files: map[string]string{"a/b/c.txt": "c", "a/d.txt": "d"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "src")
			if err := os.MkdirAll(src, 0o755); err != nil {
				t.Fatal(err)
			}
			for rel, content := range tc.files {
				p := filepath.Join(src, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			dst := filepath.Join(t.TempDir(), "dst")
			source := Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "local"}
			destination := Endpoint{FS: NewLocalFilesystem(), Path: dst, Identity: "local"}
			if err := Copy(source, destination); err != nil {
				t.Fatalf("Copy: %v", err)
			}
			info, err := os.Stat(dst)
			if err != nil || !info.IsDir() {
				t.Fatalf("destination root not created as directory: %v", err)
			}
			for rel, content := range tc.files {
				got, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(rel)))
				if err != nil {
					t.Fatalf("expected %s: %v", filepath.Join(dst, rel), err)
				}
				if string(got) != content {
					t.Fatalf("content of %s: got %q, want %q", rel, got, content)
				}
			}
		})
	}
}

func TestCopyRejectsLocalDirectoryIntoItself(t *testing.T) {
	rejections := []struct {
		name   string
		dstFor func(src string) string
	}{
		{name: "destination is source itself", dstFor: func(src string) string { return src }},
		{name: "destination is descendant of source", dstFor: func(src string) string { return filepath.Join(src, "sub") }},
		{name: "destination resolves to source base in parent", dstFor: func(src string) string { return filepath.Dir(src) }},
	}
	for _, tc := range rejections {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			src := filepath.Join(root, "src")
			if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			source := Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "local"}
			destination := Endpoint{FS: NewLocalFilesystem(), Path: tc.dstFor(src), Identity: "local"}
			if err := Copy(source, destination); err == nil {
				t.Fatal("Copy: expected self-copy rejection, got nil")
			}
		})
	}

	t.Run("sibling destination is allowed", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "src")
		dstDir := filepath.Join(root, "dst")
		if err := os.MkdirAll(src, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dstDir, 0o755); err != nil {
			t.Fatal(err)
		}
		source := Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "local"}
		destination := Endpoint{FS: NewLocalFilesystem(), Path: dstDir, Identity: "local"}
		if err := Copy(source, destination); err != nil {
			t.Fatalf("Copy: unexpected error: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dstDir, "src", "a.txt")); err != nil {
			t.Fatalf("expected copied file: %v", err)
		}
	})
}

func TestCopyRejectsSourceSymlink(t *testing.T) {
	cases := []struct {
		name string
		link func(root string) (string, error)
	}{
		{name: "symlink to file", link: func(root string) (string, error) {
			target := filepath.Join(root, "target.txt")
			if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
				return "", err
			}
			link := filepath.Join(root, "link.txt")
			return link, os.Symlink(target, link)
		}},
		{name: "symlink to directory", link: func(root string) (string, error) {
			target := filepath.Join(root, "target-dir")
			if err := os.MkdirAll(target, 0o755); err != nil {
				return "", err
			}
			link := filepath.Join(root, "link-dir")
			return link, os.Symlink(target, link)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			link, err := tc.link(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(t.TempDir(), "out")
			source := Endpoint{FS: NewLocalFilesystem(), Path: link, Identity: "local"}
			destination := Endpoint{FS: NewLocalFilesystem(), Path: dst, Identity: "local"}
			if err := Copy(source, destination); err == nil {
				t.Fatal("Copy: expected symlink rejection, got nil")
			}
			if _, err := os.Stat(dst); !os.IsNotExist(err) {
				t.Fatalf("destination should not have been created, err=%v", err)
			}
		})
	}
}

// errWriteFailed is returned by failingWriter after its first successful write.
var errWriteFailed = errors.New("write failed")

// failingWriter lets the first Write through and fails every later one,
// simulating a mid-copy write error on the temporary file.
type failingWriter struct {
	inner  io.WriteCloser
	writes int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes > 1 {
		return 0, errWriteFailed
	}
	return w.inner.Write(p)
}

func (w *failingWriter) Close() error { return w.inner.Close() }

// failingCreateFilesystem wraps a Filesystem so that Create returns writers
// which fail after their first write.
type failingCreateFilesystem struct {
	Filesystem
}

func (f *failingCreateFilesystem) Create(name string) (io.WriteCloser, error) {
	w, err := f.Filesystem.Create(name)
	if err != nil {
		return nil, err
	}
	return &failingWriter{inner: w}, nil
}

func TestCopyRemovesTemporaryFileAfterWriteFailure(t *testing.T) {
	src := filepath.Join(t.TempDir(), "source.bin")
	dst := filepath.Join(t.TempDir(), "destination.bin")
	// Larger than io.Copy's 32KB staging buffer so the copy issues multiple
	// writes through the failing writer and the second one fails.
	data := bytes.Repeat([]byte("x"), 128*1024)
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	fs := NewLocalFilesystem()
	source := Endpoint{FS: fs, Path: src, Identity: "local"}
	destination := Endpoint{FS: &failingCreateFilesystem{Filesystem: fs}, Path: dst, Identity: "local"}

	if err := Copy(source, destination); err == nil {
		t.Fatal("Copy: expected write failure, got nil")
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("destination should remain readable: %v", err)
	}
	if string(got) != "original" {
		t.Fatalf("destination changed after failed copy: got %q, want %q", got, "original")
	}

	matches, err := filepath.Glob(dst + ".warden-cp-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files left behind: %v", matches)
	}
}

func TestCopyAppliesSourceMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o640, 0o755} {
		t.Run(fmt.Sprintf("file mode %o", mode), func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "script.sh")
			dst := filepath.Join(t.TempDir(), "script.sh")
			if err := os.WriteFile(src, []byte("#!/bin/sh\necho hi\n"), mode); err != nil {
				t.Fatal(err)
			}
			srcInfo, err := os.Stat(src)
			if err != nil {
				t.Fatal(err)
			}
			source := Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "local"}
			destination := Endpoint{FS: NewLocalFilesystem(), Path: dst, Identity: "local"}
			if err := Copy(source, destination); err != nil {
				t.Fatalf("Copy: %v", err)
			}
			info, err := os.Stat(dst)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != srcInfo.Mode().Perm() {
				t.Fatalf("destination mode: got %v, want %v", got, srcInfo.Mode().Perm())
			}
		})
	}

	t.Run("directory mode", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "src")
		sub := filepath.Join(src, "sub")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(src, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(sub, 0o750); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(t.TempDir(), "dst")
		source := Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "local"}
		destination := Endpoint{FS: NewLocalFilesystem(), Path: dst, Identity: "local"}
		if err := Copy(source, destination); err != nil {
			t.Fatalf("Copy: %v", err)
		}
		for p, want := range map[string]os.FileMode{dst: 0o700, filepath.Join(dst, "sub"): 0o750} {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != want {
				t.Fatalf("mode of %s: got %v, want %v", p, got, want)
			}
		}
	})
}
