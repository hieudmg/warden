package sftp

import (
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
