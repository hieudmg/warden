package sftp

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	pkgsftp "github.com/pkg/sftp"
)

type hostileListing struct {
	info os.FileInfo
	name string
}
type infoList []os.FileInfo

func (l infoList) ListAt(out []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(out, l[offset:])
	if n < len(out) {
		return n, io.EOF
	}
	return n, nil
}
func (h hostileListing) Filelist(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	if r.Method == "List" {
		return infoList{namedEntry{h.info, h.name}}, nil
	}
	return infoList{h.info}, nil
}

type joinObservation struct {
	Filesystem
	joined bool
}

func (f *joinObservation) Join(parts ...string) string {
	f.joined = true
	return f.Filesystem.Join(parts...)
}
func (f *joinObservation) Lstat(p string) (os.FileInfo, error) {
	if f.joined {
		return nil, os.ErrPermission
	}
	return f.Filesystem.Lstat(p)
}

func TestActualSFTPHostileListingRejectedBeforeJoin(t *testing.T) {
	// Client.ReadDir filters dot/dotdot, and FileInfo.Name applies POSIX Base
	// to slash-bearing names. Core tests separately inject the original names
	// so Warden's guard cannot depend on that library behavior.
	for _, name := range []string{"", `C:\escape`, `C:relative`, `\\host\share`, `a\b`, "file:stream", "NUL.txt", "trailing."} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			info, err := os.Stat(root)
			if err != nil {
				t.Fatal(err)
			}
			a, b := net.Pipe()
			server := pkgsftp.NewRequestServer(b, pkgsftp.Handlers{FileList: hostileListing{info, name}})
			done := make(chan error, 1)
			go func() { done <- server.Serve() }()
			client, err := pkgsftp.NewClientPipe(a, a)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { client.Close(); server.Close(); <-done }()
			source := &joinObservation{Filesystem: NewRemoteFilesystem(client)}
			destination := t.TempDir()
			target := filepath.Join(destination, "target")
			outside := filepath.Join(destination, "escape")
			if err := os.WriteFile(outside, []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			err = Copy(Endpoint{FS: source, Path: "/source", Identity: "remote"}, Endpoint{FS: NewLocalFilesystem(), Path: target, Identity: "local"})
			if err == nil || source.joined {
				t.Errorf("hostile listing reached Join: joined=%v err=%v", source.joined, err)
			}
			data, err := os.ReadFile(outside)
			if err != nil || string(data) != "old" {
				t.Fatalf("outside target changed: %q %v", data, err)
			}
			entries, err := os.ReadDir(destination)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if e.Name() != "target" && e.Name() != "escape" {
					t.Errorf("unexpected outside entry %q", e.Name())
				}
			}
		})
	}
}

type emptyDirectoryListing struct{ info os.FileInfo }

func (h emptyDirectoryListing) Filelist(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	if r.Method == "List" {
		return infoList{}, nil
	}
	return infoList{h.info}, nil
}

func TestCopyExplicitRemoteDotAndRootSources(t *testing.T) {
	for _, sourcePath := range []string{".", "/"} {
		t.Run(sourcePath, func(t *testing.T) {
			info, err := os.Stat(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			a, b := net.Pipe()
			server := pkgsftp.NewRequestServer(b, pkgsftp.Handlers{FileList: emptyDirectoryListing{info}})
			done := make(chan error, 1)
			go func() { done <- server.Serve() }()
			client, err := pkgsftp.NewClientPipe(a, a)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { client.Close(); server.Close(); <-done }()
			destination := t.TempDir()
			if err := Copy(Endpoint{FS: NewRemoteFilesystem(client), Path: sourcePath, Identity: "remote"}, Endpoint{FS: NewLocalFilesystem(), Path: destination, Identity: "local"}); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(destination)
			if err != nil || len(entries) != 0 {
				t.Fatalf("unexpected target child: %v %v", entries, err)
			}
		})
	}
}

func TestCopyPortableNamesAndExplicitPOSIXPaths(t *testing.T) {
	for _, name := range []string{"ordinary.txt", ".hidden", "..child", "a b.txt", "日本語.txt", "COM0", "COM10.txt"} {
		t.Run(name, func(t *testing.T) {
			src := t.TempDir()
			if err := os.WriteFile(filepath.Join(src, name), []byte("copy"), 0600); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(t.TempDir(), "dst")
			if err := Copy(Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "a"}, Endpoint{FS: NewLocalFilesystem(), Path: dst, Identity: "b"}); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(dst, name))
			if err != nil || string(data) != "copy" {
				t.Fatalf("copied=%q err=%v", data, err)
			}
		})
	}
	t.Run("explicit colon paths remain POSIX paths", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("colon is a POSIX filename, not a native Windows component")
		}
		src := filepath.Join(t.TempDir(), "source:literal")
		if err := os.WriteFile(src, []byte("copy"), 0600); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(t.TempDir(), "target:literal")
		fs, _ := newAdapterSFTP(t, filepath.Dir(dst))
		if err := Copy(Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "local"}, Endpoint{FS: fs, Path: dst, Identity: "remote"}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(dst)
		if err != nil || string(data) != "copy" {
			t.Fatalf("copied=%q err=%v", data, err)
		}
	})
}
