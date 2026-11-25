package agent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"warden/internal/client/sftp"
)

func TestCheckRsyncTreeRejectsWindowsNameCollisions(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fixture stores Windows aliases as distinct entries on a Linux filesystem")
	}
	for _, tc := range []struct{ name, first, second, diagnostic string }{
		{"ascii case", "Report.txt", "report.TXT", "colliding"},
		{"unicode case", "Å.txt", "å.TXT", "colliding"},
		{"uppercase aliases", "I.txt", "ı.txt", "colliding"},
		{"case folding aliases", "K.txt", "K.txt", "colliding"},
		{"DOS short-name alias", "Long File.txt", "LONGFI~1.TXT", "short-name"},
		{"trailing dot", "name", "name.", "unsafe"},
		{"trailing space", "name", "name ", "unsafe"},
		{"alternate data stream", "name", "name:stream", "unsafe"},
		{"backslash", "name", `name\child`, "unsafe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := sftp.NewLocalFilesystem()
			source := sftp.Endpoint{FS: fs, Path: t.TempDir()}
			nested := filepath.Join(source.Path, "nested")
			if err := os.Mkdir(nested, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{tc.first, tc.second} {
				if err := os.WriteFile(filepath.Join(nested, name), []byte("source"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			root := t.TempDir()
			marker := filepath.Join(root, "nested", tc.first)
			if err := os.Mkdir(filepath.Dir(marker), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(marker, []byte("prior"), 0600); err != nil {
				t.Fatal(err)
			}
			missing := filepath.Join(root, "missing")
			for _, dest := range []struct {
				path   string
				exists bool
			}{{missing, false}, {root, true}} {
				err := checkRsyncTree(context.Background(), source, sftp.Endpoint{FS: fs, Path: dest.path}, dest.exists, rsyncTreePolicy{windowsDestination: true})
				if err == nil || !strings.Contains(err.Error(), tc.diagnostic) {
					t.Errorf("target exists=%v: got %v; want %q", dest.exists, err, tc.diagnostic)
				}
			}
			if _, err := os.Lstat(missing); !os.IsNotExist(err) {
				t.Errorf("unexpected destination change: %v", err)
			}
			if got, err := os.ReadFile(marker); err != nil || string(got) != "prior" {
				t.Fatalf("existing destination = %q, %v", got, err)
			}
			if err := checkRsyncTree(context.Background(), source, sftp.Endpoint{FS: fs, Path: missing}, false, rsyncTreePolicy{}); err != nil {
				t.Fatalf("POSIX policy must allow these distinct names: %v", err)
			}
		})
	}
}

type rsyncAliasFilesystem struct{ sftp.Filesystem }

func (fs rsyncAliasFilesystem) Lstat(name string) (os.FileInfo, error) {
	if filepath.Base(name) == "alias.txt" {
		name = filepath.Join(filepath.Dir(name), "actual filename.txt")
	}
	return fs.Filesystem.Lstat(name)
}

func TestCheckRsyncTreeRejectsUnlistedWindowsDestinationAlias(t *testing.T) {
	fs := sftp.NewLocalFilesystem()
	source, target := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "alias.txt"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	prior := filepath.Join(target, "actual filename.txt")
	if err := os.WriteFile(prior, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	err := checkRsyncTree(context.Background(), sftp.Endpoint{FS: fs, Path: source}, sftp.Endpoint{FS: rsyncAliasFilesystem{fs}, Path: target}, true, rsyncTreePolicy{windowsDestination: true})
	if err == nil || !strings.Contains(err.Error(), "alias") {
		t.Fatalf("got %v; want rejection of destination alias", err)
	}
	if got, err := os.ReadFile(prior); err != nil || string(got) != "keep" {
		t.Fatalf("aliased entry = %q, %v", got, err)
	}
}
