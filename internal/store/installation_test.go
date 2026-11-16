package store

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestSQLiteFileURL(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, path := range []string{"vault.db", filepath.Join("state # %25", "vault.db")} {
		u, err := sqliteFileURL(path)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := url.Parse(u.String())
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Scheme != "file" || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
			t.Fatalf("filename became URI metadata: %s", u)
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		// SQLite's Windows VFS discards the URI path's leading '/' before X:.
		decoded := parsed.Path
		if runtime.GOOS == "windows" && len(filepath.VolumeName(absolute)) == 2 {
			if len(decoded) < 4 || decoded[0] != '/' || decoded[2] != ':' {
				t.Fatalf("drive path lacks /X: prefix: %s", u)
			}
			decoded = decoded[1:]
		}
		if filepath.FromSlash(decoded) != absolute {
			t.Fatalf("URI path %q does not represent native path %q", parsed.Path, absolute)
		}
	}
	// Lexical URL evidence only: this runs on Linux too, not the Windows VFS.
	u := url.URL{Scheme: "file", Path: "/C:/state # %/vault.db"}
	if got, want := u.String(), "file:///C:/state%20%23%20%25/vault.db"; got != want {
		t.Fatalf("drive URI encoding = %q, want %q", got, want)
	}
}

func TestInstallationRelativePathsPublishAndRead(t *testing.T) {
	paths := []string{"vault.db", filepath.Join("state", "vault.db"), filepath.Join("state # %", "vault # %25.db")}
	if runtime.GOOS != "windows" {
		// '?' is legal in Unix filenames, but not in native Windows filenames.
		paths = append(paths, filepath.Join("state ?mode=memory&cache=shared", "vault?mode=memory&_pragma=journal_mode(WAL)#%.db"))
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			t.Chdir(t.TempDir())
			lease, err := ReserveInitialization(path)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			record := []byte(`{"owner_id":"relative-path-fixture"}`)
			if err := CommitInstallation(context.Background(), path, record); err != nil {
				t.Fatalf("publish relative path: %v", err)
			}
			assertInstallationReadPreservesFile(t, path, record)
			if err := CommitInstallation(context.Background(), path, []byte("replacement")); err == nil {
				t.Fatal("replaced existing installation")
			}
			assertInstallationReadPreservesFile(t, path, record)
		})
	}
}

func TestReadInstallationRelativePaths(t *testing.T) {
	for _, path := range []string{"vault.db", filepath.Join("state", "vault.db")} {
		t.Run(path, func(t *testing.T) {
			t.Chdir(t.TempDir())
			absolute, err := filepath.Abs(path)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := ReserveInitialization(absolute)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			record := []byte(`{"owner_id":"reader-fixture"}`)
			if err := CommitInstallation(context.Background(), absolute, record); err != nil {
				t.Fatal(err)
			}
			assertInstallationReadPreservesFile(t, path, record)
		})
	}
}

func assertInstallationReadPreservesFile(t *testing.T, path string, record []byte) {
	t.Helper()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadInstallation(context.Background(), path)
	if err != nil || !bytes.Equal(got, record) {
		t.Fatalf("read relative path: got %q, error %v", got, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("read changed database bytes: %v", err)
	}
	afterInfo, err := os.Stat(path)
	if err != nil || afterInfo.Mode() != info.Mode() {
		t.Fatalf("read changed database mode: %v", err)
	}
	afterEntries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(afterEntries) != len(entries) {
		t.Fatalf("read created sidecars: %v", err)
	}
	for i := range entries {
		if entries[i].Name() != afterEntries[i].Name() {
			t.Fatal("read changed directory entries")
		}
	}
}

func TestInitRefusesInitializedAndConcurrentInit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	lease, err := ReserveInitialization(path)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := ReserveInitialization(path); err == nil {
		other.Close()
		t.Fatal("concurrent init accepted")
	}
	lease.Close()
	lease, err = ReserveInitialization(path)
	if err != nil {
		t.Fatal("could not retry before commit", err)
	}
	lease.Close()
	if err := os.WriteFile(path, []byte("legacy"), 0640); err != nil {
		t.Fatal(err)
	}
	if other, err := ReserveInitialization(path); err == nil {
		other.Close()
		t.Fatal("existing DB accepted")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "legacy" {
		t.Fatal("changed legacy")
	}
}

func TestInitLegacyEncryptedSQLiteArtifactsPreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")
	var key [32]byte
	key[0] = 42
	legacy, err := Open(context.Background(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if _, err := legacy.CreateSSH(context.Background(), SSHProfileForTest("synthetic-legacy", "[]")); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		name := path + suffix
		if err := os.Chmod(name, 0640); err != nil {
			t.Fatal(err)
		}
		files[name], err = os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Contains(files[path], []byte("s3cret")) || bytes.Contains(files[path+"-wal"], []byte("s3cret")) {
		t.Fatal("fixture is not encrypted")
	}
	if lease, err := ReserveInitialization(path); err == nil {
		lease.Close()
		t.Fatal("legacy accepted")
	}
	if _, err := ReadInstallation(context.Background(), path); err == nil {
		t.Fatal("legacy probe accepted")
	}
	for name, want := range files {
		got, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("changed legacy artifact", name, err)
		}
		info, _ := os.Stat(name)
		if info.Mode().Perm() != 0640 {
			t.Fatal("chmod legacy artifact", name)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != len(files) {
		t.Fatal("created managed state on refusal", entries)
	}
}

func TestInitProcessCrashBoundaries(t *testing.T) {
	if path := os.Getenv("WARDEN_TEST_INSTALLATION_CRASH_PATH"); path != "" {
		lease, err := ReserveInitialization(path)
		if err != nil {
			t.Fatal(err)
		}
		_ = lease
		record := []byte(`{"format":1,"owner_id":"crash-fixture"}`)
		if os.Getenv("WARDEN_TEST_INSTALLATION_CRASH_STAGE") == "before-publish" {
			if _, err := stageInstallation(context.Background(), path, record); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := publishInstallation(context.Background(), path, record); err != nil {
				t.Fatal(err)
			}
		}
		os.Exit(23) // Deliberately bypass defers/kernel releases the reservation.
	}
	for _, stage := range []string{"before-publish", "after-publish"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vault.db")
			child := exec.Command(os.Args[0], "-test.run=^TestInitProcessCrashBoundaries$")
			child.Env = append(os.Environ(), "WARDEN_TEST_INSTALLATION_CRASH_PATH="+path, "WARDEN_TEST_INSTALLATION_CRASH_STAGE="+stage)
			if err := child.Run(); err == nil {
				t.Fatal("child did not exit at crash checkpoint")
			} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 23 {
				t.Fatalf("child failed before crash checkpoint: %v", err)
			}
			if stage == "before-publish" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("partial installation visible")
				}
				lease, err := ReserveInitialization(path)
				if err != nil {
					t.Fatal("crash reservation not released", err)
				}
				defer lease.Close()
				if err := publishInstallation(context.Background(), path, []byte(`{"retry":true}`)); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := ReadInstallation(context.Background(), path); err != nil {
					t.Fatal("lost committed identity", err)
				}
				if lease, err := ReserveInitialization(path); err == nil {
					lease.Close()
					t.Fatal("overwrote committed identity")
				}
			}
		})
	}
}

func TestSetupFinalizeAtomicSingleWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	// This low-level publication test uses a tiny synthetic identity. Protocol
	// and envelope validation belongs to the setup finalizer, before persistence.
	record := []byte(`{"format":1,"owner_id":"synthetic"}`)
	if err := publishInstallation(context.Background(), path, nil); err == nil {
		t.Fatal("transaction constraint failure accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed transaction published target")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := publishInstallation(ctx, path, record); err == nil {
		t.Fatal("cancelled commit accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("partial target published")
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- publishInstallation(context.Background(), path, record) }()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("winners %d", winners)
	}
	got, err := ReadInstallation(context.Background(), path)
	if err != nil || string(got) != string(record) {
		t.Fatalf("restart metadata %s %v", got, err)
	}
	if err := publishInstallation(context.Background(), path, []byte("replacement")); err == nil {
		t.Fatal("overwrote identity")
	}
}
