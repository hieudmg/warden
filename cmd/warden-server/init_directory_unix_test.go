//go:build !windows

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"warden/internal/config"
)

func TestInitNestedDirectorySyncBeforePublication(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "parent-symlink"}[alias], func(t *testing.T) {
			root := t.TempDir()
			canonicalRoot, err := filepath.EvalSymlinks(root)
			if err != nil {
				t.Fatal(err)
			}
			inputRoot := root
			if alias {
				inputRoot = filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(root, inputRoot); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(inputRoot, "new-parent", "new-child", "config.json")
			db := filepath.Join(root, "independent-vault.db")
			wantParents := []string{canonicalRoot, filepath.Join(canonicalRoot, "new-parent")}
			var synced []string
			published, called := false, false
			oldAncestor := synchronizeInitializationAncestor
			oldPublication := synchronizeInitializationPublication
			t.Cleanup(func() {
				synchronizeInitializationAncestor = oldAncestor
				synchronizeInitializationPublication = oldPublication
			})
			synchronizeInitializationAncestor = func(dir string) error {
				for _, name := range []string{path, path + ".setup.lock"} {
					if _, err := os.Lstat(name); !os.IsNotExist(err) {
						t.Fatalf("ancestor sync occurred after publication of %s: %v", name, err)
					}
				}
				synced = append(synced, dir)
				return oldAncestor(dir)
			}
			synchronizeInitializationPublication = func(dir string) error {
				previous := -1
				for _, parent := range wantParents {
					index := slices.Index(synced, parent)
					if index <= previous {
						t.Fatalf("missing or out-of-order ancestor sync for %s before config publication; synced %v", parent, synced)
					}
					previous = index
				}
				if dir != filepath.Join(canonicalRoot, "new-parent", "new-child") {
					t.Fatal("publication lost canonical config directory", dir)
				}
				published = true
				return oldPublication(dir)
			}
			answers := db + "\nhttps://warden.example\nwarden.example\nproxy\n127.0.0.1:8080\n\npasskey\n"
			_, _, err = initializeWithAnswers(strings.NewReader(answers), io.Discard, path, func(config.Server) error {
				called = true
				if !published {
					t.Fatal("setup before durable directory/config publication")
				}
				return nil
			})
			if err != nil || !called {
				t.Fatal("initialization did not reach setup", err, called)
			}
			for _, dir := range []string{filepath.Dir(path), filepath.Dir(filepath.Dir(path))} {
				info, err := os.Stat(dir)
				if err != nil || info.Mode().Perm() != 0700 {
					t.Fatal("new config directory not private", dir, info, err)
				}
			}
		})
	}
}

func TestInitAncestorSyncFailurePreventsPublicationAndSetup(t *testing.T) {
	for _, failureParent := range []string{"existing-anchor", "new-parent"} {
		t.Run(failureParent, func(t *testing.T) {
			root := t.TempDir()
			canonicalRoot, err := filepath.EvalSymlinks(root)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "new-parent", "new-child", "config.json")
			db := filepath.Join(root, "independent-vault.db")
			failDir := canonicalRoot
			if failureParent == "new-parent" {
				failDir = filepath.Join(canonicalRoot, "new-parent")
			}
			oldAncestor := synchronizeInitializationAncestor
			oldPublication := synchronizeInitializationPublication
			t.Cleanup(func() {
				synchronizeInitializationAncestor = oldAncestor
				synchronizeInitializationPublication = oldPublication
			})
			sentinel := errors.New("injected ancestor sync failure")
			fail, visited, published, called := true, false, false, false
			synchronizeInitializationAncestor = func(dir string) error {
				if dir == failDir {
					visited = true
					if fail {
						return sentinel
					}
				}
				return oldAncestor(dir)
			}
			synchronizeInitializationPublication = func(dir string) error {
				published = true
				return oldPublication(dir)
			}
			answers := db + "\nhttps://warden.example\nwarden.example\nproxy\n127.0.0.1:8080\n\npasskey\n"
			run := func() error {
				_, _, err := initializeWithAnswers(strings.NewReader(answers), io.Discard, path, func(config.Server) error {
					called = true
					return nil
				})
				return err
			}
			err = run()
			if !errors.Is(err, sentinel) || !visited || published || called {
				t.Fatalf("ancestor sync failure did not prevent publication/setup: err=%v visited=%v published=%v setup=%v", err, visited, published, called)
			}
			for _, name := range []string{path, path + ".setup.lock", db} {
				if _, err := os.Lstat(name); !os.IsNotExist(err) {
					t.Fatalf("created %s after ancestor sync failure: %v", name, err)
				}
			}
			// Failure leaves directories behind. Retry must synchronize their entries
			// again, not mistake their existence for durability from an earlier run.
			fail, visited = false, false
			if err := run(); err != nil || !visited || !published || !called {
				t.Fatalf("retry bypassed the ancestor barrier: err=%v visited=%v published=%v setup=%v", err, visited, published, called)
			}
		})
	}
}
