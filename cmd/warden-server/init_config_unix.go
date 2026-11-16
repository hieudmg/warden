//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var synchronizeInitializationAncestor = syncInitializationDirectory

// MkdirAll's new entries need their parents synced before config publication.
// Sync the full resolved ancestry, including existing directories: a prior
// failed/interrupted init may have created them without completing this barrier.
func syncInitializationAncestors(dir string) error {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return err
	}
	var ancestors []string
	for parent := filepath.Dir(resolved); ; parent = filepath.Dir(parent) {
		ancestors = append(ancestors, parent)
		if filepath.Dir(parent) == parent {
			break
		}
	}
	// Persist each ancestor's entry before relying on its descendants. The
	// final config directory's contents still sync after every publication.
	for i := len(ancestors) - 1; i >= 0; i-- {
		if err := synchronizeInitializationAncestor(ancestors[i]); err != nil {
			return fmt.Errorf("sync initialization ancestor %q: %w", ancestors[i], err)
		}
	}
	return nil
}

func publishInitializationConfig(from, to string, replace bool) error {
	if replace {
		return os.Rename(from, to)
	}
	return os.Link(from, to)
}
func syncInitializationDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func lockInitializationConfig(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
