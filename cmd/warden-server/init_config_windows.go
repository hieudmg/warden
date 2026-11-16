package main

import (
	"golang.org/x/sys/windows"
	"os"
)

// MoveFileExW's documented write-through publication is the Windows barrier.
// Sibling staging never enables COPY_ALLOWED. First publication cannot replace.
// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
func publishInitializationConfig(from, to string, replace bool) error {
	src, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(src, dst, flags)
}
func syncInitializationDirectory(string) error { return nil } // publication above is write-through

// No Unix directory-fsync equivalent is asserted here. Publication retains the
// documented write-through move above; native ancestor durability is unverified.
func syncInitializationAncestors(string) error { return nil }

func lockInitializationConfig(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_FAIL_IMMEDIATELY|windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &windows.Overlapped{})
}
