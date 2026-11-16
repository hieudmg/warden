//go:build !windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var dialUnixEndpoint = func(path string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", path, timeout)
}

func runtimeEndpointPath(dir string) string { return filepath.Join(dir, runtimeEndpoint) }

func listenRuntime(runtime *Runtime, path string) (net.Listener, error) {
	listener, err := net.Listen("unix", path)
	if err == nil {
		return protectSocket(listener, path)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		return nil, err
	}
	info, statErr := os.Lstat(path)
	if statErr != nil || filepath.Dir(path) != runtime.dir || validateSocketInfo(info) != nil {
		return nil, err
	}
	probe, probeErr := dialUnixEndpoint(path, 100*time.Millisecond)
	if probeErr == nil {
		if probe != nil {
			probe.Close()
		}
		return nil, err
	}
	if !errors.Is(probeErr, syscall.ECONNREFUSED) {
		return nil, err
	}
	after, statErr := os.Lstat(path)
	if statErr != nil || !os.SameFile(info, after) || validateSocketInfo(after) != nil {
		return nil, err
	}
	if removeErr := os.Remove(path); removeErr != nil {
		return nil, err
	}
	listener, err = net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return protectSocket(listener, path)
}
func protectSocket(listener net.Listener, path string) (net.Listener, error) {
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	info, err := os.Lstat(path)
	if err == nil {
		err = validateSocketInfo(info)
	}
	if err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}
func validateSocketInfo(info os.FileInfo) error {
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("agent endpoint is not a Unix socket")
	}
	return validateUnixOwnerMode(info, 0600)
}
func dialRuntime(ctx context.Context, path string) (net.Conn, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := validateSocketInfo(info); err != nil {
		return nil, err
	}
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}

// Every path component is checked; writable sticky roots (e.g. /tmp) are safe
// only because they cannot replace this user's existing child. Final opens use
// O_NOFOLLOW and descriptor validation, never stat-then-read of a new path.
func openPrivateDirectory(path string, create bool) (*privateDirectory, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	current := string(filepath.Separator)
	privateAncestor := false
	for _, part := range strings.Split(strings.TrimPrefix(absolute, current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && create {
			if err := os.Mkdir(current, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return nil, err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("agent runtime ancestor is not a real directory")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0) {
			return nil, errors.New("untrusted agent runtime directory owner")
		}
		if current == absolute {
			if err := validateUnixOwnerMode(info, 0700); err != nil {
				return nil, err
			}
		} else if !privateAncestor && info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return nil, fmt.Errorf("agent runtime ancestor %s is writable by others", current)
		}
		if stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0 {
			privateAncestor = true
		}
	}
	fd, err := unix.Open(absolute, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), absolute)
	info, err := file.Stat()
	if err == nil {
		err = validateUnixOwnerMode(info, 0700)
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		file.Close()
		return nil, err
	}
	anchored, err := root.Stat(".")
	if err != nil || !os.SameFile(info, anchored) {
		root.Close()
		file.Close()
		return nil, errors.New("agent runtime directory changed while opening")
	}
	return &privateDirectory{root: root, file: file}, nil
}
func validateUnixOwnerMode(info os.FileInfo, mode os.FileMode) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("agent runtime object has wrong owner")
	}
	if info.Mode().Perm() != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("agent runtime permissions must be %o", mode)
	}
	return nil
}
func openPrivateChild(directory *os.File, name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("agent runtime credential/lock is not a regular file")
	}
	if err == nil {
		err = validateUnixOwnerMode(info, 0600)
	}
	if err == nil {
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Nlink != 1 {
			err = errors.New("agent runtime file has multiple links")
		}
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
func lockRuntime(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
