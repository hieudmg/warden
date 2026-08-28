//go:build !windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var dialUnixEndpoint = func(path string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", path, timeout)
}

func runtimeEndpointPath(dir string) string {
	return filepath.Join(dir, runtimeEndpoint)
}

func listenRuntime(runtime *Runtime, path string) (net.Listener, error) {
	listener, err := net.Listen("unix", path)
	if err == nil {
		if err := os.Chmod(path, 0600); err != nil {
			_ = listener.Close()
			_ = os.Remove(path)
			return nil, fmt.Errorf("protect agent socket: %w", err)
		}
		return listener, nil
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		return nil, err
	}

	// An endpoint that accepts a connection belongs to a live agent and must
	// never be removed. Only an actual Unix-socket entry at the exact runtime
	// path is eligible for stale cleanup.
	probe, probeErr := dialUnixEndpoint(path, 100*time.Millisecond)
	if probeErr == nil {
		if probe != nil {
			_ = probe.Close()
		}
		return nil, err
	}
	if !errors.Is(probeErr, syscall.ECONNREFUSED) {
		return nil, err
	}
	info, statErr := os.Lstat(path)
	if statErr != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSocket != os.ModeSocket {
		return nil, err
	}
	if filepath.Dir(path) != runtime.dir {
		return nil, err
	}
	if removeErr := os.Remove(path); removeErr != nil {
		return nil, err
	}

	listener, err = net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("protect agent socket: %w", err)
	}
	return listener, nil
}

func dialRuntime(ctx context.Context, path string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}

func cleanupRuntimeEndpoint(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket != os.ModeSocket {
		return errors.New("agent endpoint is not a Unix socket")
	}
	return os.Remove(path)
}

func ensurePrivateDirectory(path string) error {
	if path == "" {
		return errors.New("agent runtime directory is empty")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("agent runtime directory is a symlink")
		}
		if !info.IsDir() {
			return errors.New("agent runtime path is not a directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("create agent runtime directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("agent runtime path is not a directory")
	}
	if err := os.Chmod(path, 0700); err != nil {
		return fmt.Errorf("protect agent runtime directory: %w", err)
	}
	return nil
}

func validateTokenFileInfo(info os.FileInfo) error {
	if got, want := info.Mode().Perm(), os.FileMode(0600); got != want {
		return fmt.Errorf("agent token permissions are %o, want %o", got, want)
	}
	return nil
}
