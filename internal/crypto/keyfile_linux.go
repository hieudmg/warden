//go:build linux

package crypto

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

func loadMasterKeyPlatform(path string) ([masterKeySize]byte, error) {
	return loadMasterKeyLinux(path, os.Geteuid)
}

func loadMasterKeyLinux(path string, currentEUID func() int) ([masterKeySize]byte, error) {
	var key [masterKeySize]byte

	info, err := os.Stat(path)
	if err != nil {
		return key, fmt.Errorf("stat master key %q: %w", path, err)
	}
	if err := validateMasterKeyPermissions(path, info.Mode()); err != nil {
		return key, err
	}
	if err := validateMasterKeyOwner(path, info, currentEUID()); err != nil {
		return key, err
	}

	file, err := os.Open(path)
	if err != nil {
		return key, fmt.Errorf("open master key %q: %w", path, err)
	}
	defer file.Close()

	if _, err := io.ReadFull(file, key[:]); err != nil {
		clear(key[:])
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return key, fmt.Errorf("master key %q must be exactly 32 bytes", path)
		}
		return key, fmt.Errorf("read master key %q: %w", path, err)
	}

	var extra [1]byte
	n, err := file.Read(extra[:])
	if err != nil && !errors.Is(err, io.EOF) {
		clear(key[:])
		return key, fmt.Errorf("read master key %q: %w", path, err)
	}
	if n != 0 {
		clear(key[:])
		return key, fmt.Errorf("master key %q must be exactly 32 bytes", path)
	}

	return key, nil
}

func validateMasterKeyPermissions(path string, mode os.FileMode) error {
	if mode.Perm() != 0o600 || mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("master key %q has unsafe permissions: require exactly 0600 with no special bits", path)
	}

	return nil
}

func validateMasterKeyOwner(path string, info os.FileInfo, currentEUID int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("master key %q ownership metadata unavailable", path)
	}
	if stat.Uid != uint32(currentEUID) {
		return fmt.Errorf("master key %q has wrong owner uid %d: require uid %d", path, stat.Uid, currentEUID)
	}

	return nil
}
