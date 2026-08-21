package crypto

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
)

const masterKeySize = 32

func LoadMasterKey(path string) ([masterKeySize]byte, error) {
	var key [masterKeySize]byte

	info, err := os.Stat(path)
	if err != nil {
		return key, fmt.Errorf("stat master key %q: %w", path, err)
	}
	if runtime.GOOS == "windows" {
		return key, errors.New("master key validation is unsupported on windows")
	}
	if err := validateMasterKeyPermissions(path, info.Mode()); err != nil {
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
	perm := mode.Perm()
	if perm != 0o600 {
		return fmt.Errorf("master key %q has unsafe permissions %04o: require 0600", path, perm)
	}

	return nil
}
