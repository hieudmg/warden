//go:build !linux

package crypto

import "errors"

func loadMasterKeyPlatform(path string) ([masterKeySize]byte, error) {
	return [masterKeySize]byte{}, errors.New("master key validation is unsupported on non-linux platforms")
}
