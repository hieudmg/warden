package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	blobVersion byte = 1
	nonceSize        = 12
	gcmTagSize       = 16
)

type Codec struct {
	Key [masterKeySize]byte
}

func (c Codec) Encrypt(plaintext, aad []byte) ([]byte, error) {
	aead, err := c.aead()
	if err != nil {
		return nil, err
	}

	blob := make([]byte, 1+nonceSize, 1+nonceSize+len(plaintext)+aead.Overhead())
	blob[0] = blobVersion
	nonce := blob[1 : 1+nonceSize]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	return aead.Seal(blob, nonce, plaintext, aad), nil
}

func (c Codec) Decrypt(blob, aad []byte) ([]byte, error) {
	if len(blob) < 1+nonceSize+gcmTagSize {
		return nil, fmt.Errorf("invalid blob length %d", len(blob))
	}
	if blob[0] != blobVersion {
		return nil, fmt.Errorf("unsupported blob version %d", blob[0])
	}

	aead, err := c.aead()
	if err != nil {
		return nil, err
	}

	nonce := blob[1 : 1+nonceSize]
	ciphertext := blob[1+nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt blob: %w", err)
	}

	return plaintext, nil
}

func (c Codec) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(c.Key[:])
	if err != nil {
		return nil, fmt.Errorf("create AES-256 cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM cipher: %w", err)
	}

	return aead, nil
}
