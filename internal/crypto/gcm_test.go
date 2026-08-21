package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestCodecEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	codec := Codec{Key: testKey(1)}
	plaintext := []byte("super-secret-password")
	aad := []byte("warden/ssh/42/password")

	blob, err := codec.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if blob[0] != 1 {
		t.Fatalf("blob version = %d, want 1", blob[0])
	}
	if got, want := len(blob), 1+12+len(plaintext)+16; got != want {
		t.Fatalf("len(blob) = %d, want %d", got, want)
	}

	got, err := codec.Decrypt(blob, aad)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt() = %q, want %q", got, plaintext)
	}
}

func TestCodecEncryptUsesFreshNonce(t *testing.T) {
	t.Parallel()

	codec := Codec{Key: testKey(2)}
	plaintext := []byte("same-plaintext")
	aad := []byte("warden/db/9/password")

	blob1, err := codec.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt() first call error = %v", err)
	}
	blob2, err := codec.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt() second call error = %v", err)
	}
	if bytes.Equal(blob1, blob2) {
		t.Fatal("Encrypt() reused blob for repeated plaintext")
	}
	if bytes.Equal(blob1[1:13], blob2[1:13]) {
		t.Fatal("Encrypt() reused nonce for repeated plaintext")
	}
}

func TestCodecDecryptRejectsTampering(t *testing.T) {
	t.Parallel()

	codec := Codec{Key: testKey(3)}
	blob, err := codec.Encrypt([]byte("top-secret"), []byte("warden/ssh/7/private_key"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0xff

	if _, err := codec.Decrypt(tampered, []byte("warden/ssh/7/private_key")); err == nil {
		t.Fatal("Decrypt() error = nil, want authentication error")
	}
}

func TestCodecDecryptRejectsWrongKey(t *testing.T) {
	t.Parallel()

	blob, err := (Codec{Key: testKey(4)}).Encrypt([]byte("db-password"), []byte("warden/db/7/password"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if _, err := (Codec{Key: testKey(5)}).Decrypt(blob, []byte("warden/db/7/password")); err == nil {
		t.Fatal("Decrypt() error = nil, want authentication error")
	}
}

func TestCodecDecryptRejectsMalformedBlob(t *testing.T) {
	t.Parallel()

	codec := Codec{Key: testKey(6)}
	for _, tc := range []struct {
		name    string
		blob    []byte
		wantErr string
	}{
		{name: "empty", blob: nil, wantErr: "blob length"},
		{name: "too short", blob: bytes.Repeat([]byte{0}, 28), wantErr: "blob length"},
		{name: "wrong version", blob: append([]byte{2}, bytes.Repeat([]byte{0}, 28)...), wantErr: "version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := codec.Decrypt(tc.blob, []byte("warden/ssh/1/password"))
			if err == nil {
				t.Fatal("Decrypt() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Decrypt() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestCodecDecryptRejectsAADMismatch(t *testing.T) {
	t.Parallel()

	codec := Codec{Key: testKey(7)}
	blob, err := codec.Encrypt([]byte("proxy-pass"), []byte("warden/ssh/12/proxy_password"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if _, err := codec.Decrypt(blob, []byte("warden/ssh/13/proxy_password")); err == nil {
		t.Fatal("Decrypt() error = nil, want authentication error")
	}
}

func BenchmarkCodecEncrypt(b *testing.B) {
	benchmarkCodecEncrypt(b, 64)
	benchmarkCodecEncrypt(b, 1024)
	benchmarkCodecEncrypt(b, 16*1024)
}

func BenchmarkCodecDecrypt(b *testing.B) {
	benchmarkCodecDecrypt(b, 64)
	benchmarkCodecDecrypt(b, 1024)
	benchmarkCodecDecrypt(b, 16*1024)
}

func benchmarkCodecEncrypt(b *testing.B, size int) {
	b.Helper()

	codec := Codec{Key: testKey(8)}
	plaintext := bytes.Repeat([]byte{0x5a}, size)
	aad := []byte("warden/ssh/99/password")

	b.Run(humanSize(size), func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))

		for i := 0; i < b.N; i++ {
			blob, err := codec.Encrypt(plaintext, aad)
			if err != nil {
				b.Fatalf("Encrypt() error = %v", err)
			}
			if len(blob) == 0 {
				b.Fatal("Encrypt() returned empty blob")
			}
		}
	})
}

func benchmarkCodecDecrypt(b *testing.B, size int) {
	b.Helper()

	codec := Codec{Key: testKey(9)}
	plaintext := bytes.Repeat([]byte{0x33}, size)
	aad := []byte("warden/db/99/password")
	blob, err := codec.Encrypt(plaintext, aad)
	if err != nil {
		b.Fatalf("Encrypt() setup error = %v", err)
	}

	b.Run(humanSize(size), func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))

		for i := 0; i < b.N; i++ {
			got, err := codec.Decrypt(blob, aad)
			if err != nil {
				b.Fatalf("Decrypt() error = %v", err)
			}
			if len(got) != len(plaintext) {
				b.Fatalf("len(Decrypt()) = %d, want %d", len(got), len(plaintext))
			}
		}
	})
}

func testKey(seed byte) [32]byte {
	var key [32]byte
	for i := range key {
		key[i] = seed + byte(i)
	}

	return key
}

func humanSize(size int) string {
	switch size {
	case 64:
		return "64B"
	case 1024:
		return "1KiB"
	case 16 * 1024:
		return "16KiB"
	default:
		return "unknown"
	}
}
