package crypto

import (
	"os"
	"testing"
)

func TestEncryptionDecryption(t *testing.T) {
	os.Setenv("OTTERGATE_MASTER_KEY", "super-secret-test-master-key-12345")
	defer os.Unsetenv("OTTERGATE_MASTER_KEY")

	plaintext := "my-highly-sensitive-password"

	encrypted, err := EncryptSecret(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt secret: %v", err)
	}

	if !IsEncrypted(encrypted) {
		t.Fatalf("encrypted payload failed IsEncrypted format check: %s", encrypted)
	}

	decrypted, err := DecryptSecret(encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt secret: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("decrypted secret mismatch: expected %q, got %q", plaintext, decrypted)
	}
}

func TestDecryptUnencrypted(t *testing.T) {
	raw := "not-encrypted-value"
	decrypted, err := DecryptSecret(raw)
	if err != nil {
		t.Fatalf("failed on raw pass-through: %v", err)
	}
	if decrypted != raw {
		t.Errorf("expected pass-through value, got %q", decrypted)
	}
}

func TestHKDF(t *testing.T) {
	salt := []byte("salt")
	ikm := []byte("ikm")
	info := []byte("info")
	derived := HKDF(salt, ikm, info, 32)
	if len(derived) != 32 {
		t.Fatalf("expected 32 derived bytes, got %d", len(derived))
	}
}
