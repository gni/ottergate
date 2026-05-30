package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"ottergate/pkg/audit"
)

var (
	masterKey     []byte
	masterKeyOnce sync.Once
)

func getMasterKey() []byte {
	masterKeyOnce.Do(func() {
		if envKey := os.Getenv("OTTERGATE_MASTER_KEY"); envKey != "" {
			h := sha256.Sum256([]byte(envKey))
			masterKey = h[:]
			return
		}

		isTest := strings.HasSuffix(os.Args[0], ".test") || os.Getenv("GO_ENV") == "test"
		var keyDir string
		if isTest {
			keyDir = os.TempDir()
		} else {
			cwd, _ := os.Getwd()
			keyDir = filepath.Join(cwd, "config")
		}

		keyPath := filepath.Join(keyDir, ".ottergate-master-key")

		if data, err := os.ReadFile(keyPath); err == nil {
			trimmed := strings.TrimSpace(string(data))
			h := sha256.Sum256([]byte(trimmed))
			masterKey = h[:]
			return
		}

		// Generate a new persistent key
		generated := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, generated); err != nil {
			// Ephemeral fallback
			fallback := make([]byte, 32)
			_, _ = io.ReadFull(rand.Reader, fallback)
			masterKey = fallback
			audit.Logger.Error(fmt.Sprintf("[SECURITY] Unable to generate master key: %s. Using ephemeral fallback!", err.Error()))
			return
		}

		genHex := hex.EncodeToString(generated)
		if err := os.MkdirAll(keyDir, 0700); err == nil {
			if err := os.WriteFile(keyPath, []byte(genHex), 0600); err == nil {
				h := sha256.Sum256([]byte(genHex))
				masterKey = h[:]
				audit.Logger.System(fmt.Sprintf("[SECURITY] OTTERGATE_MASTER_KEY not set. Generated persistent key at %s", keyPath))
				return
			}
		}

		// Ephemeral fallback
		fallback := make([]byte, 32)
		_, _ = io.ReadFull(rand.Reader, fallback)
		masterKey = fallback
		audit.Logger.Error("[SECURITY] Unable to persist master key. Using ephemeral fallback! Secrets will be lost on restart.")
	})

	return masterKey
}

func IsEncrypted(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 4 || parts[0] != "v1" {
		return false
	}
	return len(parts[1]) == 24 && len(parts[2]) == 32
}

func EncryptSecret(plaintext string) (string, error) {
	if IsEncrypted(plaintext) {
		return plaintext, nil
	}

	key := getMasterKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// In Go, GCM Seal appends the authenticated tag to the ciphertext.
	// We must separate them to match the original layout: v1:nonce:tag:ciphertext
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	tagSize := gcm.Overhead()
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	return fmt.Sprintf("v1:%s:%s:%s",
		hex.EncodeToString(nonce),
		hex.EncodeToString(tag),
		hex.EncodeToString(ciphertext)), nil
}

func DecryptSecret(encrypted string) (string, error) {
	if !IsEncrypted(encrypted) {
		return encrypted, nil
	}

	parts := strings.Split(encrypted, ":")
	nonce, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	tag, err := hex.DecodeString(parts[2])
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(parts[3])
	if err != nil {
		return "", err
	}

	key := getMasterKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Recombine ciphertext and tag for Go's GCM Open
	sealed := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", errors.New("AEAD Decryption Fault: Integrity violation or Master Key mismatch. Payload rejected.")
	}

	return string(plaintext), nil
}

// HKDF-SHA256 Implementation (RFC 5869)
func HKDF(salt []byte, ikm []byte, info []byte, length int) []byte {
	// If salt is empty, use a hash-len string of zeros
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}

	// Step 1: Extract
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)

	// Step 2: Expand
	okm := make([]byte, 0, length)
	var t []byte
	counter := byte(1)

	for len(okm) < length {
		mac = hmac.New(sha256.New, prk)
		if len(t) > 0 {
			mac.Write(t)
		}
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		okm = append(okm, t...)
		counter++
	}

	return okm[:length]
}
