// Package crypto provides blob encryption, token generation and password hashing.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
)

const KeyEnv = "QCFG_MASTER_KEY"

// LoadOrCreateKey returns the master key from $QCFG_MASTER_KEY (64 hex chars)
// or dataDir/master.key, generating the file on first use.
func LoadOrCreateKey(dataDir string) ([]byte, error) {
	if v := os.Getenv(KeyEnv); v != "" {
		k, err := hex.DecodeString(strings.TrimSpace(v))
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("%s must be 64 hex characters", KeyEnv)
		}
		return k, nil
	}
	path := filepath.Join(dataDir, "master.key")
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("%s: invalid key length %d", path, len(b))
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k := RandomBytes(32)
	if err := os.WriteFile(path, k, 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func Seal(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = RandomBytes(gcm.NonceSize())
	return nonce, gcm.Seal(nil, nonce, plaintext, nil), nil
}

func Open(key, nonce, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func Sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func newTokenBody() string { return new(big.Int).SetBytes(RandomBytes(32)).Text(62) }

// NewToken returns "qcfg_" followed by 32 random bytes in base62.
func NewToken() string { return "qcfg_" + newTokenBody() }

// NewPAT returns "qcfg_pat_" followed by 32 random bytes in base62.
func NewPAT() string { return "qcfg_pat_" + newTokenBody() }

func HashToken(token string) string { return Sha256Hex([]byte(token)) }

const userCodeChars = "BCDFGHJKLMNPQRSTVWXZ"

// NewUserCode returns an 8-letter device authorization code as XXXX-XXXX.
func NewUserCode() string {
	b := make([]byte, 9)
	for i := range b {
		if i == 4 {
			b[i] = '-'
			continue
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(userCodeChars))))
		if err != nil {
			panic(err)
		}
		b[i] = userCodeChars[n.Int64()]
	}
	return string(b)
}

// NormalizeUserCode uppercases s, drops separators and formats it as XXXX-XXXX.
func NormalizeUserCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if r >= 'A' && r <= 'Z' {
			b.WriteRune(r)
		}
	}
	c := b.String()
	if len(c) != 8 {
		return c
	}
	return c[:4] + "-" + c[4:]
}

// RandomString returns a URL-safe random string of n bytes of entropy.
func RandomString(n int) string {
	return base64.RawURLEncoding.EncodeToString(RandomBytes(n))
}

const (
	argonTime    = 2
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

// HashPassword returns an encoded argon2id hash.
func HashPassword(pw string) string {
	salt := RandomBytes(16)
	h := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$%d$%d$%d$%s$%s", argonTime, argonMemory, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(h))
}

func VerifyPassword(encoded, pw string) bool {
	var t, m uint32
	var p uint8
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "argon2id" {
		return false
	}
	if _, err := fmt.Sscanf(parts[1]+" "+parts[2]+" "+parts[3], "%d %d %d", &t, &m, &p); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
