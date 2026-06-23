// Package vault provides password-based encryption for local meshd secrets.
package vault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Version = 1

	kdfArgon2id   = "argon2id"
	cipherXChaCha = "xchacha20poly1305"

	saltSize = 16
	keySize  = chacha20poly1305.KeySize
)

// Argon2idParams are serialized with the vault so KDF settings are explicit.
type Argon2idParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"keyLen"`
}

// DefaultArgon2idParams is intentionally moderate for CLI unlock latency while
// still using a memory-hard KDF for at-rest key protection.
var DefaultArgon2idParams = Argon2idParams{
	Time:    3,
	Memory:  64 * 1024,
	Threads: 4,
	KeyLen:  keySize,
}

// FastArgon2idParams is for tests only.
var FastArgon2idParams = Argon2idParams{
	Time:    1,
	Memory:  1024,
	Threads: 1,
	KeyLen:  keySize,
}

// Envelope is the JSON file format for an encrypted vault payload.
type Envelope struct {
	Version    int            `json:"version"`
	KDF        string         `json:"kdf"`
	KDFParams  Argon2idParams `json:"kdfParams"`
	Cipher     string         `json:"cipher"`
	Salt       string         `json:"salt"`
	Nonce      string         `json:"nonce"`
	Ciphertext string         `json:"ciphertext"`
}

// Seal encrypts plaintext using the default KDF parameters.
func Seal(plaintext []byte, password string) ([]byte, error) {
	return SealWithParams(plaintext, password, DefaultArgon2idParams)
}

// SealWithParams encrypts plaintext using explicit KDF parameters.
func SealWithParams(plaintext []byte, password string, params Argon2idParams) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("vault password is required")
	}
	var err error
	params, err = normalizeParams(params)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate vault salt: %w", err)
	}

	key := deriveKey(password, salt, params)
	defer clear(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create vault cipher: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate vault nonce: %w", err)
	}

	env := Envelope{
		Version:    Version,
		KDF:        kdfArgon2id,
		KDFParams:  params,
		Cipher:     cipherXChaCha,
		Salt:       base64.RawURLEncoding.EncodeToString(salt),
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, nil)),
	}

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal vault envelope: %w", err)
	}
	return data, nil
}

// Open decrypts a vault envelope.
func Open(data []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("vault password is required")
	}

	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse vault envelope: %w", err)
	}
	if env.Version != Version {
		return nil, fmt.Errorf("unsupported vault version %d", env.Version)
	}
	if env.KDF != kdfArgon2id {
		return nil, fmt.Errorf("unsupported vault kdf %q", env.KDF)
	}
	if env.Cipher != cipherXChaCha {
		return nil, fmt.Errorf("unsupported vault cipher %q", env.Cipher)
	}
	params, err := normalizeParams(env.KDFParams)
	if err != nil {
		return nil, err
	}

	salt, err := base64.RawURLEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode vault salt: %w", err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode vault nonce: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode vault ciphertext: %w", err)
	}

	key := deriveKey(password, salt, params)
	defer clear(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create vault cipher: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}
	return plaintext, nil
}

func normalizeParams(params Argon2idParams) (Argon2idParams, error) {
	if params.Time == 0 {
		return params, fmt.Errorf("vault kdf time must be greater than zero")
	}
	if params.Memory == 0 {
		return params, fmt.Errorf("vault kdf memory must be greater than zero")
	}
	if params.Threads == 0 {
		return params, fmt.Errorf("vault kdf threads must be greater than zero")
	}
	if params.KeyLen == 0 {
		params.KeyLen = keySize
	}
	if params.KeyLen != keySize {
		return params, fmt.Errorf("vault key length must be %d bytes", keySize)
	}
	return params, nil
}

func deriveKey(password string, salt []byte, params Argon2idParams) []byte {
	return argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, params.KeyLen)
}

func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
