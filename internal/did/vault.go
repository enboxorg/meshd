package did

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/enboxorg/meshd/internal/vault"
)

const encryptedStateFile = "identity.vault.json"

// StoreEncrypted persists the DID private key in a password-encrypted vault.
func (d *DID) StoreEncrypted(stateDir string, password string) error {
	return d.storeEncryptedWithParams(stateDir, password, vault.DefaultArgon2idParams)
}

func (d *DID) storeEncryptedWithParams(stateDir string, password string, params vault.Argon2idParams) error {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	state := storedState{
		URI:        d.URI,
		PrivateKey: []byte(d.SigningKey),
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal identity state: %w", err)
	}

	sealed, err := vault.SealWithParams(data, password, params)
	if err != nil {
		return err
	}

	target := filepath.Join(stateDir, encryptedStateFile)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0600); err != nil {
		return fmt.Errorf("write encrypted identity: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename encrypted identity: %w", err)
	}
	return nil
}

// LoadEncrypted reads a password-encrypted DID identity.
func LoadEncrypted(stateDir string, password string) (*DID, error) {
	target := filepath.Join(stateDir, encryptedStateFile)
	data, err := os.ReadFile(target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read encrypted identity: %w", err)
	}

	plaintext, err := vault.Open(data, password)
	if err != nil {
		return nil, err
	}

	var state storedState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, fmt.Errorf("unmarshal encrypted identity: %w", err)
	}
	if len(state.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d", len(state.PrivateKey))
	}

	d, err := FromPrivateKey(ed25519.PrivateKey(state.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("reconstruct DID: %w", err)
	}
	return d, nil
}

// EncryptedExists checks whether an encrypted DID identity file exists.
func EncryptedExists(stateDir string) bool {
	target := filepath.Join(stateDir, encryptedStateFile)
	_, err := os.Stat(target)
	return err == nil
}

// RemovePlaintext removes a legacy plaintext DID identity file.
func RemovePlaintext(stateDir string) error {
	if err := os.Remove(filepath.Join(stateDir, stateFile)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plaintext identity: %w", err)
	}
	return nil
}

// MigrateToEncrypted encrypts a legacy plaintext identity and removes the
// plaintext identity file after the encrypted file is safely written.
func MigrateToEncrypted(stateDir string, password string) error {
	return migrateToEncryptedWithParams(stateDir, password, vault.DefaultArgon2idParams)
}

func migrateToEncryptedWithParams(stateDir string, password string, params vault.Argon2idParams) error {
	if EncryptedExists(stateDir) {
		return nil
	}

	identity, err := Load(stateDir)
	if err != nil {
		return err
	}
	if identity == nil {
		return fmt.Errorf("no plaintext identity to migrate")
	}

	if err := identity.storeEncryptedWithParams(stateDir, password, params); err != nil {
		return err
	}
	if err := RemovePlaintext(stateDir); err != nil {
		return err
	}
	return nil
}
