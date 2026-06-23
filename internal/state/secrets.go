package state

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/enboxorg/meshd/internal/vault"
)

const secretsFile = "secrets.vault.json"

// Secrets is the encrypted local secret payload for a meshd state directory.
type Secrets struct {
	ContextKeys map[string]string `json:"contextKeys,omitempty"`
}

// EncryptedSecretsExist checks whether encrypted local secrets exist.
func EncryptedSecretsExist(stateDir string) bool {
	_, err := os.Stat(filepath.Join(stateDir, secretsFile))
	return err == nil
}

// LoadContextKey loads an encrypted Protocol Context key for a network.
func LoadContextKey(stateDir string, password string, networkID string) ([]byte, bool, error) {
	if networkID == "" {
		return nil, false, fmt.Errorf("network id is required")
	}

	secrets, err := loadSecrets(stateDir, password)
	if err != nil {
		return nil, false, err
	}
	if secrets == nil || secrets.ContextKeys == nil {
		return nil, false, nil
	}

	encoded := secrets.ContextKeys[networkID]
	if encoded == "" {
		return nil, false, nil
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false, fmt.Errorf("decode context key: %w", err)
	}
	return key, true, nil
}

// StoreContextKey stores a Protocol Context key in encrypted local secrets.
func StoreContextKey(stateDir string, password string, networkID string, key []byte) error {
	if networkID == "" {
		return fmt.Errorf("network id is required")
	}
	if len(key) == 0 {
		return fmt.Errorf("context key is required")
	}

	secrets, err := loadSecrets(stateDir, password)
	if err != nil {
		return err
	}
	if secrets == nil {
		secrets = &Secrets{}
	}
	if secrets.ContextKeys == nil {
		secrets.ContextKeys = make(map[string]string)
	}
	secrets.ContextKeys[networkID] = base64.StdEncoding.EncodeToString(key)
	return saveSecrets(stateDir, password, secrets)
}

func loadSecrets(stateDir string, password string) (*Secrets, error) {
	target := filepath.Join(stateDir, secretsFile)
	data, err := os.ReadFile(target)
	if err != nil {
		if os.IsNotExist(err) {
			return &Secrets{}, nil
		}
		return nil, fmt.Errorf("read encrypted secrets: %w", err)
	}

	plaintext, err := vault.Open(data, password)
	if err != nil {
		return nil, fmt.Errorf("open encrypted secrets: %w", err)
	}

	var secrets Secrets
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, fmt.Errorf("unmarshal encrypted secrets: %w", err)
	}
	return &secrets, nil
}

func saveSecrets(stateDir string, password string, secrets *Secrets) error {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	plaintext, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("marshal encrypted secrets: %w", err)
	}
	sealed, err := vault.Seal(plaintext, password)
	if err != nil {
		return err
	}

	target := filepath.Join(stateDir, secretsFile)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0600); err != nil {
		return fmt.Errorf("write encrypted secrets: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename encrypted secrets: %w", err)
	}
	return nil
}
