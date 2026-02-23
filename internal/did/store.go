package did

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// stateFile is the filename for the serialized DID state.
const stateFile = "identity.json"

// storedState is the on-disk representation of a DID's private material.
type storedState struct {
	URI        string `json:"uri"`
	PrivateKey []byte `json:"privateKey"` // Ed25519 private key (64 bytes)
}

// Store persists the DID's private key to the given state directory.
// The file is written atomically (write-to-temp + rename).
func (d *DID) Store(stateDir string) error {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	state := storedState{
		URI:        d.URI,
		PrivateKey: []byte(d.SigningKey),
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	target := filepath.Join(stateDir, stateFile)
	tmp := target + ".tmp"

	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}

	return nil
}

// Load reads a previously stored DID from the state directory.
// Returns nil, nil if the file does not exist (not yet initialized).
func Load(stateDir string) (*DID, error) {
	target := filepath.Join(stateDir, stateFile)

	data, err := os.ReadFile(target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}

	var state storedState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}

	if len(state.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d", len(state.PrivateKey))
	}

	d, err := FromPrivateKey(ed25519.PrivateKey(state.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("reconstruct DID: %w", err)
	}

	// Sanity check: stored URI should match derived URI.
	if state.URI != "" && state.URI != d.URI {
		return nil, fmt.Errorf("stored URI %q does not match derived URI %q", state.URI, d.URI)
	}

	return d, nil
}

// Exists checks whether a DID identity file exists in the state directory.
func Exists(stateDir string) bool {
	target := filepath.Join(stateDir, stateFile)
	_, err := os.Stat(target)
	return err == nil
}
