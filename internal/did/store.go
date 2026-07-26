package did

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/enboxorg/meshd/internal/state"
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
	return d.StoreAs(stateDir, stateFile)
}

// StoreAs persists the DID's private key under a named file in stateDir.
// The filename must be controlled by the caller.
func (d *DID) StoreAs(stateDir string, filename string) error {
	if err := state.CheckNoLegacyVault(stateDir, filename); err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	stored := storedState{
		URI:        d.URI,
		PrivateKey: []byte(d.SigningKey),
	}

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	target := filepath.Join(stateDir, filename)
	tmp := target + ".tmp"

	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	// Keep root-written key files readable by the profile owner, exactly like
	// SaveNetworkState does after the sudo TUN re-exec.
	state.AlignOwnerToDir(stateDir, tmp)
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}

	return nil
}

// Load reads a previously stored DID from the state directory.
// Returns nil, nil if the file does not exist (not yet initialized).
func Load(stateDir string) (*DID, error) {
	return LoadAs(stateDir, stateFile)
}

// LoadAs reads a previously stored DID from a named file in stateDir.
// The filename must be controlled by the caller.
func LoadAs(stateDir string, filename string) (*DID, error) {
	if err := state.CheckNoLegacyVault(stateDir, filename); err != nil {
		return nil, err
	}
	target := filepath.Join(stateDir, filename)

	data, err := os.ReadFile(target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}

	var stored storedState
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}

	if len(stored.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d", len(stored.PrivateKey))
	}

	d, err := FromPrivateKey(ed25519.PrivateKey(stored.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("reconstruct DID: %w", err)
	}

	// The derived URI is authoritative. Old identity files may contain a
	// did:dht URI for the same key — we silently upgrade to did:jwk.
	// No backwards compatibility is needed (meshd is pre-release).

	return d, nil
}

// Exists checks whether a DID identity file exists in the state directory.
func Exists(stateDir string) bool {
	target := filepath.Join(stateDir, stateFile)
	_, err := os.Stat(target)
	return err == nil
}

// ExistsAs checks whether a named DID identity file exists in stateDir.
func ExistsAs(stateDir string, filename string) bool {
	target := filepath.Join(stateDir, filename)
	_, err := os.Stat(target)
	return err == nil
}

// LegacyVaultExists reports whether a retired password-encrypted identity
// vault sits where the plaintext identity file would be read. Callers treat
// this as "initialized" so loading fails with the vaults-removed error
// instead of minting a fresh identity next to the legacy one.
func LegacyVaultExists(stateDir string) bool {
	return state.CheckNoLegacyVault(stateDir, stateFile) != nil
}
