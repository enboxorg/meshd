// Package state manages the on-disk state for a meshd node.
//
// State is stored in a profile-specific directory:
//
//	~/.enbox/profiles/<name>/meshd/
//	  identity.json   # DID private key (from the did package)
//	  network.json    # current network membership info
//
// The state directory is resolved by the profile package. The functions in
// this package accept a stateDir parameter and are agnostic to profiles.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// LegacyStateDir returns the pre-profiles state directory path.
// This is used only for detecting and migrating legacy installations.
//
// Deprecated: Use profile.ResolveDataPath instead.
func LegacyStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "meshd")
	}
	return filepath.Join(home, ".meshd")
}

// HasLegacyState checks if a pre-profiles state directory exists with
// identity data. Returns the path if found, or empty string if not.
func HasLegacyState() string {
	dir := LegacyStateDir()
	if _, err := os.Stat(filepath.Join(dir, "identity.json")); err == nil {
		return dir
	}
	return ""
}

// NetworkState holds the persisted network membership information.
type NetworkState struct {
	// NetworkRecordID is the record ID of the network on the anchor DWN.
	NetworkRecordID string `json:"networkRecordId"`

	// AnchorDID is the DID of the anchor DWN owner.
	AnchorDID string `json:"anchorDid"`

	// AnchorEndpoint is the HTTP endpoint of the anchor DWN.
	AnchorEndpoint string `json:"anchorEndpoint"`

	// NetworkName is the human-readable network name.
	NetworkName string `json:"networkName"`

	// MeshCIDR is the network's IP range.
	MeshCIDR string `json:"meshCidr"`

	// MeshIP is this node's allocated IP within the mesh.
	MeshIP string `json:"meshIp,omitempty"`

	// NodeRecordID is the record ID of this node's node record on the anchor DWN.
	NodeRecordID string `json:"nodeRecordId,omitempty"`

	// NodeDateCreated is the dateCreated timestamp from the initial
	// node record write. Required for updates because dateCreated is immutable.
	NodeDateCreated string `json:"nodeDateCreated,omitempty"`

	// MemberRecordID is the record ID of this node's member record, if
	// the node was added as a member-associated device (network/member/node).
	// Empty for owner-provisioned devices (network/node).
	MemberRecordID string `json:"memberRecordId,omitempty"`

	// MemberDateCreated is the dateCreated timestamp from the member
	// record write. Required for updates because dateCreated is immutable.
	MemberDateCreated string `json:"memberDateCreated,omitempty"`

	// ContextKey is the Protocol Context encryption key (base64-encoded
	// X25519 private key). Persisted so the mesh survives DWN outages
	// at startup — if the anchor's DWN is unreachable, the node can
	// still encrypt/decrypt records using the cached key.
	//
	// For the anchor, this is empty — the anchor derives the context key
	// from its root key via HKDF on every startup.
	ContextKey string `json:"contextKey,omitempty"`
}

const networkFile = "network.json"

// SaveNetworkState persists network membership state.
func SaveNetworkState(stateDir string, ns *NetworkState) error {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	data, err := json.MarshalIndent(ns, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	target := filepath.Join(stateDir, networkFile)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// LoadNetworkState loads persisted network state.
// Returns nil, nil if not yet joined any network.
func LoadNetworkState(stateDir string) (*NetworkState, error) {
	target := filepath.Join(stateDir, networkFile)
	data, err := os.ReadFile(target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read: %w", err)
	}

	var ns NetworkState
	if err := json.Unmarshal(data, &ns); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &ns, nil
}

// HasNetwork checks if a network state file exists.
func HasNetwork(stateDir string) bool {
	_, err := os.Stat(filepath.Join(stateDir, networkFile))
	return err == nil
}

// ClearNetworkState removes the network state (for network leave).
func ClearNetworkState(stateDir string) error {
	target := filepath.Join(stateDir, networkFile)
	err := os.Remove(target)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
