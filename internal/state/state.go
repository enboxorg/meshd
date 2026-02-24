// Package state manages the on-disk state for a dwn-mesh node.
//
// State is stored in a directory (default: ~/.dwn-mesh/) containing:
//   - identity.json: DID private key (from the did package)
//   - network.json: current network membership info
//   - cursors.json: EventLog cursors for crash-safe subscription reconnection
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// DefaultStateDir returns the default state directory path.
// Linux/macOS: ~/.dwn-mesh
func DefaultStateDir() string {
	if d := os.Getenv("DWN_MESH_STATE_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "dwn-mesh")
	}
	return filepath.Join(home, ".dwn-mesh")
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

	// WireGuardPublicKey is this node's WG public key (base64).
	WireGuardPublicKey string `json:"wireguardPublicKey,omitempty"`

	// WireGuardPrivateKey is this node's WG private key (base64).
	// Stored locally only — never sent over the network.
	WireGuardPrivateKey string `json:"wireguardPrivateKey,omitempty"`

	// NodeInfoRecordID is the record ID of this node's nodeInfo record.
	NodeInfoRecordID string `json:"nodeInfoRecordId,omitempty"`
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
