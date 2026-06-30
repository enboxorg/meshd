// Package state manages the on-disk state for a meshd node.
//
// State is stored in a profile-specific directory:
//
//	~/.enbox/profiles/<name>/meshd/
//	  identity.vault.json  # encrypted DID private key (from the did package)
//	  identity.json        # legacy plaintext DID private key
//	  network.json         # current network membership info
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

	// NodeExpiresAt is the owner-controlled expiry for this node's membership.
	// Empty means the membership does not expire.
	NodeExpiresAt string `json:"nodeExpiresAt,omitempty"`

	// NodeLabel is the human-readable owner/dashboard label for this node.
	NodeLabel string `json:"nodeLabel,omitempty"`

	// NodeDID is this machine's device DID. It is the DID used for WireGuard
	// key derivation, node records, endpoint writes, and "this device" UI.
	// Older state files omit it; callers should fall back to the local profile
	// DID when empty.
	NodeDID string `json:"nodeDid,omitempty"`

	// OwnerDID is the durable wallet/member DID that owns this node. In
	// local-vault mode it is usually the same as NodeDID. In wallet-connected
	// mode it is the wallet identity while NodeDID remains device-local.
	OwnerDID string `json:"ownerDid,omitempty"`

	// MemberDID is the pre-beta JSON name for OwnerDID. Keep writing and reading
	// it so existing network.json files and tooling continue to work.
	MemberDID string `json:"memberDid,omitempty"`

	// DelegateDID is the local control/session DID with wallet-issued grants for
	// this node. Older state may omit it and grant directly to NodeDID.
	DelegateDID string `json:"delegateDid,omitempty"`

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

	// PendingOwnerRequestID is set while this node is waiting for a wallet
	// owner to approve it from the dashboard. During this state
	// NetworkRecordID and NodeRecordID are intentionally empty.
	PendingOwnerRequestID string `json:"pendingOwnerRequestId,omitempty"`

	// PendingOwnerRequestAt is when the owner-scoped node request was written.
	PendingOwnerRequestAt string `json:"pendingOwnerRequestAt,omitempty"`
}

// NormalizeOwnerDID keeps the newer ownerDid field and the older memberDid
// field interchangeable while local state files transition.
func (ns *NetworkState) NormalizeOwnerDID() {
	if ns == nil {
		return
	}
	if ns.OwnerDID == "" {
		ns.OwnerDID = ns.MemberDID
	}
	if ns.MemberDID == "" {
		ns.MemberDID = ns.OwnerDID
	}
}

// EffectiveNodeDID returns the node/device DID, applying the legacy fallback.
func (ns *NetworkState) EffectiveNodeDID(fallback string) string {
	if ns != nil && ns.NodeDID != "" {
		return ns.NodeDID
	}
	return fallback
}

// EffectiveOwnerDID returns the wallet owner/member DID, applying local defaults.
func (ns *NetworkState) EffectiveOwnerDID(fallback string) string {
	if ns != nil {
		if ns.OwnerDID != "" {
			return ns.OwnerDID
		}
		if ns.MemberDID != "" {
			return ns.MemberDID
		}
	}
	return fallback
}

// EffectiveMemberDID returns the wallet/member DID, applying local defaults.
//
// Deprecated: use EffectiveOwnerDID.
func (ns *NetworkState) EffectiveMemberDID(fallback string) string {
	return ns.EffectiveOwnerDID(fallback)
}

const networkFile = "network.json"

// SaveNetworkState persists network membership state.
func SaveNetworkState(stateDir string, ns *NetworkState) error {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	ns.NormalizeOwnerDID()

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
	ns.NormalizeOwnerDID()
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
