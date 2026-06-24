// Package engine provides automatic context key delivery for the mesh anchor.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/internal/mesh"
	"github.com/enboxorg/meshd/protocols"
)

// AutoKeyDelivery monitors the mesh node list and automatically delivers
// context keys to new nodes. This is active on a local anchor node or a
// wallet-authorized owner node that has a cached network context key.
//
// When the engine polls DWN state and discovers nodes that don't yet have
// a context key, it delivers one to each of them. This removes the need for
// the anchor operator to manually run "peer approve" for every new node.
type AutoKeyDelivery struct {
	// Endpoint is the DWN server URL for the anchor.
	Endpoint string

	// AnchorDID is the anchor node's DID.
	AnchorDID string

	// NetworkRecordID is the root network record ID (used as contextId).
	NetworkRecordID string

	// Signer signs DWN messages for the anchor.
	Signer *dwn.Signer

	// EncryptionKeyManager provides key derivation from the root key.
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager

	// Logger for output.
	Logger *slog.Logger

	// PermissionGrantID invokes a wallet/member grant for contextKey writes.
	PermissionGrantID string

	mu        sync.Mutex
	delivered map[string]bool // DID → true if context key already delivered
}

// KeyDeliveryRecipient identifies a node that may need a delivered context key.
type KeyDeliveryRecipient struct {
	DID         string
	KeyDelivery *dwncrypto.KeyDeliveryPublic
}

// NewAutoKeyDelivery creates a new auto key delivery instance.
// Returns nil if the EncryptionKeyManager cannot resolve this network's
// context key.
func NewAutoKeyDelivery(cfg AutoKeyDeliveryConfig) *AutoKeyDelivery {
	if cfg.EncryptionKeyManager == nil ||
		(!cfg.EncryptionKeyManager.IsOwner() && !cfg.EncryptionKeyManager.HasContextKey(cfg.NetworkRecordID)) {
		return nil
	}

	l := cfg.Logger
	if l == nil {
		l = slog.Default()
	}

	return &AutoKeyDelivery{
		Endpoint:             cfg.Endpoint,
		AnchorDID:            cfg.AnchorDID,
		NetworkRecordID:      cfg.NetworkRecordID,
		Signer:               cfg.Signer,
		EncryptionKeyManager: cfg.EncryptionKeyManager,
		Logger:               l,
		PermissionGrantID:    cfg.PermissionGrantID,
		delivered:            make(map[string]bool),
	}
}

// AutoKeyDeliveryConfig holds configuration for auto key delivery.
type AutoKeyDeliveryConfig struct {
	Endpoint             string
	AnchorDID            string
	NetworkRecordID      string
	Signer               *dwn.Signer
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager
	Logger               *slog.Logger
	PermissionGrantID    string
}

// OnNodesUpdated should be called after each poll that discovers node DIDs.
// It checks for nodes that haven't received a context key yet and delivers
// one to each of them.
//
// nodeDIDs is the full set of node DIDs from the current mesh state.
// It is safe to call concurrently.
func (a *AutoKeyDelivery) OnNodesUpdated(ctx context.Context, nodeDIDs []string) {
	recipients := make([]KeyDeliveryRecipient, 0, len(nodeDIDs))
	for _, did := range nodeDIDs {
		recipients = append(recipients, KeyDeliveryRecipient{DID: did})
	}
	a.OnRecipientsUpdated(ctx, recipients)
}

// OnRecipientsUpdated should be called after each poll that discovers nodes.
// It delivers context keys to nodes that have not yet received them, using
// recipient key-delivery public keys when available.
func (a *AutoKeyDelivery) OnRecipientsUpdated(ctx context.Context, recipients []KeyDeliveryRecipient) {
	if a == nil {
		return
	}

	a.mu.Lock()
	var pending []KeyDeliveryRecipient
	for _, recipient := range recipients {
		if recipient.DID == "" {
			continue
		}
		if !a.delivered[recipient.DID] {
			pending = append(pending, recipient)
		}
	}
	a.mu.Unlock()

	if len(pending) == 0 {
		return
	}

	kdm := &mesh.KeyDeliveryManager{
		Endpoint:             a.Endpoint,
		Signer:               a.Signer,
		EncryptionKeyManager: a.EncryptionKeyManager,
		Logger:               a.Logger,
	}

	for _, recipient := range pending {
		err := kdm.DeliverContextKey(ctx, mesh.DeliverContextKeyParams{
			AnchorDID:            a.AnchorDID,
			RecipientDID:         recipient.DID,
			SourceProtocol:       protocols.MeshProtocolURI,
			ContextID:            a.NetworkRecordID,
			PermissionGrantID:    a.PermissionGrantID,
			RecipientKeyDelivery: recipient.KeyDelivery,
		})
		if err != nil {
			a.Logger.Warn("auto key delivery failed",
				slog.String("recipient", recipient.DID),
				slog.Any("error", err),
			)
			continue
		}

		a.mu.Lock()
		a.delivered[recipient.DID] = true
		a.mu.Unlock()

		a.Logger.Info("auto-delivered context key",
			slog.String("recipient", recipient.DID),
		)
	}
}

// MarkDelivered marks a node DID as already having received a context key.
// Use this to seed the delivered set from existing contextKey records.
func (a *AutoKeyDelivery) MarkDelivered(did string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.delivered[did] = true
	a.mu.Unlock()
}

// DeliveredCount returns the number of nodes with delivered context keys.
func (a *AutoKeyDelivery) DeliveredCount() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.delivered)
}

// PendingDelivery returns the list of node DIDs from the given set that
// haven't received a context key yet.
func (a *AutoKeyDelivery) PendingDelivery(nodeDIDs []string) []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	var pending []string
	for _, did := range nodeDIDs {
		if !a.delivered[did] {
			pending = append(pending, did)
		}
	}
	return pending
}

// String returns a summary of the auto key delivery state.
func (a *AutoKeyDelivery) String() string {
	if a == nil {
		return "AutoKeyDelivery: disabled (not anchor)"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return fmt.Sprintf("AutoKeyDelivery: %d delivered", len(a.delivered))
}
