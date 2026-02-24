// Package engine provides automatic context key delivery for the mesh anchor.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/enboxorg/dwn-mesh/internal/dwn"
	dwncrypto "github.com/enboxorg/dwn-mesh/internal/dwn/crypto"
	"github.com/enboxorg/dwn-mesh/internal/mesh"
	"github.com/enboxorg/dwn-mesh/protocols"
)

// AutoKeyDelivery monitors the mesh member list and automatically delivers
// context keys to new members. This is only active on the anchor node
// (the network owner who holds the root private key).
//
// When the engine polls DWN state and discovers members who don't yet have
// a context key, it delivers one to each of them. This removes the need for
// the anchor operator to manually run "peer approve" for every new member.
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

	mu        sync.Mutex
	delivered map[string]bool // DID → true if context key already delivered
}

// NewAutoKeyDelivery creates a new auto key delivery instance.
// Returns nil if the EncryptionKeyManager is not an owner (doesn't have root private key).
func NewAutoKeyDelivery(cfg AutoKeyDeliveryConfig) *AutoKeyDelivery {
	if cfg.EncryptionKeyManager == nil || !cfg.EncryptionKeyManager.IsOwner() {
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
}

// OnMembersUpdated should be called after each poll that discovers member DIDs.
// It checks for members who haven't received a context key yet and delivers
// one to each of them.
//
// memberDIDs is the full set of member DIDs from the current mesh state.
// It is safe to call concurrently.
func (a *AutoKeyDelivery) OnMembersUpdated(ctx context.Context, memberDIDs []string) {
	if a == nil {
		return
	}

	a.mu.Lock()
	var pending []string
	for _, did := range memberDIDs {
		if !a.delivered[did] {
			pending = append(pending, did)
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

	for _, did := range pending {
		err := kdm.DeliverContextKey(ctx, mesh.DeliverContextKeyParams{
			AnchorDID:      a.AnchorDID,
			RecipientDID:   did,
			SourceProtocol: protocols.MeshProtocolURI,
			ContextID:      a.NetworkRecordID,
		})
		if err != nil {
			a.Logger.Warn("auto key delivery failed",
				slog.String("recipient", did),
				slog.Any("error", err),
			)
			continue
		}

		a.mu.Lock()
		a.delivered[did] = true
		a.mu.Unlock()

		a.Logger.Info("auto-delivered context key",
			slog.String("recipient", did),
		)
	}
}

// MarkDelivered marks a member DID as already having received a context key.
// Use this to seed the delivered set from existing contextKey records.
func (a *AutoKeyDelivery) MarkDelivered(did string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.delivered[did] = true
	a.mu.Unlock()
}

// DeliveredCount returns the number of members with delivered context keys.
func (a *AutoKeyDelivery) DeliveredCount() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.delivered)
}

// PendingDelivery returns the list of member DIDs from the given set that
// haven't received a context key yet.
func (a *AutoKeyDelivery) PendingDelivery(memberDIDs []string) []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	var pending []string
	for _, did := range memberDIDs {
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
