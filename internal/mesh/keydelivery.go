package mesh

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/protocols"
)

// KeyDeliveryManager handles writing and fetching contextKey records
// for the DWN Key Delivery Protocol.
//
// When a network owner creates a network or adds a node, they derive a
// Protocol Context key for the network context and deliver it to each
// participant through an access-controlled contextKey record. Participants
// can then decrypt records in that context.
type KeyDeliveryManager struct {
	// Endpoint is the DWN server URL.
	Endpoint string

	// Signer signs DWN messages.
	Signer *dwn.Signer

	// EncryptionKeyManager provides key derivation.
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager

	// Logger for debug output.
	Logger *slog.Logger
}

// DeliverContextKeyParams configures a context key delivery.
type DeliverContextKeyParams struct {
	// AnchorDID is the DWN owner (who holds the root key and derives context keys).
	AnchorDID string

	// RecipientDID is the participant who should receive the context key.
	RecipientDID string

	// SourceProtocol is the protocol URI that the context belongs to.
	SourceProtocol string

	// ContextID is the root context ID (typically the network record ID).
	ContextID string
}

// DeliverContextKey derives the Protocol Context key for a context and
// writes a contextKey record to the anchor's DWN.
//
// The contextKey record payload is plaintext JSON, but protocol authorization
// only allows the addressed recipient to read it. It is not Protocol Context
// encrypted, because that would create a circular key exchange dependency.
//
// This MUST be called by the DWN owner (anchor) who has the root private key.
func (m *KeyDeliveryManager) DeliverContextKey(ctx context.Context, params DeliverContextKeyParams) error {
	if !m.EncryptionKeyManager.IsOwner() {
		return fmt.Errorf("context key delivery requires the DWN owner's root private key")
	}

	logger := m.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// 1. Derive the context key payload.
	contextKeyJwk, err := m.EncryptionKeyManager.DeriveContextKeyJwk(params.ContextID)
	if err != nil {
		return fmt.Errorf("deriving context key: %w", err)
	}

	payload, err := contextKeyJwk.MarshalPayload()
	if err != nil {
		return fmt.Errorf("marshaling context key payload: %w", err)
	}

	// 2. Write the contextKey record unencrypted. The key-delivery protocol
	//    does not require encryption ($encryption is not set). Access is
	//    controlled by $actions authorization — only the recipient can read.
	//    This avoids the circular key exchange problem.

	agent := dwn.NewSimpleAgent(m.Endpoint, m.Signer)
	api := dwn.NewDwnAPI(agent)

	// 3. Write the contextKey record (unencrypted — access controlled by $actions).
	_, status, err := api.Write(ctx, params.AnchorDID, dwn.WriteParams{
		Protocol:     protocols.KeyDeliveryProtocolURI,
		ProtocolPath: "contextKey",
		DataFormat:   "application/json",
		Recipient:    params.RecipientDID,
		Data:         payload,
		Tags: map[string]any{
			"protocol":  params.SourceProtocol,
			"contextId": params.ContextID,
		},
	})
	if err != nil {
		return fmt.Errorf("writing contextKey record: %w", err)
	}
	if status.Code >= 300 {
		return fmt.Errorf("contextKey write failed: %d %s", status.Code, status.Detail)
	}

	logger.Info("delivered context key",
		slog.String("recipient", params.RecipientDID),
		slog.String("contextId", params.ContextID),
		slog.String("protocol", params.SourceProtocol),
	)

	return nil
}

// FetchContextKeyParams configures a context key fetch.
type FetchContextKeyParams struct {
	// AnchorEndpoint is the DWN server URL of the anchor (key owner).
	AnchorEndpoint string

	// AnchorDID is the DWN owner who wrote the contextKey record.
	AnchorDID string

	// SelfDID is this node's DID (the recipient).
	SelfDID string

	// ContextID is the network root context ID that the key must decrypt.
	// When set, FetchContextKey ignores delivered keys for other contexts.
	ContextID string

	// Signer signs query/read messages.
	Signer *dwn.Signer
}

// FetchContextKey queries the anchor DWN for a contextKey record addressed
// to this node and returns the DerivedPrivateJwk payload.
//
// The query relies on the DWN's implicit recipient authorization — any
// authenticated party can query for records where they are the recipient.
// contextKey records are written unencrypted (access controlled by $actions).
//
// Returns nil (no error) if no matching contextKey record is found.
func FetchContextKey(ctx context.Context, params FetchContextKeyParams) (*dwncrypto.DerivedPrivateJwk, error) {
	signer := params.Signer
	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, signer)
	api := dwn.NewDwnAPI(agent)

	// Query for contextKey records addressed to this node.
	//
	// NOTE: We query by protocol/protocolPath/recipient only, without tag filters.
	// Tag-based query filtering has issues with some DWN server deployments, and
	// the recipient + protocol combo is already sufficiently specific for our use case.
	// If multiple contextKeys exist per recipient, we use dateSort to get the most recent.
	records, status, err := api.Query(ctx, params.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.KeyDeliveryProtocolURI,
			ProtocolPath: "contextKey",
			Recipient:    params.SelfDID,
		},
		DateSort: "createdDescending",
	}, "")
	if err != nil {
		return nil, fmt.Errorf("querying contextKey records: %w", err)
	}
	if status.Code != 200 {
		return nil, fmt.Errorf("querying contextKey: unexpected status %d %s", status.Code, status.Detail)
	}
	for _, queryRecord := range records {
		// Query results do not include data; read each candidate newest-first
		// and return the first payload for the requested network context.
		record, readStatus, err := api.Read(ctx, params.AnchorDID, dwn.RecordsFilter{
			RecordID: queryRecord.ID,
		}, "")
		if err != nil {
			return nil, fmt.Errorf("reading contextKey record: %w", err)
		}
		if readStatus.Code != 200 || record == nil {
			return nil, fmt.Errorf("contextKey read failed: %d %s", readStatus.Code, readStatus.Detail)
		}

		// Get the record data. For RecordsRead, data comes from the HTTP body
		// (stored as rawData) or from encodedData (for small inline payloads).
		// contextKey records are written unencrypted (access controlled by $actions),
		// so the data is plaintext JSON.
		dataBytes, err := record.Data().Bytes(ctx)
		if err != nil {
			return nil, fmt.Errorf("reading contextKey data: %w", err)
		}

		key, err := dwncrypto.ParseDerivedPrivateJwk(dataBytes)
		if err != nil {
			return nil, err
		}
		if !contextKeyMatchesContext(key, params.ContextID) {
			continue
		}
		return key, nil
	}

	return nil, nil // No matching record found.
}

func contextKeyMatchesContext(key *dwncrypto.DerivedPrivateJwk, contextID string) bool {
	if contextID == "" {
		return true
	}
	if key == nil || key.DerivationScheme != dwncrypto.DerivationSchemeProtocolContext {
		return false
	}
	expectedPath := dwncrypto.BuildProtocolContextDerivation(contextID)
	if len(key.DerivationPath) != len(expectedPath) {
		return false
	}
	for i := range expectedPath {
		if key.DerivationPath[i] != expectedPath[i] {
			return false
		}
	}
	return true
}

// EnsureKeyDeliveryProtocol installs the key-delivery protocol on the
// given DWN with $encryption directives injected.
//
// This should be called once during network creation, before any contextKey
// records are written.
func EnsureKeyDeliveryProtocol(ctx context.Context, endpoint string, ownerDID string, signer *dwn.Signer, encPrivateKey []byte, encKeyID string) error {
	// Inject encryption keys into the key-delivery protocol definition.
	protocolDef, err := dwncrypto.InjectEncryptionDirectives(
		protocols.KeyDeliveryProtocolJSON,
		encPrivateKey,
		encKeyID,
	)
	if err != nil {
		return fmt.Errorf("injecting encryption keys into key-delivery protocol: %w", err)
	}

	agent := dwn.NewSimpleAgent(endpoint, signer)
	api := dwn.NewDwnAPI(agent)

	status, err := api.ConfigureProtocol(ctx, ownerDID, protocolDef)
	if err != nil {
		return fmt.Errorf("configuring key-delivery protocol: %w", err)
	}
	// 409 = already configured, which is fine.
	if status.Code >= 300 && status.Code != 409 {
		return fmt.Errorf("key-delivery protocol configure failed: %d %s", status.Code, status.Detail)
	}

	return nil
}
