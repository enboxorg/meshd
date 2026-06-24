package mesh

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

	// PermissionGrantID invokes a wallet/member grant when a local node DID
	// writes the contextKey record on behalf of the wallet owner.
	PermissionGrantID string

	// RecipientKeyDelivery is the recipient's key-delivery ProtocolPath
	// public key. When present, the contextKey payload is encrypted to it.
	RecipientKeyDelivery *dwncrypto.KeyDeliveryPublic
}

// DeliverContextKey derives the Protocol Context key for a context and
// writes a contextKey record to the anchor's DWN.
//
// The contextKey record payload is encrypted to the recipient's key-delivery
// ProtocolPath public key when it is available. It is never Protocol Context
// encrypted, because that would create a circular key exchange dependency.
// For older/manual flows that only have a recipient DID, meshd falls back to
// plaintext JSON with key-delivery protocol authorization controlling reads.
//
// This can be called by the DWN owner (who can derive the context key from the
// root key) or by a wallet-authorized node that already holds the delivered
// context key locally.
func (m *KeyDeliveryManager) DeliverContextKey(ctx context.Context, params DeliverContextKeyParams) error {
	if m.EncryptionKeyManager == nil {
		return fmt.Errorf("EncryptionKeyManager is required")
	}

	logger := m.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// 1. Derive or reuse the context key payload.
	contextKeyJwk, err := deliverableContextKeyJwk(m.EncryptionKeyManager, params.ContextID)
	if err != nil {
		return fmt.Errorf("resolving context key: %w", err)
	}

	payload, err := contextKeyJwk.MarshalPayload()
	if err != nil {
		return fmt.Errorf("marshaling context key payload: %w", err)
	}

	// 2. Prefer standard key-delivery encryption when the recipient's public
	//    ProtocolPath key is available. Manual peer-add flows that only have a
	//    DID fall back to authorization-controlled plaintext.
	recipients, err := keyDeliveryEncryptionRecipients(params.RecipientKeyDelivery)
	if err != nil {
		return err
	}

	agent := dwn.NewSimpleAgent(m.Endpoint, m.Signer)
	api := dwn.NewDwnAPI(agent)

	// 3. Write the contextKey record.
	_, status, err := api.Write(ctx, params.AnchorDID, dwn.WriteParams{
		Protocol:             protocols.KeyDeliveryProtocolURI,
		ProtocolPath:         "contextKey",
		DataFormat:           "application/json",
		Recipient:            params.RecipientDID,
		Data:                 payload,
		EncryptionRecipients: recipients,
		PermissionGrantID:    params.PermissionGrantID,
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

func keyDeliveryEncryptionRecipients(public *dwncrypto.KeyDeliveryPublic) ([]dwncrypto.KeyEncryptionInput, error) {
	if public == nil {
		return nil, nil
	}
	rootKeyID := public.RootKeyID
	if rootKeyID == "" {
		rootKeyID = public.PublicKeyJWK.KID
	}
	if rootKeyID == "" {
		return nil, fmt.Errorf("recipient key-delivery rootKeyId is required")
	}
	if public.PublicKeyJWK.X == "" {
		return nil, fmt.Errorf("recipient key-delivery publicKeyJwk.x is required")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(public.PublicKeyJWK.X)
	if err != nil {
		return nil, fmt.Errorf("decoding recipient key-delivery public key: %w", err)
	}
	if len(publicKey) != 32 {
		return nil, fmt.Errorf("recipient key-delivery public key is %d bytes, want 32", len(publicKey))
	}
	return []dwncrypto.KeyEncryptionInput{
		{
			PublicKeyID:      rootKeyID,
			PublicKey:        publicKey,
			DerivationScheme: dwncrypto.DerivationSchemeProtocolPath,
		},
	}, nil
}

func deliverableContextKeyJwk(encMgr *dwncrypto.EncryptionKeyManager, contextID string) (*dwncrypto.DerivedPrivateJwk, error) {
	if encMgr == nil {
		return nil, fmt.Errorf("EncryptionKeyManager is required")
	}
	contextKey := encMgr.GetContextKey(contextID)
	if len(contextKey) > 0 {
		return dwncrypto.NewDerivedPrivateJwk(
			encMgr.RootKeyID,
			dwncrypto.DerivationSchemeProtocolContext,
			dwncrypto.BuildProtocolContextDerivation(contextID),
			contextKey,
		)
	}
	if encMgr.IsOwner() {
		return encMgr.DeriveContextKeyJwk(contextID)
	}
	return nil, fmt.Errorf("context key delivery requires the owner root key or a cached context key for %s", contextID)
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

	// EncryptionKeyManager holds this node's encryption root and is used to
	// decrypt wallet-authored contextKey records encrypted to the node.
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager
}

// FetchContextKey queries the anchor DWN for a contextKey record addressed
// to this node and returns the DerivedPrivateJwk payload.
//
// The query relies on the DWN's implicit recipient authorization — any
// authenticated party can query for records where they are the recipient.
// contextKey records may be written unencrypted by meshd or encrypted by a
// wallet to the node's key-delivery ProtocolPath public key.
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
		// The bytes may be plaintext JSON (CLI-authored) or ciphertext
		// (wallet-authored with JWE metadata in RawEntry).
		dataBytes, err := record.Data().Bytes(ctx)
		if err != nil {
			return nil, fmt.Errorf("reading contextKey data: %w", err)
		}

		key, err := parseContextKeyRecordData(record.RawEntry, dataBytes, params.EncryptionKeyManager)
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

func parseContextKeyRecordData(rawEntry json.RawMessage, dataBytes []byte, encMgr *dwncrypto.EncryptionKeyManager) (*dwncrypto.DerivedPrivateJwk, error) {
	key, parseErr := dwncrypto.ParseDerivedPrivateJwk(dataBytes)
	if parseErr == nil {
		return key, nil
	}

	enc := contextKeyRecordEncryption(rawEntry)
	if enc == nil {
		return nil, parseErr
	}
	if encMgr == nil || len(encMgr.RootPrivateKey) == 0 || encMgr.RootKeyID == "" {
		return nil, fmt.Errorf("decrypting encrypted contextKey requires this node's encryption key manager")
	}

	privKey, err := dwncrypto.DeriveKeyDeliveryDecryptionKey(encMgr.RootPrivateKey, protocols.KeyDeliveryProtocolURI)
	if err != nil {
		return nil, err
	}

	plaintext, err := dwncrypto.DecryptData(dataBytes, enc, privKey, encMgr.RootKeyID)
	if err != nil {
		return nil, fmt.Errorf("decrypting contextKey data: %w", err)
	}

	key, err = dwncrypto.ParseDerivedPrivateJwk(plaintext)
	if err != nil {
		return nil, fmt.Errorf("parsing decrypted contextKey data: %w", err)
	}
	return key, nil
}

func contextKeyRecordEncryption(rawEntry json.RawMessage) *dwncrypto.Encryption {
	if len(rawEntry) == 0 {
		return nil
	}

	var entry struct {
		RecordsWrite struct {
			Encryption *dwncrypto.Encryption `json:"encryption"`
		} `json:"recordsWrite"`
		Encryption *dwncrypto.Encryption `json:"encryption"`
	}
	if err := json.Unmarshal(rawEntry, &entry); err != nil {
		return nil
	}
	if entry.Encryption != nil {
		return entry.Encryption
	}
	return entry.RecordsWrite.Encryption
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
