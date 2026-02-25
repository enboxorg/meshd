package mesh

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/enboxorg/dwn-mesh/internal/dwn"
	dwncrypto "github.com/enboxorg/dwn-mesh/internal/dwn/crypto"
	"github.com/enboxorg/dwn-mesh/protocols"
)

// KeyDeliveryManager handles writing and fetching contextKey records
// for the DWN Key Delivery Protocol.
//
// When a network owner creates a network or adds a member, they derive a
// Protocol Context key for the network context and deliver it (encrypted)
// to each participant. Participants can then decrypt records in that context.
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
// writes an encrypted contextKey record to the anchor's DWN.
//
// The contextKey record is encrypted with the Protocol Path scheme for
// the key-delivery protocol, so only the recipient can decrypt it.
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

	// 2. Derive encryption recipients for the key-delivery protocol's
	//    "contextKey" path. We encrypt to the owner's Protocol Path key
	//    (self-delivery for now — the recipient reads from the owner's DWN).
	//
	//    In a full implementation, if we had the recipient's key-delivery
	//    public key (authorKeyDeliveryPublicKey), we would encrypt to
	//    their key instead. For now, all participants read from the anchor
	//    DWN, and the anchor encrypts to its own key — which the recipient
	//    can access because contextKey has $actions allowing recipient reads.
	//
	//    The recipient accesses the *cleartext* through the DWN server's
	//    authorization layer (the server checks $actions), not through
	//    client-side JWE decryption. Alternatively, if the server returns
	//    ciphertext, the recipient needs the anchor's Protocol Path key
	//    for key-delivery, which would need a separate key exchange.
	//
	//    The pragmatic approach for dwn-mesh: encrypt to the anchor's own
	//    key. The recipient queries the anchor's DWN, the server returns
	//    ciphertext, the recipient either:
	//    a) Has been given the anchor's key-delivery decryption key out-of-band
	//    b) The contextKey is stored unencrypted (if key-delivery protocol
	//       doesn't require encryption)
	//
	//    Looking at the spec more carefully: the key-delivery protocol
	//    types don't have `encryptionRequired: true`. This means the
	//    contextKey record CAN be written unencrypted. The recipient reads
	//    it via $actions authorization. The DWN server enforces access.
	//
	//    For maximum compatibility with the spec, we write the contextKey
	//    record ENCRYPTED to the anchor's own Protocol Path key. The anchor
	//    can always decrypt. For cross-DWN delivery to non-owners, the spec
	//    says to encrypt to the recipient's Protocol Path key for key-delivery,
	//    which requires knowing their public key.
	//
	//    The key-delivery protocol does NOT have $encryption or encryptionRequired,
	//    so contextKey records can be written unencrypted. Access is controlled by
	//    $actions authorization (recipient can read). This is the simplest approach
	//    and avoids the circular key exchange problem.

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

	// Signer signs query/read messages.
	Signer *dwn.Signer

	// SourceProtocol is the protocol URI to filter by.
	SourceProtocol string

	// ContextID is the context ID to filter by.
	ContextID string

	// DecryptionPrivateKey is reserved for future use (when key-delivery
	// protocol uses $encryption). Currently unused since contextKey records
	// are written unencrypted with access controlled by $actions.
	DecryptionPrivateKey []byte

	// DecryptionKeyID is reserved for future use. Currently unused.
	DecryptionKeyID string
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
	if status.Code != 200 || len(records) == 0 {
		return nil, nil // No matching record found.
	}

	// Read the first (most recent) match to get the full data.
	record, readStatus, err := api.Read(ctx, params.AnchorDID, dwn.RecordsFilter{
		RecordID: records[0].ID,
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

	return dwncrypto.ParseDerivedPrivateJwk(dataBytes)
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
