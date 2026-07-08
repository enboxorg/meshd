package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
)

// RolePathKeyProvider yields the private half of a role path's $keyAgreement
// key — the "seal key" that authorizes minting and unsealing role-audience
// keys. The network owner derives it from its encryption root; a delegate
// derives it from a covering grantKey subtree key.
type RolePathKeyProvider interface {
	RolePathPrivateKey(protocol, rolePath string) ([]byte, error)
}

// OwnerRolePathKeys derives role-path seal keys from the network owner's
// encryption root via its EncryptionKeyManager.
type OwnerRolePathKeys struct {
	Manager *dwncrypto.EncryptionKeyManager
}

// RolePathPrivateKey implements RolePathKeyProvider.
func (o OwnerRolePathKeys) RolePathPrivateKey(protocol, rolePath string) ([]byte, error) {
	if o.Manager == nil {
		return nil, fmt.Errorf("encryption key manager is required")
	}
	if protocol != o.Manager.ProtocolURI {
		return nil, fmt.Errorf("protocol %s does not match key manager protocol %s", protocol, o.Manager.ProtocolURI)
	}
	return o.Manager.DeriveDecryptionKey(rolePath)
}

// SealedAudienceSourceConfig configures a SealedAudienceSource.
type SealedAudienceSourceConfig struct {
	// Client talks to the source DWN (the anchor tenant's endpoint).
	Client *dwn.Client
	// Tenant is the DWN tenant (network owner DID) hosting the records.
	Tenant string
	// ProtocolDefinition is the INSTALLED source protocol definition with
	// $keyAgreement public keys injected. Required for minting.
	ProtocolDefinition json.RawMessage
	// QueryAuth authorizes audience-record queries (role, plain grant, or
	// delegated grant). The tenant queries plainly with a zero value.
	QueryAuth dwn.MessageAuth
	// WriteAuth authorizes audience-record mint writes.
	WriteAuth dwn.MessageAuth
	// SealKeys provides role-path seal keys. When nil the source is
	// read-only: minting and unsealing are disabled.
	SealKeys RolePathKeyProvider
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// SealedAudienceSource resolves and mints `$encryption/audience` records on
// the source DWN. It implements dwncrypto.AudienceSource for the encrypted
// write path (mint-on-miss, matching the SDK's seal-covered audience
// minting) and additionally recovers audience PRIVATE keys for the read
// path by unsealing the audience record's sealedPrivateKey.
type SealedAudienceSource struct {
	client   *dwn.Client
	tenant   string
	protoDef json.RawMessage
	qAuth    dwn.MessageAuth
	wAuth    dwn.MessageAuth
	sealKeys RolePathKeyProvider
	logger   *slog.Logger

	mu    sync.Mutex
	cache map[string]*audienceRecord // tuple key → current audience
}

type audienceRecord struct {
	payload     dwncrypto.AudiencePayload
	recordID    string
	dateCreated string
	author      string
}

// NewSealedAudienceSource creates a SealedAudienceSource.
func NewSealedAudienceSource(cfg SealedAudienceSourceConfig) *SealedAudienceSource {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &SealedAudienceSource{
		client:   cfg.Client,
		tenant:   cfg.Tenant,
		protoDef: cfg.ProtocolDefinition,
		qAuth:    cfg.QueryAuth,
		wAuth:    cfg.WriteAuth,
		sealKeys: cfg.SealKeys,
		logger:   logger,
		cache:    make(map[string]*audienceRecord),
	}
}

func tupleKey(protocol, rolePath, contextID string) string {
	return protocol + "\n" + rolePath + "\n" + contextID
}

// Current implements dwncrypto.AudienceSource: it returns the current
// audience public key for the tuple, minting (and writing) a fresh sealed
// audience record when none exists and a seal key is available.
func (s *SealedAudienceSource) Current(ctx context.Context, protocol, rolePath, contextID string) ([]byte, string, error) {
	rec, err := s.current(ctx, protocol, rolePath, contextID, true)
	if err != nil {
		return nil, "", err
	}
	pub, err := publicKeyBytesFromJWK(&rec.payload.PublicKeyJwk)
	if err != nil {
		return nil, "", fmt.Errorf("parsing audience public key: %w", err)
	}
	return pub, rec.payload.KeyID, nil
}

// AudiencePrivateKeyByKeyID recovers the audience PRIVATE key for the given
// (protocol, rolePath, keyId) by unsealing the audience record's
// sealedPrivateKey with the role-path seal key. The tuple contextId comes
// from the fetched record itself (a roleAudience keyEncryption entry does
// not carry it). Read-side use: unwrapping roleAudience entries on records
// this reader can already derive seal keys for.
func (s *SealedAudienceSource) AudiencePrivateKeyByKeyID(ctx context.Context, protocol, rolePath, keyID string) ([]byte, error) {
	if s.sealKeys == nil {
		return nil, fmt.Errorf("no seal keys available")
	}
	rec, err := s.audienceByKeyID(ctx, protocol, rolePath, keyID)
	if err != nil {
		return nil, err
	}
	sealKey, err := s.sealKeys.RolePathPrivateKey(protocol, rolePath)
	if err != nil {
		return nil, fmt.Errorf("deriving seal key for %s: %w", rolePath, err)
	}
	defer clear(sealKey)
	return dwncrypto.UnsealAudienceRecord(&rec.payload, sealKey)
}

// current returns the projected current audience record for a tuple,
// consulting the cache, then the DWN, then minting when permitted.
func (s *SealedAudienceSource) current(ctx context.Context, protocol, rolePath, contextID string, mint bool) (*audienceRecord, error) {
	key := tupleKey(protocol, rolePath, contextID)
	s.mu.Lock()
	if rec, ok := s.cache[key]; ok {
		s.mu.Unlock()
		return rec, nil
	}
	s.mu.Unlock()

	records, err := s.queryAudience(ctx, map[string]any{
		"protocol":  protocol,
		"rolePath":  rolePath,
		"contextId": contextID,
	}, protocol, func(p *dwncrypto.AudiencePayload) bool {
		return p.Protocol == protocol && p.RolePath == rolePath && p.ContextID == contextID
	})
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		if !mint {
			return nil, fmt.Errorf("no audience record for %s %s ctx %q", protocol, rolePath, contextID)
		}
		rec, err := s.mint(ctx, protocol, rolePath, contextID)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.cache[key] = rec
		s.mu.Unlock()
		return rec, nil
	}

	rec := projectCurrentAudience(records, s.tenant)
	s.mu.Lock()
	s.cache[key] = rec
	s.mu.Unlock()
	return rec, nil
}

// audienceByKeyID fetches the audience record with an exact keyId tag,
// bypassing current-projection (old keys stay resolvable for decryption).
func (s *SealedAudienceSource) audienceByKeyID(ctx context.Context, protocol, rolePath, keyID string) (*audienceRecord, error) {
	s.mu.Lock()
	for _, rec := range s.cache {
		if rec.payload.KeyID == keyID && rec.payload.Protocol == protocol && rec.payload.RolePath == rolePath {
			s.mu.Unlock()
			return rec, nil
		}
	}
	s.mu.Unlock()

	records, err := s.queryAudience(ctx, map[string]any{
		"protocol": protocol,
		"rolePath": rolePath,
		"keyId":    keyID,
	}, protocol, func(p *dwncrypto.AudiencePayload) bool {
		return p.Protocol == protocol && p.RolePath == rolePath && p.KeyID == keyID
	})
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no audience record for keyId %s (%s %s)", keyID, protocol, rolePath)
	}
	return records[0], nil
}

// queryAudience queries `$encryption/audience` records by tag filter and
// parses entries that pass validation and the given payload predicate.
func (s *SealedAudienceSource) queryAudience(ctx context.Context, filterTags map[string]any, protocol string, matches func(*dwncrypto.AudiencePayload) bool) ([]*audienceRecord, error) {
	reply, err := s.client.RecordsQueryWithAuth(ctx, s.tenant, dwn.RecordsFilter{
		Protocol:     protocol,
		ProtocolPath: dwncrypto.EncryptionControlAudiencePath,
		Tags:         filterTags,
	}, "createdAscending", nil, s.qAuth)
	if err != nil {
		return nil, fmt.Errorf("querying audience records: %w", err)
	}
	entries, err := dwn.QueryEntries(reply)
	if err != nil {
		return nil, fmt.Errorf("parsing audience query: %w", err)
	}

	var records []*audienceRecord
	for _, entry := range entries {
		rec, err := parseAudienceEntry(entry)
		if err != nil {
			s.logger.Debug("skipping audience record", slog.Any("error", err))
			continue
		}
		if !matches(&rec.payload) {
			continue
		}
		records = append(records, rec)
	}
	return records, nil
}

// mint generates a fresh audience key pair, seals its private half to the
// role-path $keyAgreement key, writes the audience record, and returns it.
// Mirrors the SDK's seal-covered minting: refuses when this actor cannot
// derive the seal key (an unsealable audience record would be unrecoverable).
func (s *SealedAudienceSource) mint(ctx context.Context, protocol, rolePath, contextID string) (*audienceRecord, error) {
	if s.sealKeys == nil {
		return nil, fmt.Errorf("no audience record exists for %s %s ctx %q and this node cannot mint one (no seal keys)", protocol, rolePath, contextID)
	}
	if len(s.protoDef) == 0 {
		return nil, fmt.Errorf("protocol definition required to mint audience records")
	}
	// Seal-coverage guard: only mint what we can unseal.
	sealKey, err := s.sealKeys.RolePathPrivateKey(protocol, rolePath)
	if err != nil {
		return nil, fmt.Errorf("refusing to mint audience for %s (no seal coverage): %w", rolePath, err)
	}

	sealingPub, _, err := dwncrypto.KeyAgreementPublicKeyAtPath(s.protoDef, rolePath)
	if err != nil {
		clear(sealKey)
		return nil, fmt.Errorf("resolving role-path key agreement key: %w", err)
	}
	derivedSealPub, err := dwncrypto.X25519PublicKey(sealKey)
	clear(sealKey)
	if err != nil {
		return nil, fmt.Errorf("deriving seal public key for %s: %w", rolePath, err)
	}
	if !bytes.Equal(derivedSealPub, sealingPub) {
		return nil, fmt.Errorf("refusing to mint audience for %s: seal key does not match installed protocol definition", rolePath)
	}

	km, err := dwncrypto.GenerateAudienceKey()
	if err != nil {
		return nil, fmt.Errorf("generating audience key: %w", err)
	}
	payloadPtr, err := dwncrypto.BuildAudiencePayload(km, sealingPub, protocol, rolePath, contextID)
	if err != nil {
		return nil, fmt.Errorf("sealing audience key: %w", err)
	}
	payload := *payloadPtr
	data, err := json.Marshal(&payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling audience payload: %w", err)
	}
	keyID := payload.KeyID

	result, err := s.client.RecordsWrite(ctx, s.tenant, dwn.RecordsWriteOptions{
		Protocol:     protocol,
		ProtocolPath: dwncrypto.EncryptionControlAudiencePath,
		Schema:       dwncrypto.EncryptionControlAudienceSchemaURI,
		DataFormat:   "application/json",
		Data:         data,
		Tags: map[string]any{
			"protocol":  protocol,
			"rolePath":  rolePath,
			"contextId": contextID,
			"keyId":     keyID,
		},
		ProtocolRole:      s.wAuth.ProtocolRole,
		PermissionGrantID: s.wAuth.PermissionGrantID,
		DelegatedGrant:    s.wAuth.DelegatedGrant,
	})
	if err != nil {
		return nil, fmt.Errorf("writing audience record: %w", err)
	}
	if result.Reply == nil || result.Reply.Status.Code >= 300 {
		code, detail := 0, "nil reply"
		if result.Reply != nil {
			code, detail = result.Reply.Status.Code, result.Reply.Status.Detail
		}
		return nil, fmt.Errorf("audience record write failed: %d %s", code, detail)
	}

	s.logger.Info("minted role-audience key",
		slog.String("protocol", protocol),
		slog.String("rolePath", rolePath),
		slog.String("contextId", contextID),
		slog.String("keyId", keyID),
	)

	return &audienceRecord{
		payload:     payload,
		recordID:    result.RecordID,
		dateCreated: stringDescriptorField(result.Message.Descriptor, "dateCreated"),
		author:      s.tenant,
	}, nil
}

// publicKeyBytesFromJWK decodes the raw X25519 public key from a JWK.
func publicKeyBytesFromJWK(jwk *dwncrypto.PublicKeyJWK) ([]byte, error) {
	if jwk.KTY != "OKP" || jwk.CRV != "X25519" {
		return nil, fmt.Errorf("unsupported key type %s/%s", jwk.KTY, jwk.CRV)
	}
	pub, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("decoding public key: %w", err)
	}
	if len(pub) != 32 {
		return nil, fmt.Errorf("invalid X25519 public key length %d", len(pub))
	}
	return pub, nil
}

// projectCurrentAudience picks the single current audience record for a
// tuple: tenant-authored first, then oldest dateCreated, then lowest
// recordId — mirroring the SDK's resolveCurrentAudienceRecord ordering.
func projectCurrentAudience(records []*audienceRecord, tenant string) *audienceRecord {
	sorted := append([]*audienceRecord(nil), records...)
	sort.SliceStable(sorted, func(i, j int) bool {
		iTenant := sorted[i].author == tenant
		jTenant := sorted[j].author == tenant
		if iTenant != jTenant {
			return iTenant
		}
		if sorted[i].dateCreated != sorted[j].dateCreated {
			return sorted[i].dateCreated < sorted[j].dateCreated
		}
		return sorted[i].recordID < sorted[j].recordID
	})
	return sorted[0]
}

// parseAudienceEntry parses an `$encryption/audience` query entry into its
// payload plus the projection ordering fields.
func parseAudienceEntry(entry json.RawMessage) (*audienceRecord, error) {
	data, ok := entryEncodedData(entry)
	if !ok {
		return nil, fmt.Errorf("audience entry has no inline data")
	}
	var payload dwncrypto.AudiencePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("parsing audience payload: %w", err)
	}
	if err := dwncrypto.VerifyAudiencePayload(&payload); err != nil {
		return nil, fmt.Errorf("invalid audience payload: %w", err)
	}

	var meta struct {
		RecordID     string         `json:"recordId"`
		Descriptor   map[string]any `json:"descriptor"`
		RecordsWrite *struct {
			RecordID   string         `json:"recordId"`
			Descriptor map[string]any `json:"descriptor"`
		} `json:"recordsWrite"`
	}
	if err := json.Unmarshal(entry, &meta); err != nil {
		return nil, fmt.Errorf("parsing audience entry: %w", err)
	}
	recordID := meta.RecordID
	descriptor := meta.Descriptor
	if recordID == "" && meta.RecordsWrite != nil {
		recordID = meta.RecordsWrite.RecordID
		descriptor = meta.RecordsWrite.Descriptor
	}

	return &audienceRecord{
		payload:     payload,
		recordID:    recordID,
		dateCreated: stringDescriptorField(descriptor, "dateCreated"),
		author:      entrySignerDID(entry),
	}, nil
}

func stringDescriptorField(descriptor map[string]any, field string) string {
	if descriptor == nil {
		return ""
	}
	v, _ := descriptor[field].(string)
	return v
}
