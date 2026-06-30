package control

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

// DWNAudienceEpochSource resolves role-audience epochs from the owner DWN by
// querying EncryptionProtocol `audienceEpoch` records. It is the write-path
// counterpart of fetchAudienceKeyRecord on the read path and implements
// dwncrypto.AudienceEpochSource so it can be passed to BuildWriteEncryption.
//
// audienceEpoch records are published plaintext, so the query needs neither a
// protocol role nor a permission grant.
type DWNAudienceEpochSource struct {
	ctx    context.Context
	client *dwn.Client
	tenant string
	logger *slog.Logger
}

var _ dwncrypto.AudienceEpochSource = (*DWNAudienceEpochSource)(nil)

// NewDWNAudienceEpochSource creates an AudienceEpochSource that queries the
// given DWN tenant. The context bounds the lifetime of the per-write lookups
// (the AudienceEpochSource.Latest interface carries no context of its own).
func NewDWNAudienceEpochSource(ctx context.Context, client *dwn.Client, tenant string, logger *slog.Logger) *DWNAudienceEpochSource {
	if logger == nil {
		logger = slog.Default()
	}
	return &DWNAudienceEpochSource{
		ctx:    ctx,
		client: client,
		tenant: tenant,
		logger: logger,
	}
}

// Latest queries the owner DWN for the most recent audienceEpoch matching
// (protocol, contextId, role) and returns its audience public key, epoch and
// keyId. It returns an error when no epoch exists; the write must then fail
// rather than mint a fresh audience key.
func (s *DWNAudienceEpochSource) Latest(protocol, contextID, role string) ([]byte, int, string, error) {
	reply, err := s.client.RecordsQuery(s.ctx, s.tenant, dwn.RecordsFilter{
		Protocol:     protocols.EncryptionProtocolURI,
		ProtocolPath: "audienceEpoch",
		Tags: map[string]any{
			"protocol":  protocol,
			"contextId": contextID,
			"role":      role,
		},
	}, "createdDescending", nil, "", "")
	if err != nil {
		return nil, 0, "", fmt.Errorf("querying audienceEpoch records: %w", err)
	}

	entries, err := dwn.QueryEntries(reply)
	if err != nil {
		return nil, 0, "", fmt.Errorf("parsing audienceEpoch query: %w", err)
	}

	payloads := make([]audienceEpochPayload, 0, len(entries))
	for _, entry := range entries {
		p, ok := parseAudienceEpochEntry(entry)
		if !ok {
			continue
		}
		payloads = append(payloads, p)
	}

	best, ok := selectLatestAudienceEpoch(payloads, protocol, contextID, role)
	if !ok {
		return nil, 0, "", fmt.Errorf("missing audienceEpoch for protocol=%q context=%q role=%q", protocol, contextID, role)
	}

	pub, err := decodeBase64URL(best.PublicKeyJwk.X)
	if err != nil {
		return nil, 0, "", fmt.Errorf("decoding audienceEpoch publicKeyJwk.x: %w", err)
	}
	return pub, best.Epoch, best.KeyID, nil
}

// audienceEpochPayload is the plaintext data of an EncryptionProtocol
// audienceEpoch record.
type audienceEpochPayload struct {
	Protocol     string                 `json:"protocol"`
	ContextID    string                 `json:"contextId"`
	Role         string                 `json:"role"`
	Epoch        int                    `json:"epoch"`
	KeyID        string                 `json:"keyId"`
	PublicKeyJwk dwncrypto.PublicKeyJWK `json:"publicKeyJwk"`
}

// selectLatestAudienceEpoch returns the highest-epoch payload matching the
// (protocol, contextId, role) tuple. The match is re-checked against the
// plaintext payload as defense in depth against an over-broad tag query.
func selectLatestAudienceEpoch(payloads []audienceEpochPayload, protocol, contextID, role string) (audienceEpochPayload, bool) {
	bestIdx := -1
	for i := range payloads {
		p := payloads[i]
		if p.Protocol != protocol || p.ContextID != contextID || p.Role != role {
			continue
		}
		if p.PublicKeyJwk.X == "" {
			continue
		}
		if bestIdx == -1 || p.Epoch > payloads[bestIdx].Epoch {
			bestIdx = i
		}
	}
	if bestIdx == -1 {
		return audienceEpochPayload{}, false
	}
	return payloads[bestIdx], true
}

// parseAudienceEpochEntry extracts the audienceEpoch plaintext payload from a
// query entry (wrapped or flat form). audienceEpoch records are not encrypted.
func parseAudienceEpochEntry(entry json.RawMessage) (audienceEpochPayload, bool) {
	type record struct {
		EncodedData string `json:"encodedData"`
	}

	rec := record{}
	var wrapped struct {
		RecordsWrite record `json:"recordsWrite"`
	}
	if err := json.Unmarshal(entry, &wrapped); err == nil && wrapped.RecordsWrite.EncodedData != "" {
		rec = wrapped.RecordsWrite
	} else if err := json.Unmarshal(entry, &rec); err != nil {
		return audienceEpochPayload{}, false
	}

	if rec.EncodedData == "" {
		return audienceEpochPayload{}, false
	}
	data, err := decodeBase64URL(rec.EncodedData)
	if err != nil {
		return audienceEpochPayload{}, false
	}

	var payload audienceEpochPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return audienceEpochPayload{}, false
	}
	return payload, true
}

// decodeBase64URL decodes a base64url string with or without padding.
func decodeBase64URL(s string) ([]byte, error) {
	if data, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
