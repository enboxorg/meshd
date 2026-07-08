package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
)

// GrantKeySet holds the protocol-path subtree keys delivered to a delegate
// via Encryption-protocol grantKey records. The wallet writes one grantKey
// record per eligible grant scope; each carries an owner-derived subtree
// private key wrapped to the delegate's root X25519 key (pre-supplied
// delegate mode, enbox/wrapped-grant-key@1).
type GrantKeySet struct {
	decrypters []*dwncrypto.SubtreeDecrypter
}

// FetchGrantKeys queries the owner tenant for grantKey records addressed to
// granteeDID under the given source protocol and unwraps every
// wrapped-grant-key envelope with the delegate's root X25519 private key.
//
// grantKey records are recipient-readable, so the query is signed plainly by
// the delegate (no role or grant invocation).
func FetchGrantKeys(
	ctx context.Context,
	client *dwn.Client,
	tenant string,
	granteeDID string,
	protocolURI string,
	rootX25519Priv []byte,
	logger *slog.Logger,
) (*GrantKeySet, error) {
	if logger == nil {
		logger = slog.Default()
	}
	reply, err := client.RecordsQuery(ctx, tenant, dwn.RecordsFilter{
		Protocol:     dwncrypto.EncryptionProtocolURI,
		ProtocolPath: dwncrypto.GrantKeyProtocolPath,
		Recipient:    granteeDID,
		Tags:         map[string]any{"protocol": protocolURI},
	}, "createdAscending", nil, "")
	if err != nil {
		return nil, fmt.Errorf("querying grantKey records: %w", err)
	}
	entries, err := dwn.QueryEntries(reply)
	if err != nil {
		return nil, fmt.Errorf("parsing grantKey query: %w", err)
	}

	set := &GrantKeySet{}
	for _, entry := range entries {
		payload, err := unwrapGrantKeyEntry(entry, rootX25519Priv)
		if err != nil {
			logger.Debug("skipping grantKey record", slog.Any("error", err))
			continue
		}
		dec, err := dwncrypto.NewSubtreeDecrypterFromGrantKey(payload)
		if err != nil {
			logger.Debug("skipping grantKey subtree", slog.Any("error", err))
			continue
		}
		set.decrypters = append(set.decrypters, dec)
	}
	return set, nil
}

// unwrapGrantKeyEntry extracts the plaintext wrapped-grant-key envelope from
// a grantKey query entry and unwraps it with the delegate root key.
func unwrapGrantKeyEntry(entry json.RawMessage, rootX25519Priv []byte) (*dwncrypto.GrantKeyPayload, error) {
	data, ok := entryEncodedData(entry)
	if !ok {
		return nil, fmt.Errorf("grantKey entry has no inline data")
	}
	return dwncrypto.UnwrapGrantKeyEnvelope(data, rootX25519Priv)
}

// Empty reports whether the set holds no usable subtree keys.
func (s *GrantKeySet) Empty() bool {
	return s == nil || len(s.decrypters) == 0
}

// DecrypterFor returns the first subtree decrypter covering the given
// protocol path, or nil when none covers it.
func (s *GrantKeySet) DecrypterFor(protocol, protocolPath string) *dwncrypto.SubtreeDecrypter {
	if s == nil {
		return nil
	}
	for _, dec := range s.decrypters {
		if dec.Covers(protocol, protocolPath) {
			return dec
		}
	}
	return nil
}

// RolePathPrivateKey derives the role-path private key for the given role
// from a covering subtree key. This is the seal key for role-audience
// records — holding it authorizes minting and unsealing audience keys.
func (s *GrantKeySet) RolePathPrivateKey(protocol, rolePath string) ([]byte, error) {
	dec := s.DecrypterFor(protocol, rolePath)
	if dec == nil {
		return nil, fmt.Errorf("no grant key covers role path %s %s", protocol, rolePath)
	}
	return dec.RolePathKey(protocol, rolePath)
}

// Close zeroizes all held key material.
func (s *GrantKeySet) Close() {
	if s == nil {
		return
	}
	for _, dec := range s.decrypters {
		dec.Close()
	}
	s.decrypters = nil
}

// entryEncodedData extracts and decodes the inline encodedData of a query
// entry (flat or recordsWrite-wrapped form).
func entryEncodedData(entry json.RawMessage) ([]byte, bool) {
	var flat struct {
		EncodedData string `json:"encodedData"`
	}
	var wrapped struct {
		RecordsWrite struct {
			EncodedData string `json:"encodedData"`
		} `json:"recordsWrite"`
	}
	encoded := ""
	if err := json.Unmarshal(entry, &wrapped); err == nil && wrapped.RecordsWrite.EncodedData != "" {
		encoded = wrapped.RecordsWrite.EncodedData
	} else if err := json.Unmarshal(entry, &flat); err == nil && flat.EncodedData != "" {
		encoded = flat.EncodedData
	}
	if encoded == "" {
		return nil, false
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		if data, err = base64.URLEncoding.DecodeString(encoded); err != nil {
			return nil, false
		}
	}
	return data, true
}

// entrySignerDID extracts the signer DID from a query entry's authorization
// JWS (the kid header minus the fragment). Delegated messages resolve to the
// GRANTOR via authorDelegatedGrant semantics server-side; for the audience
// projection below the raw signer is what distinguishes tenant-authored
// records, so the immediate signer is returned.
func entrySignerDID(entry json.RawMessage) string {
	var msg struct {
		Authorization struct {
			Signature struct {
				Signatures []struct {
					Protected string `json:"protected"`
				} `json:"signatures"`
			} `json:"signature"`
			AuthorDelegatedGrant json.RawMessage `json:"authorDelegatedGrant"`
		} `json:"authorization"`
		RecordsWrite json.RawMessage `json:"recordsWrite"`
	}
	if err := json.Unmarshal(entry, &msg); err != nil {
		return ""
	}
	if len(msg.Authorization.Signature.Signatures) == 0 && len(msg.RecordsWrite) > 0 {
		if err := json.Unmarshal(msg.RecordsWrite, &msg); err != nil {
			return ""
		}
	}
	if len(msg.Authorization.Signature.Signatures) == 0 {
		return ""
	}
	// A delegated write's logical author is the grantor.
	if len(msg.Authorization.AuthorDelegatedGrant) > 0 {
		var grant struct {
			Authorization struct {
				Signature struct {
					Signatures []struct {
						Protected string `json:"protected"`
					} `json:"signatures"`
				} `json:"signature"`
			} `json:"authorization"`
		}
		if err := json.Unmarshal(msg.Authorization.AuthorDelegatedGrant, &grant); err == nil &&
			len(grant.Authorization.Signature.Signatures) > 0 {
			if did := didFromProtectedHeader(grant.Authorization.Signature.Signatures[0].Protected); did != "" {
				return did
			}
		}
	}
	return didFromProtectedHeader(msg.Authorization.Signature.Signatures[0].Protected)
}

func didFromProtectedHeader(protected string) string {
	headerBytes, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return ""
	}
	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return ""
	}
	did, _, _ := strings.Cut(header.Kid, "#")
	return did
}
