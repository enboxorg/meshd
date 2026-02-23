package dwn

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// GeneralJWS represents a JWS in General JSON Serialization (RFC 7515).
// This matches the DWN SDK's GeneralJws type.
type GeneralJWS struct {
	Payload    string         `json:"payload"`
	Signatures []JWSSignature `json:"signatures"`
}

// JWSSignature is one signature in the JWS signatures array.
type JWSSignature struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

// jwsProtectedHeader is the JWS Protected Header.
type jwsProtectedHeader struct {
	ALG string `json:"alg"`
	KID string `json:"kid"` // DID URL, e.g. "did:dht:abc...#0"
}

// SignJWS creates a General JSON Serialization JWS signed with Ed25519.
//
// The payload is JSON-serialized, base64url-encoded, then signed per JWS
// spec: sign(ASCII(base64url(header)) || '.' || ASCII(base64url(payload))).
func SignJWS(payload any, kid string, privateKey ed25519.PrivateKey) (*GeneralJWS, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling payload: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	header := jwsProtectedHeader{
		ALG: "EdDSA",
		KID: kid,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("marshaling header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	sigInput := headerB64 + "." + payloadB64
	sig := ed25519.Sign(privateKey, []byte(sigInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return &GeneralJWS{
		Payload: payloadB64,
		Signatures: []JWSSignature{
			{
				Protected: headerB64,
				Signature: sigB64,
			},
		},
	}, nil
}
