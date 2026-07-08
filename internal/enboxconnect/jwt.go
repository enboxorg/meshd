package enboxconnect

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/enboxorg/meshd/pkg/dids/didjwk"
)

// jwtHeader is the JOSE header used by the connect protocol
// (enbox-connect-protocol.ts signJwt): {alg, kid, typ} in this order.
type jwtHeader struct {
	ALG string `json:"alg"`
	KID string `json:"kid"`
	TYP string `json:"typ"`
}

// signJWT signs a JSON-serializable payload as a compact JWT with EdDSA,
// mirroring enbox-connect-protocol.ts signJwt. kid must be the signer DID's
// verification method id (e.g. "did:jwk:...#0").
func signJWT(payload any, kid string, priv ed25519.PrivateKey) (string, error) {
	headerJSON, err := json.Marshal(jwtHeader{ALG: "EdDSA", KID: kid, TYP: "JWT"})
	if err != nil {
		return "", fmt.Errorf("marshaling jwt header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling jwt payload: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := ed25519.Sign(priv, []byte(headerB64+"."+payloadB64))

	return headerB64 + "." + payloadB64 + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// verifyJWT verifies a compact EdDSA JWT whose kid header resolves via
// did:jwk, mirroring enbox-connect-protocol.ts verifyJwt. It returns the
// decoded payload bytes.
func verifyJWT(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt must have 3 segments, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding jwt header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parsing jwt header: %w", err)
	}
	if header.KID == "" {
		return nil, fmt.Errorf("jwt missing required %q header value", "kid")
	}
	if header.ALG != "EdDSA" {
		return nil, fmt.Errorf("unsupported jwt alg %q (expected EdDSA)", header.ALG)
	}

	didURI, _, _ := strings.Cut(header.KID, "#")
	result, err := (didjwk.Resolver{}).Resolve(didURI)
	if err != nil {
		return nil, fmt.Errorf("resolving jwt signer %q: %w", didURI, err)
	}

	var pub ed25519.PublicKey
	for _, vm := range result.Document.VerificationMethod {
		if vm.ID != header.KID || vm.PublicKeyJwk == nil {
			continue
		}
		if vm.PublicKeyJwk.KTY != "OKP" || vm.PublicKeyJwk.CRV != "Ed25519" {
			return nil, fmt.Errorf("jwt signer key %q is not an Ed25519 key", header.KID)
		}
		pubBytes, err := base64.RawURLEncoding.DecodeString(vm.PublicKeyJwk.X)
		if err != nil {
			return nil, fmt.Errorf("decoding jwt signer public key: %w", err)
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("jwt signer public key has invalid length %d", len(pubBytes))
		}
		pub = ed25519.PublicKey(pubBytes)
		break
	}
	if pub == nil {
		return nil, fmt.Errorf("public key %q not found in resolved DID document", header.KID)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding jwt signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, fmt.Errorf("jwt signature verification failed")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding jwt payload: %w", err)
	}
	return payload, nil
}
