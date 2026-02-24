// X25519 key support for JWK encoding/decoding.
// X25519 is used for key agreement (ECDH-ES+A256KW) and shares the OKP key type
// with Ed25519 but uses a different curve.
package eddsa

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/enboxorg/dwn-mesh/pkg/jwk"
)

const (
	X25519JWACurve    string = "X25519"
	X25519AlgorithmID string = X25519JWACurve
)

// X25519BytesToPublicKey deserializes the byte array into a jwk.JWK public key
// with CRV=X25519.
func X25519BytesToPublicKey(input []byte) (jwk.JWK, error) {
	if len(input) != 32 {
		return jwk.JWK{}, errors.New("invalid X25519 public key: must be 32 bytes")
	}

	return jwk.JWK{
		KTY: KeyType, // "OKP"
		CRV: X25519JWACurve,
		X:   base64.RawURLEncoding.EncodeToString(input),
	}, nil
}

// X25519PublicKeyToBytes serializes the given X25519 public key into a byte array.
func X25519PublicKeyToBytes(publicKey jwk.JWK) ([]byte, error) {
	if publicKey.X == "" {
		return nil, errors.New("x must be set")
	}

	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(publicKey.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}

	return publicKeyBytes, nil
}
