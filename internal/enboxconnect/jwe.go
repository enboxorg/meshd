package enboxconnect

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/enboxorg/meshd/pkg/jwk"
)

// requestProtectedHeader is the request JWE protected header, constructed
// literally to guarantee the exact byte layout (key order) produced by
// JSON.stringify in enbox-connect-protocol.ts encryptRequest. It doubles as
// the AAD for the XChaCha20-Poly1305 seal.
const requestProtectedHeader = `{"alg":"dir","cty":"JWT","enc":"XC20P","typ":"JWT"}`

// sealRequestJWE encrypts the signed request JWT into a 5-part compact JWE
// (alg "dir", enc "XC20P") with a fresh 24-byte nonce, mirroring
// enbox-connect-protocol.ts encryptRequest. The AAD is the UTF-8 bytes of
// the protected header JSON exactly as constructed.
func sealRequestJWE(jwt string, encryptionKey []byte) (string, error) {
	aead, err := chacha20poly1305.NewX(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("creating XChaCha20-Poly1305: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	ciphertextAndTag := aead.Seal(nil, nonce, []byte(jwt), []byte(requestProtectedHeader))
	tagOffset := len(ciphertextAndTag) - aead.Overhead()

	segments := []string{
		base64.RawURLEncoding.EncodeToString([]byte(requestProtectedHeader)),
		"", // No wrapped key (direct encryption).
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString(ciphertextAndTag[:tagOffset]),
		base64.RawURLEncoding.EncodeToString(ciphertextAndTag[tagOffset:]),
	}
	return strings.Join(segments, "."), nil
}

// decryptResponseJWE decrypts the wallet's connect response JWE using ECDH
// (client X25519 private key against the header's ephemeral Ed25519 "epk",
// converted to X25519) plus the user-entered PIN as AAD, mirroring
// enbox-connect-protocol.ts decryptResponse.
//
// The AAD is the RAW decoded protected-header bytes from the JWE with
// `,"pin":"<pin>"` spliced immediately before the final '}' — the byte-exact
// equivalent of the SDK's JSON.stringify({...header, pin}), which appends
// the pin as the last key while preserving the wire key order. An empty pin
// leaves the AAD as the bare header (the SDK's local, PIN-less flow).
func decryptResponseJWE(jweCompact string, clientX25519Priv []byte, pin string) ([]byte, error) {
	parts := strings.Split(jweCompact, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("jwe must have 5 segments, got %d", len(parts))
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding jwe protected header: %w", err)
	}

	var header struct {
		EPK *jwk.JWK `json:"epk"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, fmt.Errorf("parsing jwe protected header: %w", err)
	}
	if header.EPK == nil {
		return nil, fmt.Errorf("jwe protected header is missing required %q property", "epk")
	}
	if header.EPK.KTY != "OKP" || header.EPK.CRV != "Ed25519" {
		return nil, fmt.Errorf("jwe epk must be an Ed25519 key, got kty=%s crv=%s", header.EPK.KTY, header.EPK.CRV)
	}

	epkPub, err := base64.RawURLEncoding.DecodeString(header.EPK.X)
	if err != nil {
		return nil, fmt.Errorf("decoding jwe epk public key: %w", err)
	}
	if len(epkPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("jwe epk public key has invalid length %d", len(epkPub))
	}

	sharedKey, err := deriveResponseSharedKey(clientX25519Priv, ed25519.PublicKey(epkPub))
	if err != nil {
		return nil, err
	}

	aad, err := spliceHeaderPIN(headerRaw, pin)
	if err != nil {
		return nil, err
	}

	nonce, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding jwe nonce: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("decoding jwe ciphertext: %w", err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("decoding jwe authentication tag: %w", err)
	}

	aead, err := chacha20poly1305.NewX(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("creating XChaCha20-Poly1305: %w", err)
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("jwe nonce has invalid length %d", len(nonce))
	}

	plaintext, err := aead.Open(nil, nonce, append(ciphertext, tag...), aad)
	if err != nil {
		return nil, fmt.Errorf("decrypting connect response (wrong PIN or corrupted response): %w", err)
	}
	return plaintext, nil
}

// spliceHeaderPIN inserts `,"pin":"<pin>"` before the final '}' of the raw
// protected-header JSON. The splice operates on the exact wire bytes rather
// than a re-marshal so the AAD matches the SDK byte-for-byte regardless of
// Go's JSON key ordering.
func spliceHeaderPIN(headerRaw []byte, pin string) ([]byte, error) {
	if pin == "" {
		return headerRaw, nil
	}
	if len(headerRaw) == 0 || headerRaw[len(headerRaw)-1] != '}' {
		return nil, fmt.Errorf("jwe protected header is not a JSON object")
	}
	pinJSON, err := jsonStringifyString(pin)
	if err != nil {
		return nil, fmt.Errorf("encoding pin: %w", err)
	}

	aad := make([]byte, 0, len(headerRaw)+len(pinJSON)+8)
	aad = append(aad, headerRaw[:len(headerRaw)-1]...)
	aad = append(aad, `,"pin":`...)
	aad = append(aad, pinJSON...)
	aad = append(aad, '}')
	return aad, nil
}

// jsonStringifyString serializes a string the way JSON.stringify does:
// unlike json.Marshal, it must not HTML-escape '<', '>', or '&', because
// the result feeds the AAD and has to match the SDK byte-for-byte.
func jsonStringifyString(s string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// deriveResponseSharedKey derives the 32-byte response encryption key:
// X25519 ECDH between our X25519 private key and the peer's Ed25519 public
// key (converted via the birational map), expanded with HKDF-SHA256 using
// an empty salt and empty info, mirroring enbox-connect-protocol.ts
// deriveSharedKeyFromJwk. ECDH is symmetric, so the same function serves
// both the client (decrypt) and wallet (encrypt) directions.
func deriveResponseSharedKey(x25519Priv []byte, peerEd25519Pub ed25519.PublicKey) ([]byte, error) {
	peerX25519Pub, err := ed25519PubToX25519(peerEd25519Pub)
	if err != nil {
		return nil, err
	}

	shared, err := curve25519.X25519(x25519Priv, peerX25519Pub)
	if err != nil {
		return nil, fmt.Errorf("x25519 key agreement: %w", err)
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, nil), key); err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return key, nil
}

// ed25519PubToX25519 converts an Ed25519 public key to an X25519 public key
// using the birational map (Edwards -> Montgomery). This mirrors the
// unexported helper of the same name in pkg/dids/didjwk, kept local so this
// package stays a pure protocol client.
func ed25519PubToX25519(pub ed25519.PublicKey) ([]byte, error) {
	edPoint, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("parsing ed25519 public key: %w", err)
	}
	return edPoint.BytesMontgomery(), nil
}
