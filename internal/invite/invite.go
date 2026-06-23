// Package invite encodes meshd network invite URLs.
package invite

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// SchemePrefix is the canonical URL prefix for meshd network invites.
	SchemePrefix = "meshd://invite/"

	currentVersion = 1
	secretBytes    = 32
)

// Payload is the data carried by a meshd invite URL.
type Payload struct {
	Version     int    `json:"version"`
	Endpoint    string `json:"endpoint"`
	AnchorDID   string `json:"anchorDid"`
	NetworkID   string `json:"networkId"`
	NetworkName string `json:"networkName,omitempty"`
	TokenID     string `json:"tokenId,omitempty"`
	Secret      string `json:"secret,omitempty"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
}

// New constructs a normalized invite payload.
func New(endpoint, anchorDID, networkID, networkName, tokenID, secret, expiresAt string) Payload {
	return Payload{
		Version:     currentVersion,
		Endpoint:    strings.TrimSpace(endpoint),
		AnchorDID:   strings.TrimSpace(anchorDID),
		NetworkID:   strings.TrimSpace(networkID),
		NetworkName: strings.TrimSpace(networkName),
		TokenID:     strings.TrimSpace(tokenID),
		Secret:      strings.TrimSpace(secret),
		ExpiresAt:   strings.TrimSpace(expiresAt),
	}
}

// Encode serializes a payload as a meshd://invite URL.
func Encode(p Payload) (string, error) {
	if p.Version == 0 {
		p.Version = currentVersion
	}
	if err := p.Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal invite: %w", err)
	}
	return SchemePrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// Decode parses a meshd://invite URL or the raw base64url payload.
func Decode(s string) (Payload, error) {
	raw := strings.TrimSpace(s)
	if strings.HasPrefix(raw, SchemePrefix) {
		raw = strings.TrimPrefix(raw, SchemePrefix)
	}
	if raw == "" {
		return Payload{}, fmt.Errorf("empty invite")
	}

	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return Payload{}, fmt.Errorf("decode invite payload: %w", err)
	}

	var p Payload
	if err := json.Unmarshal(data, &p); err != nil {
		return Payload{}, fmt.Errorf("parse invite payload: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Payload{}, err
	}
	return p, nil
}

// Validate checks that a payload has the fields needed to join a network.
func (p Payload) Validate() error {
	if p.Version != currentVersion {
		return fmt.Errorf("unsupported invite version %d", p.Version)
	}
	if p.Endpoint == "" {
		return fmt.Errorf("invite missing endpoint")
	}
	if p.AnchorDID == "" {
		return fmt.Errorf("invite missing anchor DID")
	}
	if p.NetworkID == "" {
		return fmt.Errorf("invite missing network ID")
	}
	return nil
}

// ValidatePreAuth checks that a payload has the token fields needed to submit a
// self-service preauth join request.
func (p Payload) ValidatePreAuth() error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.TokenID == "" {
		return fmt.Errorf("invite missing token ID")
	}
	if p.Secret == "" {
		return fmt.Errorf("invite missing secret")
	}
	return nil
}

// GenerateSecret returns a new URL-safe random invite secret.
func GenerateSecret() (string, error) {
	var b [secretBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate invite secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Proof creates a non-secret preauth proof for a joining node.
func Proof(secret, networkID, nodeDID string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(networkID))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(nodeDID))
	return "hmac-sha256:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyProof checks a preauth proof without leaking timing information.
func VerifyProof(secret, networkID, nodeDID, proof string) bool {
	expected := Proof(secret, networkID, nodeDID)
	return hmac.Equal([]byte(expected), []byte(proof))
}
