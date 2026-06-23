package invite

import (
	"strings"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	p := New(
		"https://dwn.example.com",
		"did:jwk:anchor",
		"bafy-network",
		"home",
		"bafy-token",
		"secret",
		"2026-06-23T00:00:00Z",
	)

	u, err := Encode(p)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !strings.HasPrefix(u, SchemePrefix) {
		t.Fatalf("invite URL %q missing prefix %q", u, SchemePrefix)
	}

	got, err := Decode(u)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != p {
		t.Fatalf("decoded payload mismatch\ngot:  %#v\nwant: %#v", got, p)
	}
}

func TestDecodeRawPayload(t *testing.T) {
	u, err := Encode(New("https://dwn.example.com", "did:jwk:anchor", "net", "", "tok", "sec", ""))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	raw := strings.TrimPrefix(u, SchemePrefix)

	if _, err := Decode(raw); err != nil {
		t.Fatalf("Decode(raw): %v", err)
	}
}

func TestValidateAllowsCoordinateOnlyInvite(t *testing.T) {
	p := New("https://dwn.example.com", "did:jwk:anchor", "net", "", "", "", "")
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidatePreAuthRequiresPreauthFields(t *testing.T) {
	p := New("https://dwn.example.com", "did:jwk:anchor", "net", "", "", "sec", "")
	if err := p.ValidatePreAuth(); err == nil {
		t.Fatal("expected missing token ID error")
	}
	p.TokenID = "tok"
	p.Secret = ""
	if err := p.ValidatePreAuth(); err == nil {
		t.Fatal("expected missing secret error")
	}
}

func TestGenerateSecret(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	b, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret second: %v", err)
	}
	if a == b {
		t.Fatal("two generated secrets matched")
	}
	if strings.ContainsAny(a, "+/=") {
		t.Fatalf("secret %q is not raw URL-safe base64", a)
	}
}

func TestProof(t *testing.T) {
	secret := "invite-secret"
	networkID := "net"
	nodeDID := "did:jwk:node"

	proof := Proof(secret, networkID, nodeDID)
	if !VerifyProof(secret, networkID, nodeDID, proof) {
		t.Fatal("proof did not verify")
	}
	if VerifyProof(secret, networkID, "did:jwk:other", proof) {
		t.Fatal("proof verified for wrong DID")
	}
	if VerifyProof("wrong", networkID, nodeDID, proof) {
		t.Fatal("proof verified for wrong secret")
	}
}
