package didjwk

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/enboxorg/meshd/pkg/dids/didcore"
	"github.com/enboxorg/meshd/pkg/jwk"
)

// makeEd25519JWK creates a known Ed25519 did:jwk URI for testing.
func makeEd25519JWK(t *testing.T) string {
	t.Helper()
	key := jwk.JWK{
		KTY: "OKP",
		CRV: "Ed25519",
		X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
	}
	b, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	return "did:jwk:" + base64.RawURLEncoding.EncodeToString(b)
}

// -----------------------------------------------------------------------
// Resolve tests (existing + enhanced)
// -----------------------------------------------------------------------

func TestResolve(t *testing.T) {
	tests := map[string]struct {
		uri     string
		wantErr string
		check   func(t *testing.T, result didcore.ResolutionResult)
	}{
		"valid Ed25519": {
			uri: makeEd25519JWK(t),
			check: func(t *testing.T, result didcore.ResolutionResult) {
				doc := result.Document
				if doc.ID == "" {
					t.Fatal("document ID is empty")
				}
				// Should have 2 VMs: #0 (Ed25519) and #1 (X25519).
				if len(doc.VerificationMethod) != 2 {
					t.Fatalf("expected 2 verification methods, got %d", len(doc.VerificationMethod))
				}
				vm := doc.VerificationMethod[0]
				if vm.Type != "JsonWebKey" {
					t.Errorf("VM type = %q, want %q", vm.Type, "JsonWebKey")
				}
				if vm.PublicKeyJwk == nil {
					t.Fatal("PublicKeyJwk is nil")
				}
				if vm.PublicKeyJwk.CRV != "Ed25519" {
					t.Errorf("CRV = %q, want %q", vm.PublicKeyJwk.CRV, "Ed25519")
				}
				if vm.Controller != doc.ID {
					t.Errorf("controller = %q, want %q", vm.Controller, doc.ID)
				}
				if vm.ID != doc.ID+"#0" {
					t.Errorf("VM ID = %q, want %q", vm.ID, doc.ID+"#0")
				}
			},
		},
		"purposes are set": {
			uri: makeEd25519JWK(t),
			check: func(t *testing.T, result didcore.ResolutionResult) {
				doc := result.Document
				if len(doc.AssertionMethod) == 0 {
					t.Error("assertionMethod is empty")
				}
				if len(doc.Authentication) == 0 {
					t.Error("authentication is empty")
				}
				if len(doc.CapabilityInvocation) == 0 {
					t.Error("capabilityInvocation is empty")
				}
				if len(doc.CapabilityDelegation) == 0 {
					t.Error("capabilityDelegation is empty")
				}
			},
		},
		"context is set": {
			uri: makeEd25519JWK(t),
			check: func(t *testing.T, result didcore.ResolutionResult) {
				if len(result.Document.Context) == 0 {
					t.Error("context is empty")
				}
				if result.Document.Context[0] != "https://www.w3.org/ns/did/v1" {
					t.Errorf("context[0] = %q, want DID v1", result.Document.Context[0])
				}
			},
		},
		"wrong method": {
			uri:     "did:web:example.com",
			wantErr: "invalidDid",
		},
		"invalid DID": {
			uri:     "not-a-did",
			wantErr: "invalidDid",
		},
		"invalid base64 in ID": {
			uri:     "did:jwk:!!!invalid!!!",
			wantErr: "invalidDid",
		},
		"valid base64 but not JSON": {
			uri:     "did:jwk:" + base64.RawURLEncoding.EncodeToString([]byte("not json")),
			wantErr: "invalidDid",
		},
	}

	r := Resolver{}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := r.Resolve(tc.uri)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				resErr, ok := err.(didcore.ResolutionError)
				if !ok {
					t.Fatalf("expected ResolutionError, got %T: %v", err, err)
				}
				if resErr.Code != tc.wantErr {
					t.Errorf("error code = %q, want %q", resErr.Code, tc.wantErr)
				}
				if result.ResolutionMetadata.Error != tc.wantErr {
					t.Errorf("metadata error = %q, want %q", result.ResolutionMetadata.Error, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, result)
			}
		})
	}
}

func TestResolve_Deterministic(t *testing.T) {
	r := Resolver{}
	uri := makeEd25519JWK(t)

	r1, err := r.Resolve(uri)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	r2, err := r.Resolve(uri)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}

	if r1.Document.ID != r2.Document.ID {
		t.Error("resolve is not deterministic: different document IDs")
	}
	if r1.Document.VerificationMethod[0].ID != r2.Document.VerificationMethod[0].ID {
		t.Error("resolve is not deterministic: different VM IDs")
	}
}

// -----------------------------------------------------------------------
// Resolve — X25519 key agreement enhancement
// -----------------------------------------------------------------------

func TestResolve_Ed25519_HasKeyAgreement(t *testing.T) {
	r := Resolver{}
	uri := makeEd25519JWK(t)

	result, err := r.Resolve(uri)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	doc := result.Document

	// Must have 2 VMs.
	if len(doc.VerificationMethod) != 2 {
		t.Fatalf("expected 2 verification methods, got %d", len(doc.VerificationMethod))
	}

	// #1 should be X25519 key agreement.
	kaVM := doc.VerificationMethod[1]
	if kaVM.ID != doc.ID+"#1" {
		t.Errorf("key agreement VM ID = %q, want %q", kaVM.ID, doc.ID+"#1")
	}
	if kaVM.Type != "JsonWebKey" {
		t.Errorf("key agreement VM type = %q, want %q", kaVM.Type, "JsonWebKey")
	}
	if kaVM.PublicKeyJwk == nil {
		t.Fatal("key agreement PublicKeyJwk is nil")
	}
	if kaVM.PublicKeyJwk.KTY != "OKP" {
		t.Errorf("key agreement KTY = %q, want %q", kaVM.PublicKeyJwk.KTY, "OKP")
	}
	if kaVM.PublicKeyJwk.CRV != "X25519" {
		t.Errorf("key agreement CRV = %q, want %q", kaVM.PublicKeyJwk.CRV, "X25519")
	}

	// keyAgreement purpose list should reference #1.
	if len(doc.KeyAgreement) == 0 {
		t.Fatal("keyAgreement purpose list is empty")
	}
	if doc.KeyAgreement[0] != doc.ID+"#1" {
		t.Errorf("keyAgreement[0] = %q, want %q", doc.KeyAgreement[0], doc.ID+"#1")
	}

	// The X25519 public key should decode to 32 bytes.
	x25519Bytes, err := base64.RawURLEncoding.DecodeString(kaVM.PublicKeyJwk.X)
	if err != nil {
		t.Fatalf("decoding X25519 key: %v", err)
	}
	if len(x25519Bytes) != 32 {
		t.Errorf("X25519 key length = %d, want 32", len(x25519Bytes))
	}
}

func TestResolve_SelectKeyAgreement(t *testing.T) {
	r := Resolver{}
	uri := makeEd25519JWK(t)

	result, err := r.Resolve(uri)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Should be able to select key agreement VM.
	vm, err := result.Document.SelectVerificationMethod(didcore.PurposeKeyAgreement)
	if err != nil {
		t.Fatalf("selecting key agreement VM: %v", err)
	}
	if vm.PublicKeyJwk == nil || vm.PublicKeyJwk.CRV != "X25519" {
		t.Error("selected VM is not X25519")
	}
}

// -----------------------------------------------------------------------
// Create tests
// -----------------------------------------------------------------------

func TestCreate(t *testing.T) {
	id, err := Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// URI should start with did:jwk:
	if !strings.HasPrefix(id.URI, "did:jwk:") {
		t.Errorf("URI = %q, want prefix did:jwk:", id.URI)
	}

	// Key lengths.
	if len(id.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("private key length = %d, want %d", len(id.PrivateKey), ed25519.PrivateKeySize)
	}
	if len(id.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(id.PublicKey), ed25519.PublicKeySize)
	}
	if len(id.X25519PrivateKey) != 32 {
		t.Errorf("x25519 private key length = %d, want 32", len(id.X25519PrivateKey))
	}
	if len(id.X25519PublicKey) != 32 {
		t.Errorf("x25519 public key length = %d, want 32", len(id.X25519PublicKey))
	}

	// Ed25519 signing round-trip.
	msg := []byte("test message")
	sig := ed25519.Sign(id.PrivateKey, msg)
	if !ed25519.Verify(id.PublicKey, msg, sig) {
		t.Error("ed25519 sign/verify failed")
	}

	// X25519 key pair consistency: derive pub from priv, compare.
	derivedPub, err := curve25519.X25519(id.X25519PrivateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("x25519 scalar mult: %v", err)
	}
	if !equal(derivedPub, id.X25519PublicKey) {
		t.Error("x25519 public key does not match derivation from private key")
	}
}

func TestCreate_Unique(t *testing.T) {
	id1, err := Create()
	if err != nil {
		t.Fatalf("Create 1: %v", err)
	}
	id2, err := Create()
	if err != nil {
		t.Fatalf("Create 2: %v", err)
	}

	if id1.URI == id2.URI {
		t.Error("two Create() calls produced the same URI")
	}
	if equal(id1.PrivateKey, id2.PrivateKey) {
		t.Error("two Create() calls produced the same private key")
	}
}

// -----------------------------------------------------------------------
// FromPrivateKey tests
// -----------------------------------------------------------------------

func TestFromPrivateKey(t *testing.T) {
	// Create, then reconstruct from private key — should be identical.
	original, err := Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	reconstructed, err := FromPrivateKey(original.PrivateKey, nil)
	if err != nil {
		t.Fatalf("FromPrivateKey: %v", err)
	}

	if original.URI != reconstructed.URI {
		t.Errorf("URI mismatch:\n  original:      %s\n  reconstructed: %s", original.URI, reconstructed.URI)
	}
	if !equal(original.PublicKey, reconstructed.PublicKey) {
		t.Error("public key mismatch")
	}
	if !equal(original.X25519PublicKey, reconstructed.X25519PublicKey) {
		t.Error("x25519 public key mismatch")
	}
	if !equal(original.X25519PrivateKey, reconstructed.X25519PrivateKey) {
		t.Error("x25519 private key mismatch")
	}
}

func TestFromPrivateKey_WithExplicitPublicKey(t *testing.T) {
	original, err := Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	reconstructed, err := FromPrivateKey(original.PrivateKey, original.PublicKey)
	if err != nil {
		t.Fatalf("FromPrivateKey: %v", err)
	}

	if original.URI != reconstructed.URI {
		t.Error("URI mismatch when providing explicit public key")
	}
}

func TestFromPrivateKey_InvalidLength(t *testing.T) {
	_, err := FromPrivateKey([]byte("too short"), nil)
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

// -----------------------------------------------------------------------
// DeriveX25519PublicKey tests
// -----------------------------------------------------------------------

func TestDeriveX25519PublicKey(t *testing.T) {
	id, err := Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Derive from the URI only (no private key material).
	x25519Pub, err := DeriveX25519PublicKey(id.URI)
	if err != nil {
		t.Fatalf("DeriveX25519PublicKey: %v", err)
	}

	if !equal(x25519Pub, id.X25519PublicKey) {
		t.Error("derived X25519 public key does not match identity's X25519 public key")
	}
}

func TestDeriveX25519PublicKey_MatchesWireGuard(t *testing.T) {
	// The X25519 public key derived from a did:jwk should be usable as a
	// WireGuard public key: verify by deriving pub from priv and comparing.
	id, err := Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	wgPub, err := curve25519.X25519(id.X25519PrivateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519.X25519: %v", err)
	}

	peerDerived, err := DeriveX25519PublicKey(id.URI)
	if err != nil {
		t.Fatalf("DeriveX25519PublicKey: %v", err)
	}

	if !equal(wgPub, peerDerived) {
		t.Error("peer-derived X25519 pubkey does not match WireGuard pubkey from private key")
	}
}

func TestDeriveX25519PublicKey_Errors(t *testing.T) {
	tests := map[string]string{
		"not a DID":     "not-a-did",
		"wrong method":  "did:web:example.com",
		"invalid base64": "did:jwk:!!!invalid!!!",
		"not JSON":      "did:jwk:" + base64.RawURLEncoding.EncodeToString([]byte("nope")),
		"wrong curve": func() string {
			k := jwk.JWK{KTY: "EC", CRV: "P-256", X: "dGVzdA"}
			b, _ := json.Marshal(k)
			return "did:jwk:" + base64.RawURLEncoding.EncodeToString(b)
		}(),
	}

	for name, uri := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := DeriveX25519PublicKey(uri)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// -----------------------------------------------------------------------
// Round-trip: Create → Resolve → DeriveX25519 → verify
// -----------------------------------------------------------------------

func TestRoundTrip_Create_Resolve_Derive(t *testing.T) {
	id, err := Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Resolve the created URI.
	r := Resolver{}
	result, err := r.Resolve(id.URI)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	doc := result.Document

	// Document ID should match the URI.
	if doc.ID != id.URI {
		t.Errorf("document ID = %q, want %q", doc.ID, id.URI)
	}

	// The Ed25519 public key from the document should match.
	vm0 := doc.VerificationMethod[0]
	if vm0.PublicKeyJwk.CRV != "Ed25519" {
		t.Fatalf("VM #0 CRV = %q, want Ed25519", vm0.PublicKeyJwk.CRV)
	}
	ed25519PubFromDoc, err := base64.RawURLEncoding.DecodeString(vm0.PublicKeyJwk.X)
	if err != nil {
		t.Fatalf("decoding ed25519 key from doc: %v", err)
	}
	if !equal(ed25519PubFromDoc, id.PublicKey) {
		t.Error("ed25519 public key from doc does not match identity")
	}

	// The X25519 public key from the document should match.
	vm1 := doc.VerificationMethod[1]
	if vm1.PublicKeyJwk.CRV != "X25519" {
		t.Fatalf("VM #1 CRV = %q, want X25519", vm1.PublicKeyJwk.CRV)
	}
	x25519PubFromDoc, err := base64.RawURLEncoding.DecodeString(vm1.PublicKeyJwk.X)
	if err != nil {
		t.Fatalf("decoding x25519 key from doc: %v", err)
	}
	if !equal(x25519PubFromDoc, id.X25519PublicKey) {
		t.Error("x25519 public key from doc does not match identity")
	}

	// DeriveX25519PublicKey should also match.
	derived, err := DeriveX25519PublicKey(id.URI)
	if err != nil {
		t.Fatalf("DeriveX25519PublicKey: %v", err)
	}
	if !equal(derived, id.X25519PublicKey) {
		t.Error("DeriveX25519PublicKey result does not match identity")
	}

	// And it should match WireGuard derivation from private key.
	wgPub, err := curve25519.X25519(id.X25519PrivateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519.X25519: %v", err)
	}
	if !equal(wgPub, derived) {
		t.Error("WireGuard pubkey from private does not match peer-derived pubkey")
	}
}

// -----------------------------------------------------------------------
// X25519 key exchange test — proves the derived keys actually work
// -----------------------------------------------------------------------

func TestX25519KeyExchange(t *testing.T) {
	// Create two identities and verify they can perform a Diffie-Hellman
	// key exchange using their X25519 keys.
	alice, err := Create()
	if err != nil {
		t.Fatalf("Create alice: %v", err)
	}
	bob, err := Create()
	if err != nil {
		t.Fatalf("Create bob: %v", err)
	}

	// Alice computes shared secret using her private key and Bob's public key.
	sharedAlice, err := curve25519.X25519(alice.X25519PrivateKey, bob.X25519PublicKey)
	if err != nil {
		t.Fatalf("alice DH: %v", err)
	}

	// Bob computes shared secret using his private key and Alice's public key.
	sharedBob, err := curve25519.X25519(bob.X25519PrivateKey, alice.X25519PublicKey)
	if err != nil {
		t.Fatalf("bob DH: %v", err)
	}

	if !equal(sharedAlice, sharedBob) {
		t.Error("DH shared secrets do not match")
	}

	// Also test with peer-derived public keys (from URI only).
	alicePubFromURI, err := DeriveX25519PublicKey(alice.URI)
	if err != nil {
		t.Fatalf("derive alice pub: %v", err)
	}
	bobPubFromURI, err := DeriveX25519PublicKey(bob.URI)
	if err != nil {
		t.Fatalf("derive bob pub: %v", err)
	}

	// Bob computes shared secret using alice's URI-derived public key.
	sharedBob2, err := curve25519.X25519(bob.X25519PrivateKey, alicePubFromURI)
	if err != nil {
		t.Fatalf("bob DH with URI key: %v", err)
	}
	if !equal(sharedBob2, sharedAlice) {
		t.Error("DH with URI-derived key does not match")
	}

	// Alice computes shared secret using bob's URI-derived public key.
	sharedAlice2, err := curve25519.X25519(alice.X25519PrivateKey, bobPubFromURI)
	if err != nil {
		t.Fatalf("alice DH with URI key: %v", err)
	}
	if !equal(sharedAlice2, sharedBob) {
		t.Error("DH with URI-derived key does not match (alice side)")
	}
}

// equal is a helper to compare byte slices.
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
