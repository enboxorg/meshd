package didjwk

import (
	"encoding/base64"
	"encoding/json"
	"testing"

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
				if len(doc.VerificationMethod) != 1 {
					t.Fatalf("expected 1 verification method, got %d", len(doc.VerificationMethod))
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
				// VM ID should be URI + #0
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
				// Also check that the result has the error metadata
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
