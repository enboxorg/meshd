package dids

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/enboxorg/dwn-mesh/pkg/dids/didcore"
	"github.com/enboxorg/dwn-mesh/pkg/jwk"
)

func makeTestJWKURI(t *testing.T) string {
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

func TestResolve_DIDJWK(t *testing.T) {
	uri := makeTestJWKURI(t)
	result, err := Resolve(uri)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if result.Document.ID == "" {
		t.Fatal("document ID is empty")
	}
	if len(result.Document.VerificationMethod) == 0 {
		t.Fatal("no verification methods")
	}
}

func TestResolveWithContext_DIDJWK(t *testing.T) {
	uri := makeTestJWKURI(t)
	result, err := ResolveWithContext(context.Background(), uri)
	if err != nil {
		t.Fatalf("ResolveWithContext: %v", err)
	}

	if result.Document.ID == "" {
		t.Fatal("document ID is empty")
	}
}

func TestResolve_UnsupportedMethod(t *testing.T) {
	_, err := Resolve("did:unsupported:abc123")
	if err == nil {
		t.Fatal("expected error for unsupported method")
	}
	resErr, ok := err.(didcore.ResolutionError)
	if !ok {
		t.Fatalf("expected ResolutionError, got %T: %v", err, err)
	}
	if resErr.Code != "methodNotSupported" {
		t.Errorf("error code = %q, want %q", resErr.Code, "methodNotSupported")
	}
}

func TestResolve_InvalidDID(t *testing.T) {
	_, err := Resolve("not-a-did")
	if err == nil {
		t.Fatal("expected error for invalid DID")
	}
	resErr, ok := err.(didcore.ResolutionError)
	if !ok {
		t.Fatalf("expected ResolutionError, got %T: %v", err, err)
	}
	if resErr.Code != "invalidDid" {
		t.Errorf("error code = %q, want %q", resErr.Code, "invalidDid")
	}
}

func TestResolve_MethodDispatch(t *testing.T) {
	// Verify that the resolver dispatches to the correct method resolver.
	// did:jwk should work offline, did:web and did:dht will fail with network errors
	// but should NOT return "methodNotSupported".

	t.Run("did:jwk dispatches correctly", func(t *testing.T) {
		uri := makeTestJWKURI(t)
		result, err := Resolve(uri)
		if err != nil {
			t.Fatalf("did:jwk should resolve offline: %v", err)
		}
		if result.Document.ID != uri {
			t.Errorf("document ID = %q, want %q", result.Document.ID, uri)
		}
	})

	t.Run("did:dht does not return methodNotSupported", func(t *testing.T) {
		// This will fail with a network error, not methodNotSupported
		_, err := Resolve("did:dht:fakeid12345")
		if err == nil {
			// It might actually resolve if the gateway is reachable, that's fine
			return
		}
		resErr, ok := err.(didcore.ResolutionError)
		if ok && resErr.Code == "methodNotSupported" {
			t.Error("did:dht should not return methodNotSupported")
		}
	})

	t.Run("did:web does not return methodNotSupported", func(t *testing.T) {
		// This will fail with a network error, not methodNotSupported
		_, err := Resolve("did:web:nonexistent.invalid.test")
		if err == nil {
			return
		}
		resErr, ok := err.(didcore.ResolutionError)
		if ok && resErr.Code == "methodNotSupported" {
			t.Error("did:web should not return methodNotSupported")
		}
	})
}
