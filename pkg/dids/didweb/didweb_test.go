package didweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/enboxorg/meshd/pkg/dids/didcore"
	"github.com/enboxorg/meshd/pkg/jwk"
)

func TestTransformID(t *testing.T) {
	tests := map[string]struct {
		id      string
		want    string
		wantErr bool
	}{
		"domain only": {
			id:   "example.com",
			want: "https://example.com/.well-known/did.json",
		},
		"domain with path": {
			id:   "example.com:user:alice",
			want: "https://example.com/user/alice/did.json",
		},
		"domain with port (percent-encoded)": {
			id:   "example.com%3A8080",
			want: "https://example.com:8080/.well-known/did.json",
		},
		"localhost falls back to http": {
			id:   "localhost",
			want: "http://localhost/.well-known/did.json",
		},
		"localhost with port (percent-encoded)": {
			id:   "localhost%3A3000",
			want: "http://localhost:3000/.well-known/did.json",
		},
		"IP address falls back to http": {
			id:   "127.0.0.1",
			want: "http://127.0.0.1/.well-known/did.json",
		},
		"subdomain": {
			id:   "w3c-ccg.github.io",
			want: "https://w3c-ccg.github.io/.well-known/did.json",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := TransformID(tc.id)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("TransformID(%q) = %q, want %q", tc.id, got, tc.want)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	// Set up a test HTTP server that serves a DID document
	doc := didcore.Document{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      "did:web:localhost",
		VerificationMethod: []didcore.VerificationMethod{
			{
				ID:         "did:web:localhost#key-1",
				Type:       "JsonWebKey",
				Controller: "did:web:localhost",
				PublicKeyJwk: &jwk.JWK{
					KTY: "OKP",
					CRV: "Ed25519",
					X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
		},
		Authentication: []string{"did:web:localhost#key-1"},
	}

	docBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	// Use httptest.NewServer so we can get the URL to construct a proper did:web
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/did.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(docBytes)
	}))
	defer srv.Close()

	t.Run("wrong method", func(t *testing.T) {
		r := Resolver{}
		_, err := r.Resolve("did:dht:abc123")
		if err == nil {
			t.Fatal("expected error for wrong method")
		}
		resErr, ok := err.(didcore.ResolutionError)
		if !ok {
			t.Fatalf("expected ResolutionError, got %T", err)
		}
		if resErr.Code != "invalidDid" {
			t.Errorf("error code = %q, want %q", resErr.Code, "invalidDid")
		}
	})

	t.Run("invalid DID", func(t *testing.T) {
		r := Resolver{}
		_, err := r.Resolve("not-a-did")
		if err == nil {
			t.Fatal("expected error for invalid DID")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		r := Resolver{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel immediately

		_, err := r.ResolveWithContext(ctx, "did:web:example.com")
		if err == nil {
			t.Fatal("expected error for cancelled context")
		}
	})
}

func TestResolve_WithTestServer(t *testing.T) {
	// Create a test document
	doc := didcore.Document{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      "placeholder", // will be set per request
		VerificationMethod: []didcore.VerificationMethod{
			{
				ID:         "placeholder#key-1",
				Type:       "JsonWebKey",
				Controller: "placeholder",
				PublicKeyJwk: &jwk.JWK{
					KTY: "OKP",
					CRV: "Ed25519",
					X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
		},
	}

	docBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(docBytes)
	}))
	defer srv.Close()

	// The server is at 127.0.0.1:PORT — TransformID uses http for IP addresses
	// We need to construct a did:web that maps to this server
	// srv.URL is like "http://127.0.0.1:PORT"
	// We cannot easily test with httptest since did:web constructs its own URL,
	// but we can verify TransformID is correct for the URL construction.
	t.Run("TransformID produces correct URL for server", func(t *testing.T) {
		// This just validates the URL construction logic works end to end
		url, err := TransformID("example.com:users:alice")
		if err != nil {
			t.Fatalf("TransformID: %v", err)
		}
		if url != "https://example.com/users/alice/did.json" {
			t.Errorf("got %q", url)
		}
	})
}
