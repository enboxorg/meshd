package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/enboxorg/dwn-mesh/pkg/dids/didcore"
	"github.com/enboxorg/dwn-mesh/pkg/dids/didjwk"
	"github.com/enboxorg/dwn-mesh/pkg/jwk"
)

// mockResolver implements Resolver for testing.
type mockResolver struct {
	results map[string]didcore.ResolutionResult
	err     error
}

func (m *mockResolver) ResolveWithContext(_ context.Context, uri string) (didcore.ResolutionResult, error) {
	if m.err != nil {
		return didcore.ResolutionResult{}, m.err
	}
	result, ok := m.results[uri]
	if !ok {
		return didcore.ResolutionResultWithError("notFound"), didcore.ResolutionError{Code: "notFound"}
	}
	return result, nil
}

// countingResolver wraps a resolver and counts calls.
type countingResolver struct {
	inner Resolver
	count *int
}

func (r *countingResolver) ResolveWithContext(ctx context.Context, uri string) (didcore.ResolutionResult, error) {
	*r.count++
	return r.inner.ResolveWithContext(ctx, uri)
}

func makeTestDocument(didURI string, dwnEndpoints []string) didcore.Document {
	doc := didcore.Document{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      didURI,
	}

	vm := didcore.VerificationMethod{
		ID:         didURI + "#key-1",
		Type:       "JsonWebKey",
		Controller: didURI,
		PublicKeyJwk: &jwk.JWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
		},
	}
	doc.AddVerificationMethod(vm, didcore.Purposes(
		didcore.PurposeAuthentication,
		didcore.PurposeAssertion,
	))

	if len(dwnEndpoints) > 0 {
		doc.AddService(didcore.Service{
			ID:              didURI + "#dwn",
			Type:            ServiceTypeDWN,
			ServiceEndpoint: dwnEndpoints,
		})
	}

	return doc
}

func TestResolvePeerEndpoints(t *testing.T) {
	peerDID := "did:dht:abc123"
	dwnURL := "https://dwn.example.com"

	tests := map[string]struct {
		resolver    Resolver
		uri         string
		wantErr     bool
		errContains string
		check       func(t *testing.T, info *PeerEndpointInfo)
	}{
		"valid DID with DWN service": {
			resolver: &mockResolver{
				results: map[string]didcore.ResolutionResult{
					peerDID: didcore.ResolutionResultWithDocument(
						makeTestDocument(peerDID, []string{dwnURL}),
					),
				},
			},
			uri: peerDID,
			check: func(t *testing.T, info *PeerEndpointInfo) {
				if info.DID != peerDID {
					t.Errorf("DID = %q, want %q", info.DID, peerDID)
				}
				if len(info.DWNEndpoints) != 1 {
					t.Fatalf("DWNEndpoints len = %d, want 1", len(info.DWNEndpoints))
				}
				if info.DWNEndpoints[0] != dwnURL {
					t.Errorf("DWNEndpoints[0] = %q, want %q", info.DWNEndpoints[0], dwnURL)
				}
				if info.SigningKeyID != peerDID+"#key-1" {
					t.Errorf("SigningKeyID = %q, want %q", info.SigningKeyID, peerDID+"#key-1")
				}
				if info.Document.ID != peerDID {
					t.Errorf("Document.ID = %q, want %q", info.Document.ID, peerDID)
				}
			},
		},
		"valid DID without DWN service": {
			resolver: &mockResolver{
				results: map[string]didcore.ResolutionResult{
					peerDID: didcore.ResolutionResultWithDocument(
						makeTestDocument(peerDID, nil),
					),
				},
			},
			uri: peerDID,
			check: func(t *testing.T, info *PeerEndpointInfo) {
				if len(info.DWNEndpoints) != 0 {
					t.Errorf("expected no DWN endpoints, got %d", len(info.DWNEndpoints))
				}
			},
		},
		"multiple DWN endpoints": {
			resolver: &mockResolver{
				results: map[string]didcore.ResolutionResult{
					peerDID: didcore.ResolutionResultWithDocument(
						makeTestDocument(peerDID, []string{dwnURL, "https://backup.dwn.example.com"}),
					),
				},
			},
			uri: peerDID,
			check: func(t *testing.T, info *PeerEndpointInfo) {
				if len(info.DWNEndpoints) != 2 {
					t.Fatalf("expected 2 DWN endpoints, got %d", len(info.DWNEndpoints))
				}
			},
		},
		"invalid DID URI": {
			resolver: &mockResolver{},
			uri:      "not-a-did",
			wantErr:  true,
		},
		"resolver error": {
			resolver: &mockResolver{err: errors.New("network failure")},
			uri:      peerDID,
			wantErr:  true,
		},
		"resolution notFound error": {
			resolver: &mockResolver{
				results: map[string]didcore.ResolutionResult{},
			},
			uri:         peerDID,
			wantErr:     true,
			errContains: "notFound",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			info, err := ResolvePeerEndpoints(context.Background(), tc.resolver, tc.uri, nil)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, info)
			}
		})
	}
}

func TestResolvePeerDWNEndpoint(t *testing.T) {
	peerDID := "did:dht:abc123"
	dwnURL := "https://dwn.example.com"

	t.Run("returns first endpoint", func(t *testing.T) {
		resolver := &mockResolver{
			results: map[string]didcore.ResolutionResult{
				peerDID: didcore.ResolutionResultWithDocument(
					makeTestDocument(peerDID, []string{dwnURL, "https://backup.dwn.example.com"}),
				),
			},
		}

		url, err := ResolvePeerDWNEndpoint(context.Background(), resolver, peerDID, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if url != dwnURL {
			t.Errorf("got %q, want %q", url, dwnURL)
		}
	})

	t.Run("returns error when no DWN service", func(t *testing.T) {
		resolver := &mockResolver{
			results: map[string]didcore.ResolutionResult{
				peerDID: didcore.ResolutionResultWithDocument(
					makeTestDocument(peerDID, nil),
				),
			},
		}

		_, err := ResolvePeerDWNEndpoint(context.Background(), resolver, peerDID, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrNoDWNService) {
			t.Errorf("expected ErrNoDWNService, got %v", err)
		}
	})
}

func TestDWNClient_ResolvePeerDID(t *testing.T) {
	peerDID := "did:dht:peer123"
	dwnURL := "https://peer.dwn.example.com"

	t.Run("with resolver", func(t *testing.T) {
		resolver := &mockResolver{
			results: map[string]didcore.ResolutionResult{
				peerDID: didcore.ResolutionResultWithDocument(
					makeTestDocument(peerDID, []string{dwnURL}),
				),
			},
		}

		client := NewDWNClient(
			"https://anchor.dwn.example.com",
			"did:dht:anchor",
			"rec123",
			"did:dht:self",
			nil,
			WithResolver(resolver),
		)

		info, err := client.ResolvePeerDID(context.Background(), peerDID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info == nil {
			t.Fatal("expected info, got nil")
		}
		if info.DWNEndpoints[0] != dwnURL {
			t.Errorf("endpoint = %q, want %q", info.DWNEndpoints[0], dwnURL)
		}
	})

	t.Run("caches results", func(t *testing.T) {
		callCount := 0
		resolver := &countingResolver{
			inner: &mockResolver{
				results: map[string]didcore.ResolutionResult{
					peerDID: didcore.ResolutionResultWithDocument(
						makeTestDocument(peerDID, []string{dwnURL}),
					),
				},
			},
			count: &callCount,
		}

		client := NewDWNClient(
			"https://anchor.dwn.example.com",
			"did:dht:anchor",
			"rec123",
			"did:dht:self",
			nil,
			WithResolver(resolver),
		)

		// First call resolves
		_, err := client.ResolvePeerDID(context.Background(), peerDID)
		if err != nil {
			t.Fatalf("first resolve: %v", err)
		}

		// Second call should use cache
		_, err = client.ResolvePeerDID(context.Background(), peerDID)
		if err != nil {
			t.Fatalf("second resolve: %v", err)
		}

		if callCount != 1 {
			t.Errorf("resolver called %d times, want 1 (should cache)", callCount)
		}
	})

	t.Run("without resolver returns nil", func(t *testing.T) {
		client := NewDWNClient(
			"https://anchor.dwn.example.com",
			"did:dht:anchor",
			"rec123",
			"did:dht:self",
			nil,
		)

		info, err := client.ResolvePeerDID(context.Background(), peerDID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info != nil {
			t.Error("expected nil info when no resolver configured")
		}
	})
}

// TestResolvePeerEndpoints_WithRealDIDJWK tests using the actual did:jwk
// resolver (offline — no network needed).
func TestResolvePeerEndpoints_WithRealDIDJWK(t *testing.T) {
	key := jwk.JWK{
		KTY: "OKP",
		CRV: "Ed25519",
		X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
	}
	b, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	didJWK := "did:jwk:" + base64.RawURLEncoding.EncodeToString(b)

	// didjwk.Resolver implements MethodResolver, which has the same
	// ResolveWithContext signature as our Resolver interface.
	resolver := didjwk.Resolver{}

	info, err := ResolvePeerEndpoints(context.Background(), resolver, didJWK, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// did:jwk doesn't have DWN services — that's expected
	if len(info.DWNEndpoints) != 0 {
		t.Errorf("did:jwk should have no DWN endpoints, got %d", len(info.DWNEndpoints))
	}

	// But it should have a signing key from authentication
	if info.SigningKeyID == "" {
		t.Error("expected a signing key ID from did:jwk")
	}

	if info.Document.ID != didJWK {
		t.Errorf("Document.ID = %q, want %q", info.Document.ID, didJWK)
	}
}
