package didcore

import (
	"testing"

	"github.com/enboxorg/meshd/pkg/jwk"
)

func TestAddVerificationMethod(t *testing.T) {
	doc := Document{ID: "did:example:123"}
	vm := VerificationMethod{
		ID:         "did:example:123#key-1",
		Type:       "JsonWebKey",
		Controller: "did:example:123",
		PublicKeyJwk: &jwk.JWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "test",
		},
	}

	doc.AddVerificationMethod(vm, Purposes(
		PurposeAssertion,
		PurposeAuthentication,
		PurposeKeyAgreement,
		PurposeCapabilityDelegation,
		PurposeCapabilityInvocation,
	))

	if len(doc.VerificationMethod) != 1 {
		t.Fatalf("expected 1 VM, got %d", len(doc.VerificationMethod))
	}
	if doc.VerificationMethod[0].ID != vm.ID {
		t.Errorf("VM ID mismatch")
	}

	// Check all purpose arrays
	checks := map[string][]string{
		"assertionMethod":      doc.AssertionMethod,
		"authentication":       doc.Authentication,
		"keyAgreement":         doc.KeyAgreement,
		"capabilityDelegation": doc.CapabilityDelegation,
		"capabilityInvocation": doc.CapabilityInvocation,
	}
	for purpose, ids := range checks {
		if len(ids) != 1 {
			t.Errorf("%s: expected 1 ID, got %d", purpose, len(ids))
			continue
		}
		if ids[0] != vm.ID {
			t.Errorf("%s[0] = %q, want %q", purpose, ids[0], vm.ID)
		}
	}
}

func TestAddVerificationMethod_NoPurposes(t *testing.T) {
	doc := Document{ID: "did:example:123"}
	vm := VerificationMethod{
		ID:         "did:example:123#key-1",
		Type:       "JsonWebKey",
		Controller: "did:example:123",
	}

	doc.AddVerificationMethod(vm)

	if len(doc.VerificationMethod) != 1 {
		t.Fatalf("expected 1 VM, got %d", len(doc.VerificationMethod))
	}
	if len(doc.AssertionMethod) != 0 {
		t.Error("assertionMethod should be empty")
	}
	if len(doc.Authentication) != 0 {
		t.Error("authentication should be empty")
	}
}

func TestSelectVerificationMethod(t *testing.T) {
	vm1 := VerificationMethod{ID: "did:example:123#key-1", Type: "JsonWebKey", Controller: "did:example:123"}
	vm2 := VerificationMethod{ID: "did:example:123#key-2", Type: "JsonWebKey", Controller: "did:example:123"}

	doc := Document{
		ID: "did:example:123",
	}
	doc.AddVerificationMethod(vm1, Purposes(PurposeAuthentication))
	doc.AddVerificationMethod(vm2, Purposes(PurposeAssertion))

	tests := map[string]struct {
		selector VMSelector
		wantID   string
		wantErr  bool
	}{
		"nil selector returns first": {
			selector: nil,
			wantID:   vm1.ID,
		},
		"by ID": {
			selector: ID("did:example:123#key-2"),
			wantID:   vm2.ID,
		},
		"by authentication purpose": {
			selector: PurposeAuthentication,
			wantID:   vm1.ID,
		},
		"by assertion purpose": {
			selector: PurposeAssertion,
			wantID:   vm2.ID,
		},
		"missing purpose": {
			selector: PurposeKeyAgreement,
			wantErr:  true,
		},
		"missing ID": {
			selector: ID("did:example:123#nonexistent"),
			wantErr:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			vm, err := doc.SelectVerificationMethod(tc.selector)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if vm.ID != tc.wantID {
				t.Errorf("ID = %q, want %q", vm.ID, tc.wantID)
			}
		})
	}
}

func TestSelectVerificationMethod_EmptyDocument(t *testing.T) {
	doc := Document{ID: "did:example:empty"}
	_, err := doc.SelectVerificationMethod(nil)
	if err == nil {
		t.Fatal("expected error for empty document")
	}
}

func TestAddService(t *testing.T) {
	doc := Document{ID: "did:example:123"}
	svc := Service{
		ID:              "did:example:123#dwn",
		Type:            "DecentralizedWebNode",
		ServiceEndpoint: []string{"https://dwn.example.com"},
	}
	doc.AddService(svc)

	if len(doc.Service) != 1 {
		t.Fatalf("expected 1 service, got %d", len(doc.Service))
	}
	if doc.Service[0].ID != svc.ID {
		t.Errorf("service ID = %q, want %q", doc.Service[0].ID, svc.ID)
	}
	if doc.Service[0].Type != "DecentralizedWebNode" {
		t.Errorf("service type = %q, want %q", doc.Service[0].Type, "DecentralizedWebNode")
	}
}

func TestGetAbsoluteResourceID(t *testing.T) {
	doc := Document{ID: "did:example:123"}

	tests := map[string]struct {
		input string
		want  string
	}{
		"relative": {
			input: "#key-1",
			want:  "did:example:123#key-1",
		},
		"absolute": {
			input: "did:example:123#key-1",
			want:  "did:example:123#key-1",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := doc.GetAbsoluteResourceID(tc.input)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
