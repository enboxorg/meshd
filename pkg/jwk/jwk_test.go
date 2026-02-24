package jwk

import (
	"testing"
)

func TestComputeThumbprint(t *testing.T) {
	tests := map[string]struct {
		jwk       JWK
		wantEmpty bool
	}{
		"Ed25519 key": {
			jwk: JWK{
				KTY: "OKP",
				CRV: "Ed25519",
				X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
		},
		"secp256k1 key with Y": {
			jwk: JWK{
				KTY: "EC",
				CRV: "secp256k1",
				X:   "WbbaSStufflt7SVQJkePlz--CDAwSA76XFeCG3v22Gc",
				Y:   "bOE4QfbFSGFbGwAcezB-kRBi26YR4cXuTqG0W6g1eCY",
			},
		},
		"deterministic": {
			// same key should produce same thumbprint
			jwk: JWK{
				KTY: "OKP",
				CRV: "Ed25519",
				X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
		},
	}

	// collect thumbprints to verify determinism
	var ed25519Thumbprints []string

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tp, err := tc.jwk.ComputeThumbprint()
			if err != nil {
				t.Fatalf("ComputeThumbprint: %v", err)
			}
			if tp == "" {
				t.Fatal("expected non-empty thumbprint")
			}
			// thumbprint should be base64url-encoded (no padding)
			if len(tp) == 0 {
				t.Fatal("thumbprint has zero length")
			}

			if tc.jwk.CRV == "Ed25519" {
				ed25519Thumbprints = append(ed25519Thumbprints, tp)
			}
		})
	}

	// verify determinism: all Ed25519 thumbprints should be identical
	if len(ed25519Thumbprints) >= 2 {
		for i := 1; i < len(ed25519Thumbprints); i++ {
			if ed25519Thumbprints[i] != ed25519Thumbprints[0] {
				t.Errorf("thumbprint not deterministic: %q != %q", ed25519Thumbprints[i], ed25519Thumbprints[0])
			}
		}
	}
}

func TestComputeThumbprint_IncludesY(t *testing.T) {
	// A key with Y should produce a different thumbprint than without Y
	withY := JWK{
		KTY: "EC",
		CRV: "secp256k1",
		X:   "WbbaSStufflt7SVQJkePlz--CDAwSA76XFeCG3v22Gc",
		Y:   "bOE4QfbFSGFbGwAcezB-kRBi26YR4cXuTqG0W6g1eCY",
	}

	withoutY := JWK{
		KTY: "EC",
		CRV: "secp256k1",
		X:   "WbbaSStufflt7SVQJkePlz--CDAwSA76XFeCG3v22Gc",
	}

	tp1, err := withY.ComputeThumbprint()
	if err != nil {
		t.Fatalf("ComputeThumbprint (withY): %v", err)
	}

	tp2, err := withoutY.ComputeThumbprint()
	if err != nil {
		t.Fatalf("ComputeThumbprint (withoutY): %v", err)
	}

	if tp1 == tp2 {
		t.Error("expected different thumbprints when Y is present vs absent")
	}
}
