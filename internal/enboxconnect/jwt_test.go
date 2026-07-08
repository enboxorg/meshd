package enboxconnect

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/enboxorg/meshd/pkg/dids/didjwk"
)

func TestSignAndVerifyJWT(t *testing.T) {
	signer, err := didjwk.Create()
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	payload := map[string]string{"hello": "world"}
	token, err := signJWT(payload, signer.URI+"#0", signer.PrivateKey)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}

	// Header must be the exact SDK layout: {alg, kid, typ} in this order.
	headerRaw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	wantHeader := `{"alg":"EdDSA","kid":"` + signer.URI + `#0","typ":"JWT"}`
	if string(headerRaw) != wantHeader {
		t.Errorf("header = %s, want %s", headerRaw, wantHeader)
	}

	got, err := verifyJWT(token)
	if err != nil {
		t.Fatalf("verifyJWT: %v", err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("unmarshaling payload: %v", err)
	}
	if decoded["hello"] != "world" {
		t.Errorf("payload = %v", decoded)
	}
}

func TestVerifyJWTRejectsTampering(t *testing.T) {
	signer, err := didjwk.Create()
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	token, err := signJWT(map[string]string{"a": "b"}, signer.URI+"#0", signer.PrivateKey)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}

	parts := strings.Split(token, ".")
	tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"a":"evil"}`))
	tampered := parts[0] + "." + tamperedPayload + "." + parts[2]

	if _, err := verifyJWT(tampered); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("error = %v, want signature verification failure", err)
	}
}

func TestVerifyJWTRejectsBadHeaders(t *testing.T) {
	signer, err := didjwk.Create()
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	sign := func(header map[string]string, payload string) string {
		headerJSON, _ := json.Marshal(header)
		h := base64.RawURLEncoding.EncodeToString(headerJSON)
		p := base64.RawURLEncoding.EncodeToString([]byte(payload))
		sig := base64.RawURLEncoding.EncodeToString([]byte("junk"))
		return h + "." + p + "." + sig
	}

	cases := map[string]struct {
		token   string
		wantErr string
	}{
		"missing kid": {
			token:   sign(map[string]string{"alg": "EdDSA", "typ": "JWT"}, "{}"),
			wantErr: `missing required "kid"`,
		},
		"wrong alg": {
			token:   sign(map[string]string{"alg": "RS256", "kid": signer.URI + "#0", "typ": "JWT"}, "{}"),
			wantErr: "unsupported jwt alg",
		},
		"unresolvable kid": {
			token:   sign(map[string]string{"alg": "EdDSA", "kid": "did:web:example.com#0", "typ": "JWT"}, "{}"),
			wantErr: "resolving jwt signer",
		},
		"unknown verification method": {
			token:   sign(map[string]string{"alg": "EdDSA", "kid": signer.URI + "#9", "typ": "JWT"}, "{}"),
			wantErr: "not found in resolved DID document",
		},
		"wrong segment count": {
			token:   "a.b",
			wantErr: "3 segments",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := verifyJWT(tc.token); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
