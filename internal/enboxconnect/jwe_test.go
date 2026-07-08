package enboxconnect

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/enboxorg/meshd/pkg/dids/didjwk"
)

func TestSpliceHeaderPIN(t *testing.T) {
	cases := []struct {
		name   string
		header string
		pin    string
		want   string
	}{
		{
			name:   "pin appended before closing brace",
			header: `{"alg":"dir","epk":{"kty":"OKP"}}`,
			pin:    "1234",
			want:   `{"alg":"dir","epk":{"kty":"OKP"},"pin":"1234"}`,
		},
		{
			name:   "empty pin leaves header untouched",
			header: `{"alg":"dir"}`,
			pin:    "",
			want:   `{"alg":"dir"}`,
		},
		{
			name:   "pin with JSON-special characters is escaped",
			header: `{"alg":"dir"}`,
			pin:    `12"34`,
			want:   `{"alg":"dir","pin":"12\"34"}`,
		},
		{
			// JSON.stringify does not HTML-escape < > &; the AAD must
			// match the SDK byte-for-byte.
			name:   "pin with HTML-special characters is not escaped",
			header: `{"alg":"dir"}`,
			pin:    `1<2>3&4`,
			want:   `{"alg":"dir","pin":"1<2>3&4"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := spliceHeaderPIN([]byte(tc.header), tc.pin)
			if err != nil {
				t.Fatalf("spliceHeaderPIN: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}

	if _, err := spliceHeaderPIN([]byte("not-json"), "1234"); err == nil {
		t.Error("expected error for non-object header")
	}
}

func TestSealRequestJWERoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	const jwt = "aaa.bbb.ccc"

	jwe, err := sealRequestJWE(jwt, key)
	if err != nil {
		t.Fatalf("sealRequestJWE: %v", err)
	}

	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		t.Fatalf("JWE has %d segments, want 5", len(parts))
	}
	if parts[1] != "" {
		t.Errorf("second segment = %q, want empty", parts[1])
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	if string(headerRaw) != requestProtectedHeader {
		t.Errorf("header = %s, want %s", headerRaw, requestProtectedHeader)
	}

	nonce, _ := base64.RawURLEncoding.DecodeString(parts[2])
	ciphertext, _ := base64.RawURLEncoding.DecodeString(parts[3])
	tag, _ := base64.RawURLEncoding.DecodeString(parts[4])
	if len(tag) != 16 {
		t.Errorf("tag length = %d, want 16", len(tag))
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("NewX: %v", err)
	}
	plaintext, err := aead.Open(nil, nonce, append(ciphertext, tag...), headerRaw)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(plaintext) != jwt {
		t.Errorf("plaintext = %q, want %q", plaintext, jwt)
	}

	// Tampered AAD (header) must fail authentication.
	if _, err := aead.Open(nil, nonce, append(ciphertext, tag...), []byte(`{"alg":"dir"}`)); err == nil {
		t.Error("expected authentication failure with tampered AAD")
	}
}

func TestDeriveResponseSharedKeySymmetric(t *testing.T) {
	alice, err := didjwk.Create()
	if err != nil {
		t.Fatalf("creating alice: %v", err)
	}
	bob, err := didjwk.Create()
	if err != nil {
		t.Fatalf("creating bob: %v", err)
	}

	aliceKey, err := deriveResponseSharedKey(alice.X25519PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatalf("alice derive: %v", err)
	}
	bobKey, err := deriveResponseSharedKey(bob.X25519PrivateKey, alice.PublicKey)
	if err != nil {
		t.Fatalf("bob derive: %v", err)
	}

	if !bytes.Equal(aliceKey, bobKey) {
		t.Error("shared keys differ between the two ECDH directions")
	}
	if len(aliceKey) != 32 {
		t.Errorf("shared key length = %d, want 32", len(aliceKey))
	}
}

func TestEd25519PubToX25519MatchesDidjwk(t *testing.T) {
	id, err := didjwk.Create()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}

	local, err := ed25519PubToX25519(id.PublicKey)
	if err != nil {
		t.Fatalf("ed25519PubToX25519: %v", err)
	}
	viaDidjwk, err := didjwk.DeriveX25519PublicKey(id.URI)
	if err != nil {
		t.Fatalf("didjwk.DeriveX25519PublicKey: %v", err)
	}

	if !bytes.Equal(local, viaDidjwk) {
		t.Error("local Ed25519->X25519 conversion disagrees with pkg/dids/didjwk")
	}
	if !bytes.Equal(local, id.X25519PublicKey) {
		t.Error("conversion disagrees with the identity's derived X25519 public key")
	}
}

func TestDecryptResponseJWERejectsMalformed(t *testing.T) {
	id, err := didjwk.Create()
	if err != nil {
		t.Fatalf("creating identity: %v", err)
	}

	cases := map[string]string{
		"wrong segment count": "a.b.c",
		"missing epk": base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"dir"}`)) +
			"..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA",
	}
	for name, jwe := range cases {
		if _, err := decryptResponseJWE(jwe, id.X25519PrivateKey, "1234"); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
