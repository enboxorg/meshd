package did

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tv42/zbase32"
)

func TestGenerate(t *testing.T) {
	d, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	t.Run("URI prefix", func(t *testing.T) {
		if !strings.HasPrefix(d.URI, "did:dht:") {
			t.Errorf("URI = %q, want did:dht: prefix", d.URI)
		}
	})

	t.Run("identifier decodes to public key", func(t *testing.T) {
		decoded, err := zbase32.DecodeString(d.Identifier())
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(decoded) != ed25519.PublicKeySize {
			t.Errorf("decoded %d bytes, want %d", len(decoded), ed25519.PublicKeySize)
		}
		if string(decoded) != string(d.SigningPublicKey) {
			t.Error("decoded identifier does not match public key")
		}
	})

	t.Run("key sizes", func(t *testing.T) {
		if len(d.SigningKey) != ed25519.PrivateKeySize {
			t.Errorf("signing key: %d bytes, want %d", len(d.SigningKey), ed25519.PrivateKeySize)
		}
		if len(d.EncryptionPublicKey) != 32 {
			t.Errorf("encryption public key: %d bytes, want 32", len(d.EncryptionPublicKey))
		}
		if len(d.EncryptionPrivateKey) != 32 {
			t.Errorf("encryption private key: %d bytes, want 32", len(d.EncryptionPrivateKey))
		}
	})

	t.Run("KeyID", func(t *testing.T) {
		if d.KeyID() != d.URI+"#0" {
			t.Errorf("KeyID = %q, want %q", d.KeyID(), d.URI+"#0")
		}
	})
}

func TestSignVerify(t *testing.T) {
	d, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	msg := []byte("hello mesh")
	sig, err := d.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	t.Run("valid signature", func(t *testing.T) {
		if !d.Verify(msg, sig) {
			t.Error("Verify returned false for valid signature")
		}
	})

	t.Run("tampered message", func(t *testing.T) {
		if d.Verify([]byte("tampered"), sig) {
			t.Error("Verify returned true for tampered message")
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		badSig := make([]byte, len(sig))
		copy(badSig, sig)
		badSig[0] ^= 0xff
		if d.Verify(msg, badSig) {
			t.Error("Verify returned true for tampered signature")
		}
	})
}

func TestFromPrivateKey(t *testing.T) {
	d1, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	d2, err := FromPrivateKey(d1.SigningKey)
	if err != nil {
		t.Fatalf("FromPrivateKey: %v", err)
	}

	if d1.URI != d2.URI {
		t.Errorf("URIs differ: %q vs %q", d1.URI, d2.URI)
	}
	if string(d1.EncryptionPublicKey) != string(d2.EncryptionPublicKey) {
		t.Error("encryption public keys differ")
	}

	msg := []byte("roundtrip test")
	sig, _ := d2.Sign(msg)
	if !d1.Verify(msg, sig) {
		t.Error("signature from reconstructed DID doesn't verify")
	}
}

func TestParseURI(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		d, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}

		pub, err := ParseURI(d.URI)
		if err != nil {
			t.Fatalf("ParseURI: %v", err)
		}
		if string(pub) != string(d.SigningPublicKey) {
			t.Error("parsed public key does not match")
		}

		msg := []byte("parse test")
		sig, _ := d.Sign(msg)
		if !VerifyWith(pub, msg, sig) {
			t.Error("VerifyWith parsed key failed")
		}
	})

	t.Run("errors", func(t *testing.T) {
		tests := map[string]struct {
			uri       string
			wantErr   error
		}{
			"empty":         {uri: "", wantErr: ErrInvalidURI},
			"wrong method":  {uri: "did:web:example.com", wantErr: ErrInvalidURI},
			"no identifier": {uri: "did:dht:", wantErr: ErrInvalidURI},
		}
		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				_, err := ParseURI(tc.uri)
				if err == nil {
					t.Fatal("expected error")
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("got error %v, want %v", err, tc.wantErr)
				}
			})
		}
	})
}

func TestDocument(t *testing.T) {
	d, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	t.Run("with service", func(t *testing.T) {
		doc := d.Document("http://localhost:8787")

		if doc.ID != d.URI {
			t.Errorf("ID = %q, want %q", doc.ID, d.URI)
		}
		if len(doc.VerificationMethod) != 2 {
			t.Fatalf("want 2 verification methods, got %d", len(doc.VerificationMethod))
		}
		if doc.VerificationMethod[0].PublicKeyJwk.CRV != "Ed25519" {
			t.Error("vm[0] should be Ed25519")
		}
		if doc.VerificationMethod[1].PublicKeyJwk.CRV != "X25519" {
			t.Error("vm[1] should be X25519")
		}
		if len(doc.KeyAgreement) != 1 || doc.KeyAgreement[0] != d.URI+"#enc" {
			t.Errorf("keyAgreement = %v", doc.KeyAgreement)
		}
		if len(doc.Service) != 1 || doc.Service[0].Type != "DecentralizedWebNode" {
			t.Error("missing DWN service")
		}

		// Serializable to JSON.
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if len(data) == 0 {
			t.Error("empty JSON")
		}
	})

	t.Run("without service", func(t *testing.T) {
		doc := d.Document("")
		if len(doc.Service) != 0 {
			t.Errorf("expected no services, got %d", len(doc.Service))
		}
	})
}

func TestDeterminism(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	d1, _ := FromPrivateKey(priv)
	d2, _ := FromPrivateKey(priv)

	if d1.URI != d2.URI {
		t.Error("same key produced different URIs")
	}
	if string(d1.EncryptionPublicKey) != string(d2.EncryptionPublicKey) {
		t.Error("same key produced different encryption keys")
	}
}
