package did

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/enboxorg/meshd/pkg/dids/didjwk"
)

func TestGenerate(t *testing.T) {
	d, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	t.Run("URI prefix", func(t *testing.T) {
		if !strings.HasPrefix(d.URI, "did:jwk:") {
			t.Errorf("URI = %q, want did:jwk: prefix", d.URI)
		}
	})

	t.Run("key sizes", func(t *testing.T) {
		if len(d.SigningKey) != ed25519.PrivateKeySize {
			t.Errorf("signing key: %d bytes, want %d", len(d.SigningKey), ed25519.PrivateKeySize)
		}
		if len(d.SigningPublicKey) != ed25519.PublicKeySize {
			t.Errorf("signing public key: %d bytes, want %d", len(d.SigningPublicKey), ed25519.PublicKeySize)
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

	t.Run("EncryptionKeyID", func(t *testing.T) {
		if d.EncryptionKeyID() != d.URI+"#1" {
			t.Errorf("EncryptionKeyID = %q, want %q", d.EncryptionKeyID(), d.URI+"#1")
		}
	})

	t.Run("X25519 matches didjwk derivation", func(t *testing.T) {
		// DeriveX25519PublicKey from the URI should match our encryption key.
		derived, err := didjwk.DeriveX25519PublicKey(d.URI)
		if err != nil {
			t.Fatalf("DeriveX25519PublicKey: %v", err)
		}
		if string(derived) != string(d.EncryptionPublicKey) {
			t.Error("X25519 public key from DeriveX25519PublicKey does not match EncryptionPublicKey")
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
			uri     string
			wantErr error
		}{
			"empty":        {uri: "", wantErr: ErrInvalidURI},
			"wrong method": {uri: "did:dht:abc123", wantErr: ErrInvalidURI},
			"no identifier": {uri: "did:jwk:", wantErr: ErrInvalidURI},
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
