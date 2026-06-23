package vault

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	plaintext := []byte(`{"secret":"value"}`)

	sealed, err := SealWithParams(plaintext, "correct horse battery staple", FastArgon2idParams)
	if err != nil {
		t.Fatalf("SealWithParams: %v", err)
	}
	if bytes.Contains(sealed, []byte("value")) {
		t.Fatal("sealed envelope contains plaintext")
	}

	got, err := Open(sealed, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch\ngot:  %s\nwant: %s", got, plaintext)
	}
}

func TestOpenWrongPassword(t *testing.T) {
	sealed, err := SealWithParams([]byte("secret"), "right", FastArgon2idParams)
	if err != nil {
		t.Fatalf("SealWithParams: %v", err)
	}
	if _, err := Open(sealed, "wrong"); err == nil {
		t.Fatal("expected wrong password to fail")
	}
}

func TestSealRejectsEmptyPassword(t *testing.T) {
	if _, err := SealWithParams([]byte("secret"), "", FastArgon2idParams); err == nil {
		t.Fatal("expected empty password error")
	}
}

func TestEnvelopeMetadata(t *testing.T) {
	sealed, err := SealWithParams([]byte("secret"), "password", FastArgon2idParams)
	if err != nil {
		t.Fatalf("SealWithParams: %v", err)
	}

	var env Envelope
	if err := json.Unmarshal(sealed, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.Version != Version {
		t.Fatalf("Version = %d, want %d", env.Version, Version)
	}
	if env.KDF != kdfArgon2id {
		t.Fatalf("KDF = %q, want %q", env.KDF, kdfArgon2id)
	}
	if env.Cipher != cipherXChaCha {
		t.Fatalf("Cipher = %q, want %q", env.Cipher, cipherXChaCha)
	}
	if env.Salt == "" || env.Nonce == "" || env.Ciphertext == "" {
		t.Fatal("envelope missing salt, nonce, or ciphertext")
	}
}

func TestOpenRejectsInvalidKDFParams(t *testing.T) {
	sealed, err := SealWithParams([]byte("secret"), "password", FastArgon2idParams)
	if err != nil {
		t.Fatalf("SealWithParams: %v", err)
	}

	var env Envelope
	if err := json.Unmarshal(sealed, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	env.KDFParams.Threads = 0
	corrupt, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal corrupt envelope: %v", err)
	}

	if _, err := Open(corrupt, "password"); err == nil {
		t.Fatal("expected invalid KDF params to fail")
	}
}
