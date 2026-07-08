package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// --- KEK info strings -------------------------------------------------------

// The KEK HKDF info strings are compact JSON arrays, byte-identical to the
// SDK's JSON.stringify output.
func TestKEKInfoGoldenStrings(t *testing.T) {
	if got, want := protocolPathKEKInfo("kid123"),
		`["X25519-HKDF-SHA256+A256KW","protocolPath","kid123"]`; got != want {
		t.Errorf("protocolPath info = %s, want %s", got, want)
	}
	if got, want := roleAudienceKEKInfo("https://example.com/p", "network/node", "kid123"),
		`["X25519-HKDF-SHA256+A256KW","roleAudience","https://example.com/p","network/node","kid123"]`; got != want {
		t.Errorf("roleAudience info = %s, want %s", got, want)
	}
	if got, want := SealKEKInfo("https://example.com/p", "network/node", "ctx1/ctx2", "akid"),
		`["X25519-HKDF-SHA256+A256KW","seal","https://example.com/p","network/node","ctx1/ctx2","akid"]`; got != want {
		t.Errorf("seal info = %s, want %s", got, want)
	}
	// No HTML escaping (JSON.stringify leaves &, <, > untouched).
	if got, want := protocolPathKEKInfo("a&<>b"),
		`["X25519-HKDF-SHA256+A256KW","protocolPath","a&<>b"]`; got != want {
		t.Errorf("info with specials = %s, want %s", got, want)
	}
}

// --- JSON wire shapes -------------------------------------------------------

func TestKeyEncryptionJSONShape(t *testing.T) {
	roleEntry := KeyEncryption{
		Algorithm:          "X25519-HKDF-SHA256+A256KW",
		EncryptedKey:       "EK",
		EphemeralPublicKey: &PublicKeyJWK{KTY: "OKP", CRV: "X25519", X: "XX"},
		KeyID:              "KID",
		DerivationScheme:   "roleAudience",
		Protocol:           "https://example.com/p",
		RolePath:           "network/node",
	}
	got, err := json.Marshal(roleEntry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"algorithm":"X25519-HKDF-SHA256+A256KW","encryptedKey":"EK",` +
		`"ephemeralPublicKey":{"kty":"OKP","crv":"X25519","x":"XX"},"keyId":"KID",` +
		`"derivationScheme":"roleAudience","protocol":"https://example.com/p","rolePath":"network/node"}`
	if string(got) != want {
		t.Errorf("roleAudience entry JSON:\n got=%s\nwant=%s", got, want)
	}
	for _, forbidden := range []string{`"role"`, `"epoch"`} {
		if strings.Contains(string(got), forbidden) {
			t.Errorf("roleAudience entry must not contain %s: %s", forbidden, got)
		}
	}

	pathEntry := KeyEncryption{
		Algorithm:          "X25519-HKDF-SHA256+A256KW",
		EncryptedKey:       "EK",
		EphemeralPublicKey: &PublicKeyJWK{KTY: "OKP", CRV: "X25519", X: "XX"},
		KeyID:              "KID",
		DerivationScheme:   "protocolPath",
	}
	got, err = json.Marshal(pathEntry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want = `{"algorithm":"X25519-HKDF-SHA256+A256KW","encryptedKey":"EK",` +
		`"ephemeralPublicKey":{"kty":"OKP","crv":"X25519","x":"XX"},"keyId":"KID",` +
		`"derivationScheme":"protocolPath"}`
	if string(got) != want {
		t.Errorf("protocolPath entry JSON:\n got=%s\nwant=%s", got, want)
	}
}

func TestSealKeyWrapJSONShape(t *testing.T) {
	seal := SealKeyWrap{
		Algorithm:          "X25519-HKDF-SHA256+A256KW",
		DerivationScheme:   "seal",
		EncryptedKey:       "EK",
		EphemeralPublicKey: &PublicKeyJWK{KTY: "OKP", CRV: "X25519", X: "XX"},
		KeyID:              "KID",
	}
	got, err := json.Marshal(seal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"algorithm":"X25519-HKDF-SHA256+A256KW","derivationScheme":"seal",` +
		`"encryptedKey":"EK","ephemeralPublicKey":{"kty":"OKP","crv":"X25519","x":"XX"},"keyId":"KID"}`
	if string(got) != want {
		t.Errorf("SealKeyWrap JSON:\n got=%s\nwant=%s", got, want)
	}
}

func TestAudienceAndDeliveryPayloadJSONShape(t *testing.T) {
	audience := AudiencePayload{
		Protocol:     "https://example.com/p",
		RolePath:     "network/node",
		ContextID:    "ctx",
		KeyID:        "KID",
		PublicKeyJwk: PublicKeyJWK{KTY: "OKP", CRV: "X25519", X: "PUB"},
		SealedPrivateKey: SealKeyWrap{
			Algorithm:          "X25519-HKDF-SHA256+A256KW",
			DerivationScheme:   "seal",
			EncryptedKey:       "EK",
			EphemeralPublicKey: &PublicKeyJWK{KTY: "OKP", CRV: "X25519", X: "EPK"},
			KeyID:              "SKID",
		},
	}
	got, err := json.Marshal(audience)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"protocol":"https://example.com/p","rolePath":"network/node","contextId":"ctx","keyId":"KID",` +
		`"publicKeyJwk":{"kty":"OKP","crv":"X25519","x":"PUB"},` +
		`"sealedPrivateKey":{"algorithm":"X25519-HKDF-SHA256+A256KW","derivationScheme":"seal",` +
		`"encryptedKey":"EK","ephemeralPublicKey":{"kty":"OKP","crv":"X25519","x":"EPK"},"keyId":"SKID"}}`
	if string(got) != want {
		t.Errorf("AudiencePayload JSON:\n got=%s\nwant=%s", got, want)
	}

	delivery := DeliveryPayload{
		Protocol:  "https://example.com/p",
		RolePath:  "network/node",
		ContextID: "ctx",
		KeyID:     "KID",
		KeyMaterial: RoleAudienceKeyMaterial{
			Algorithm:        "X25519-HKDF-SHA256+A256KW",
			DerivationScheme: "roleAudience",
			KeyID:            "KID",
			PublicKeyJwk:     PublicKeyJWK{KTY: "OKP", CRV: "X25519", X: "PUB"},
			PrivateKeyJwk:    PrivateKeyJWK{KTY: "OKP", CRV: "X25519", X: "PUB", D: "PRIV"},
		},
	}
	got, err = json.Marshal(delivery)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want = `{"protocol":"https://example.com/p","rolePath":"network/node","contextId":"ctx","keyId":"KID",` +
		`"keyMaterial":{"algorithm":"X25519-HKDF-SHA256+A256KW","derivationScheme":"roleAudience","keyId":"KID",` +
		`"publicKeyJwk":{"kty":"OKP","crv":"X25519","x":"PUB"},` +
		`"privateKeyJwk":{"kty":"OKP","crv":"X25519","x":"PUB","d":"PRIV"}}}`
	if string(got) != want {
		t.Errorf("DeliveryPayload JSON:\n got=%s\nwant=%s", got, want)
	}

	deliveryTags := DeliveryTags{
		Protocol: "p", RolePath: "r", ContextID: "c", KeyID: "k",
		RecipientAuthority: DeliveryRecipientAuthorityRoleHolder,
	}
	got, _ = json.Marshal(deliveryTags)
	want = `{"protocol":"p","rolePath":"r","contextId":"c","keyId":"k","recipientAuthority":"roleHolder"}`
	if string(got) != want {
		t.Errorf("DeliveryTags JSON:\n got=%s\nwant=%s", got, want)
	}
}

func TestGrantKeyJSONShapes(t *testing.T) {
	payload := GrantKeyPayload{
		GrantID: "grant-1",
		Scope: GrantKeyScope{
			Scheme:   "protocolPath",
			Protocol: "https://example.com/p",
		},
		KeyMaterial: ProtocolPathKeyMaterial{
			Algorithm:        "X25519-HKDF-SHA256+A256KW",
			DerivationScheme: "protocolPath",
			DerivationPath:   []string{"protocolPath", "https://example.com/p"},
			KeyID:            "KID",
			PublicKeyJwk:     PublicKeyJWK{KTY: "OKP", CRV: "X25519", X: "PUB"},
			PrivateKeyJwk:    PrivateKeyJWK{KTY: "OKP", CRV: "X25519", X: "PUB", D: "PRIV"},
		},
	}
	got, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"grantId":"grant-1","scope":{"scheme":"protocolPath","protocol":"https://example.com/p"},` +
		`"keyMaterial":{"algorithm":"X25519-HKDF-SHA256+A256KW","derivationScheme":"protocolPath",` +
		`"derivationPath":["protocolPath","https://example.com/p"],"keyId":"KID",` +
		`"publicKeyJwk":{"kty":"OKP","crv":"X25519","x":"PUB"},` +
		`"privateKeyJwk":{"kty":"OKP","crv":"X25519","x":"PUB","d":"PRIV"}}}`
	if string(got) != want {
		t.Errorf("GrantKeyPayload JSON:\n got=%s\nwant=%s", got, want)
	}

	env := WrappedGrantKeyEnvelope{
		Format: WrappedGrantKeyFormat,
		KeyEncryption: WrappedGrantKeyKeyEncryption{
			Algorithm:          "X25519-HKDF-SHA256+A256KW",
			KeyID:              "KID",
			EphemeralPublicKey: &PublicKeyJWK{KTY: "OKP", CRV: "X25519", X: "EPK"},
			EncryptedKey:       "EK",
		},
		ContentEncryption: WrappedGrantKeyContentEncryption{
			Algorithm:            "A256CTR",
			InitializationVector: "IV",
		},
		Ciphertext: "CT",
	}
	got, err = json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want = `{"format":"enbox/wrapped-grant-key@1",` +
		`"keyEncryption":{"algorithm":"X25519-HKDF-SHA256+A256KW","keyId":"KID",` +
		`"ephemeralPublicKey":{"kty":"OKP","crv":"X25519","x":"EPK"},"encryptedKey":"EK"},` +
		`"contentEncryption":{"algorithm":"A256CTR","initializationVector":"IV"},"ciphertext":"CT"}`
	if string(got) != want {
		t.Errorf("WrappedGrantKeyEnvelope JSON:\n got=%s\nwant=%s", got, want)
	}
	// The wrapped-envelope keyEncryption must NOT carry a derivationScheme.
	if strings.Contains(string(got), "derivationScheme") {
		t.Errorf("wrapped envelope keyEncryption must not contain derivationScheme: %s", got)
	}

	tags := GrantKeyTags{GrantID: "g", Protocol: "p", ProtocolPath: "a/b", KeyID: "k"}
	got, _ = json.Marshal(tags)
	want = `{"grantId":"g","protocol":"p","protocolPath":"a/b","keyId":"k"}`
	if string(got) != want {
		t.Errorf("GrantKeyTags JSON:\n got=%s\nwant=%s", got, want)
	}
	tags.ProtocolPath = ""
	got, _ = json.Marshal(tags)
	if strings.Contains(string(got), "protocolPath") {
		t.Errorf("empty protocolPath tag must be omitted: %s", got)
	}
}

// --- Seal wrap / unwrap -----------------------------------------------------

func TestSealRoundTrip(t *testing.T) {
	audiencePriv, audiencePub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	sealingPriv, sealingPub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	akid := thumbprintForPublicKey(audiencePub)

	seal, err := SealAudiencePrivateKey(audiencePriv, sealingPub, "https://p", "network/node", "ctx", akid)
	if err != nil {
		t.Fatalf("SealAudiencePrivateKey: %v", err)
	}
	if seal.Algorithm != AlgX25519HKDFA256KW || seal.DerivationScheme != DerivationSchemeSeal {
		t.Fatalf("unexpected seal identifiers: %+v", seal)
	}
	if seal.KeyID != thumbprintForPublicKey(sealingPub) {
		t.Fatalf("seal keyId = %q, want thumbprint of sealing key", seal.KeyID)
	}

	got, err := UnsealAudiencePrivateKey(seal, sealingPriv, "https://p", "network/node", "ctx", akid)
	if err != nil {
		t.Fatalf("UnsealAudiencePrivateKey: %v", err)
	}
	if !bytes.Equal(got, audiencePriv) {
		t.Fatal("unsealed key does not match the sealed audience private key")
	}

	// Any tuple element mismatch changes the KEK info and fails the AES-KW
	// integrity check.
	if _, err := UnsealAudiencePrivateKey(seal, sealingPriv, "https://p", "network/node", "other-ctx", akid); err == nil {
		t.Fatal("expected unseal with wrong contextId to fail")
	}
	if _, err := UnsealAudiencePrivateKey(seal, sealingPriv, "https://p", "other/role", "ctx", akid); err == nil {
		t.Fatal("expected unseal with wrong rolePath to fail")
	}
	// A wrong sealing key fails too.
	otherPriv, _, _ := GenerateX25519KeyPair()
	if _, err := UnsealAudiencePrivateKey(seal, otherPriv, "https://p", "network/node", "ctx", akid); err == nil {
		t.Fatal("expected unseal with wrong sealing key to fail")
	}
}

// --- Audience payload build / verify / unseal -------------------------------

func TestBuildAndUnsealAudienceRecord(t *testing.T) {
	const (
		proto    = "https://example.com/mesh"
		rolePath = "network/node"
		ctxID    = "ctx-network"
	)
	ownerRoot, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	// The sealing key is the tenant role-path $keyAgreement key.
	sealingPriv, err := DeriveRolePathKey(ownerRoot, proto, rolePath)
	if err != nil {
		t.Fatalf("DeriveRolePathKey: %v", err)
	}
	sealingPub, err := X25519PublicKey(sealingPriv)
	if err != nil {
		t.Fatalf("X25519PublicKey: %v", err)
	}

	km, err := GenerateAudienceKey()
	if err != nil {
		t.Fatalf("GenerateAudienceKey: %v", err)
	}
	if err := VerifyRoleAudienceKeyMaterial(km); err != nil {
		t.Fatalf("VerifyRoleAudienceKeyMaterial: %v", err)
	}

	payload, err := BuildAudiencePayload(km, sealingPub, proto, rolePath, ctxID)
	if err != nil {
		t.Fatalf("BuildAudiencePayload: %v", err)
	}
	if err := VerifyAudiencePayload(payload); err != nil {
		t.Fatalf("VerifyAudiencePayload: %v", err)
	}
	if payload.Tags() != (AudienceTags{Protocol: proto, RolePath: rolePath, ContextID: ctxID, KeyID: km.KeyID}) {
		t.Fatalf("unexpected audience tags: %+v", payload.Tags())
	}

	audiencePriv, err := UnsealAudienceRecord(payload, sealingPriv)
	if err != nil {
		t.Fatalf("UnsealAudienceRecord: %v", err)
	}
	wantPriv, err := base64URLDecode(km.PrivateKeyJwk.D)
	if err != nil {
		t.Fatalf("decode km.d: %v", err)
	}
	if !bytes.Equal(audiencePriv, wantPriv) {
		t.Fatal("unsealed audience private key mismatch")
	}

	// Tampered keyId is rejected before unsealing.
	bad := *payload
	bad.KeyID = strings.Repeat("A", 43)
	if _, err := UnsealAudienceRecord(&bad, sealingPriv); err == nil {
		t.Fatal("expected payload with tampered keyId to be rejected")
	}

	// A different role-path key must be rejected by the seal keyId check.
	wrongPriv, err := DeriveRolePathKey(ownerRoot, proto, "network/other")
	if err != nil {
		t.Fatalf("DeriveRolePathKey: %v", err)
	}
	if _, err := UnsealAudienceRecord(payload, wrongPriv); err == nil {
		t.Fatal("expected unseal with wrong role-path key to be rejected")
	}
}

// --- roleAudience encrypt / decrypt -----------------------------------------

func TestRoleAudienceEncryptDecryptRoundTrip(t *testing.T) {
	const (
		proto    = "https://example.com/mesh"
		rolePath = "network/node"
	)
	ownerRoot, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	leafPriv, leafPub, err := DerivePrivateKey(ownerRoot, BuildProtocolPathDerivation(proto, "network", "peer"))
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}

	audiencePriv, audiencePub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	plaintext := []byte(`{"peer":"wg-pubkey"}`)
	ciphertext, enc, err := EncryptData(plaintext, []KeyEncryptionInput{
		{PublicKey: leafPub, DerivationScheme: DerivationSchemeProtocolPath},
		{PublicKey: audiencePub, DerivationScheme: DerivationSchemeRoleAudience, Protocol: proto, RolePath: rolePath},
	})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	// Wire shape of the roleAudience entry.
	raEntry := FindKeyEncryption(enc, DerivationSchemeRoleAudience)
	if raEntry == nil {
		t.Fatal("missing roleAudience entry")
	}
	if raEntry.Protocol != proto || raEntry.RolePath != rolePath {
		t.Fatalf("roleAudience entry tuple = (%q, %q)", raEntry.Protocol, raEntry.RolePath)
	}
	if raEntry.KeyID != thumbprintForPublicKey(audiencePub) {
		t.Fatalf("roleAudience keyId = %q, want audience thumbprint", raEntry.KeyID)
	}
	info := RoleAudienceEntryInfo(enc)
	if info == nil || info.Protocol != proto || info.RolePath != rolePath || info.KeyID != raEntry.KeyID {
		t.Fatalf("RoleAudienceEntryInfo = %+v", info)
	}

	// Path 1: owner decrypts via the protocolPath entry.
	got, err := DecryptData(ciphertext, enc, leafPriv)
	if err != nil {
		t.Fatalf("DecryptData(owner): %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("owner decryption mismatch")
	}

	// Path 2: role holder decrypts via the roleAudience entry.
	dec, err := NewRoleAudienceDecrypter(audiencePriv)
	if err != nil {
		t.Fatalf("NewRoleAudienceDecrypter: %v", err)
	}
	defer dec.Close()
	if dec.KeyID() != raEntry.KeyID {
		t.Fatalf("decrypter keyId = %q, want %q", dec.KeyID(), raEntry.KeyID)
	}
	got, err = dec.Decrypt(ciphertext, enc)
	if err != nil {
		t.Fatalf("RoleAudienceDecrypter.Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("audience decryption mismatch")
	}

	// A different audience key finds no matching entry.
	otherPriv, _, _ := GenerateX25519KeyPair()
	other, err := NewRoleAudienceDecrypter(otherPriv)
	if err != nil {
		t.Fatalf("NewRoleAudienceDecrypter: %v", err)
	}
	if _, err := other.Decrypt(ciphertext, enc); err == nil {
		t.Fatal("expected decryption with an unrelated audience key to fail")
	}
}

func TestEncryptDataRoleAudienceRequiresTuple(t *testing.T) {
	_, pub, _ := GenerateX25519KeyPair()
	_, _, err := EncryptData([]byte("x"), []KeyEncryptionInput{
		{PublicKey: pub, DerivationScheme: DerivationSchemeRoleAudience},
	})
	if err == nil {
		t.Fatal("expected roleAudience input without protocol/rolePath to fail")
	}
}

// --- delivery records --------------------------------------------------------

func TestDecryptDeliveryRecordRoundTrip(t *testing.T) {
	const (
		proto    = "https://example.com/mesh"
		rolePath = "network/node"
		ctxID    = "ctx-network"
	)
	// The role holder derives the delivery decryption key from THEIR OWN
	// root at the role path.
	holderRoot, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	holderRolePriv, err := DeriveRolePathKey(holderRoot, proto, rolePath)
	if err != nil {
		t.Fatalf("DeriveRolePathKey: %v", err)
	}
	holderRolePub, err := X25519PublicKey(holderRolePriv)
	if err != nil {
		t.Fatalf("X25519PublicKey: %v", err)
	}

	km, err := GenerateAudienceKey()
	if err != nil {
		t.Fatalf("GenerateAudienceKey: %v", err)
	}
	payload := DeliveryPayload{
		Protocol:    proto,
		RolePath:    rolePath,
		ContextID:   ctxID,
		KeyID:       km.KeyID,
		KeyMaterial: *km,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	ciphertext, enc, err := EncryptData(payloadBytes, []KeyEncryptionInput{
		{PublicKey: holderRolePub, DerivationScheme: DerivationSchemeProtocolPath},
	})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	got, err := DecryptDeliveryRecord(holderRoot, proto, rolePath, enc, ciphertext)
	if err != nil {
		t.Fatalf("DecryptDeliveryRecord: %v", err)
	}
	if got.KeyID != km.KeyID || got.ContextID != ctxID || got.KeyMaterial.PrivateKeyJwk.D != km.PrivateKeyJwk.D {
		t.Fatalf("unexpected delivery payload: %+v", got)
	}

	// A different root cannot open the delivery.
	otherRoot, _, _ := GenerateX25519KeyPair()
	if _, err := DecryptDeliveryRecord(otherRoot, proto, rolePath, enc, ciphertext); err == nil {
		t.Fatal("expected delivery decryption with the wrong root to fail")
	}
}

// --- subtree decrypter --------------------------------------------------------

func buildSubtreeKeyMaterial(t *testing.T, ownerRoot []byte, path []string) *ProtocolPathKeyMaterial {
	t.Helper()
	priv, pub, err := DerivePrivateKey(ownerRoot, path)
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}
	x := base64URLEncode(pub)
	return &ProtocolPathKeyMaterial{
		Algorithm:        AlgX25519HKDFA256KW,
		DerivationScheme: DerivationSchemeProtocolPath,
		DerivationPath:   path,
		KeyID:            JWKThumbprintX25519(x),
		PublicKeyJwk:     PublicKeyJWK{KTY: "OKP", CRV: "X25519", X: x},
		PrivateKeyJwk:    PrivateKeyJWK{KTY: "OKP", CRV: "X25519", X: x, D: base64URLEncode(priv)},
	}
}

func TestSubtreeDecrypter(t *testing.T) {
	const proto = "https://example.com/mesh"
	ownerRoot, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	// Whole-protocol subtree key.
	km := buildSubtreeKeyMaterial(t, ownerRoot, []string{"protocolPath", proto})
	dec, err := NewSubtreeDecrypter(km)
	if err != nil {
		t.Fatalf("NewSubtreeDecrypter: %v", err)
	}
	defer dec.Close()

	// Leaf derivation through the delivered key matches owner derivation.
	wantLeaf, _, err := DerivePrivateKey(ownerRoot, BuildProtocolPathDerivation(proto, "network", "node"))
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}
	gotLeaf, err := dec.DeriveLeafKey(proto, "network/node")
	if err != nil {
		t.Fatalf("DeriveLeafKey: %v", err)
	}
	if !bytes.Equal(gotLeaf, wantLeaf) {
		t.Fatal("subtree-derived leaf key does not match owner-derived leaf key")
	}

	// Role-path key derivation (used to open audience seals) matches
	// DeriveRolePathKey from the owner root.
	wantRole, err := DeriveRolePathKey(ownerRoot, proto, "network/node")
	if err != nil {
		t.Fatalf("DeriveRolePathKey: %v", err)
	}
	gotRole, err := dec.RolePathKey(proto, "network/node")
	if err != nil {
		t.Fatalf("RolePathKey: %v", err)
	}
	if !bytes.Equal(gotRole, wantRole) {
		t.Fatal("subtree-derived role-path key mismatch")
	}

	// End-to-end record decryption.
	leafPub, err := X25519PublicKey(wantLeaf)
	if err != nil {
		t.Fatalf("X25519PublicKey: %v", err)
	}
	plaintext := []byte("subtree record")
	ciphertext, enc, err := EncryptData(plaintext, []KeyEncryptionInput{
		{PublicKey: leafPub, DerivationScheme: DerivationSchemeProtocolPath},
	})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	got, err := dec.Decrypt(ciphertext, enc, proto, "network/node")
	if err != nil {
		t.Fatalf("SubtreeDecrypter.Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("subtree decryption mismatch")
	}

	// Coverage checks: the delivered path must be a prefix of the record path.
	if !dec.Covers(proto, "network") || !dec.Covers(proto, "") {
		t.Fatal("whole-protocol key must cover all paths of its protocol")
	}
	if dec.Covers("https://other/protocol", "network") {
		t.Fatal("subtree key must not cover other protocols")
	}

	// Path-scoped key: covers its subtree only.
	scoped, err := NewSubtreeDecrypter(buildSubtreeKeyMaterial(t, ownerRoot, []string{"protocolPath", proto, "network"}))
	if err != nil {
		t.Fatalf("NewSubtreeDecrypter(scoped): %v", err)
	}
	defer scoped.Close()
	scopedLeaf, err := scoped.DeriveLeafKey(proto, "network/node")
	if err != nil {
		t.Fatalf("scoped DeriveLeafKey: %v", err)
	}
	if !bytes.Equal(scopedLeaf, wantLeaf) {
		t.Fatal("scoped subtree leaf mismatch")
	}
	// The delivered key IS the leaf for its own path.
	selfLeaf, err := scoped.DeriveLeafKey(proto, "network")
	if err != nil {
		t.Fatalf("scoped self DeriveLeafKey: %v", err)
	}
	wantSelf, _, _ := DerivePrivateKey(ownerRoot, []string{"protocolPath", proto, "network"})
	if !bytes.Equal(selfLeaf, wantSelf) {
		t.Fatal("scoped self leaf mismatch")
	}
	if _, err := scoped.DeriveLeafKey(proto, "admin"); err == nil {
		t.Fatal("expected out-of-subtree derivation to fail")
	}

	// Tampered key material is rejected.
	bad := *km
	bad.KeyID = strings.Repeat("A", 43)
	if _, err := NewSubtreeDecrypter(&bad); err == nil {
		t.Fatal("expected tampered keyId to be rejected")
	}
}

// --- wrapped grantKey envelope ------------------------------------------------

// buildWrappedGrantKeyEnvelope mirrors the SDK's buildWrappedGrantKeyRecordData.
func buildWrappedGrantKeyEnvelope(t *testing.T, payload *GrantKeyPayload, delegatePub []byte) []byte {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	dek, err := GenerateCEK()
	if err != nil {
		t.Fatalf("GenerateCEK: %v", err)
	}
	iv, err := GenerateIV()
	if err != nil {
		t.Fatalf("GenerateIV: %v", err)
	}
	ciphertext, err := CTRXor(dek, iv, payloadBytes)
	if err != nil {
		t.Fatalf("CTRXor: %v", err)
	}
	keyID := thumbprintForPublicKey(delegatePub)
	ephPub, wrapped, err := WrapCEK(delegatePub, dek, protocolPathKEKInfo(keyID))
	if err != nil {
		t.Fatalf("WrapCEK: %v", err)
	}
	env := WrappedGrantKeyEnvelope{
		Format: WrappedGrantKeyFormat,
		KeyEncryption: WrappedGrantKeyKeyEncryption{
			Algorithm:          AlgX25519HKDFA256KW,
			KeyID:              keyID,
			EphemeralPublicKey: &PublicKeyJWK{KTY: "OKP", CRV: "X25519", X: base64URLEncode(ephPub)},
			EncryptedKey:       base64URLEncode(wrapped),
		},
		ContentEncryption: WrappedGrantKeyContentEncryption{
			Algorithm:            EncA256CTR,
			InitializationVector: base64URLEncode(iv),
		},
		Ciphertext: base64URLEncode(ciphertext),
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return envBytes
}

func TestUnwrapGrantKeyEnvelopeRoundTrip(t *testing.T) {
	const proto = "https://example.com/mesh"
	ownerRoot, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	delegatePriv, delegatePub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	payload := &GrantKeyPayload{
		GrantID: "bafygrant1",
		Scope: GrantKeyScope{
			Scheme:   DerivationSchemeProtocolPath,
			Protocol: proto,
		},
		KeyMaterial: *buildSubtreeKeyMaterial(t, ownerRoot, []string{"protocolPath", proto}),
	}
	envBytes := buildWrappedGrantKeyEnvelope(t, payload, delegatePub)

	got, err := UnwrapGrantKeyEnvelope(envBytes, delegatePriv)
	if err != nil {
		t.Fatalf("UnwrapGrantKeyEnvelope: %v", err)
	}
	if got.GrantID != payload.GrantID ||
		got.Scope != payload.Scope ||
		got.KeyMaterial.KeyID != payload.KeyMaterial.KeyID ||
		got.KeyMaterial.PrivateKeyJwk.D != payload.KeyMaterial.PrivateKeyJwk.D {
		t.Fatalf("unwrapped payload mismatch:\n got=%+v\nwant=%+v", got, payload)
	}

	// The delivered key decrypts a record in the covered subtree.
	dec, err := NewSubtreeDecrypterFromGrantKey(got)
	if err != nil {
		t.Fatalf("NewSubtreeDecrypterFromGrantKey: %v", err)
	}
	defer dec.Close()
	leafPriv, leafPub, err := DerivePrivateKey(ownerRoot, BuildProtocolPathDerivation(proto, "network", "node"))
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}
	clear(leafPriv)
	plaintext := []byte("delegated read")
	ciphertext, enc, err := EncryptData(plaintext, []KeyEncryptionInput{
		{PublicKey: leafPub, DerivationScheme: DerivationSchemeProtocolPath},
	})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	decrypted, err := dec.Decrypt(ciphertext, enc, proto, "network/node")
	if err != nil {
		t.Fatalf("SubtreeDecrypter.Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("delegated decryption mismatch")
	}

	// Wrong delegate key: target-mismatch error before any unwrap attempt.
	otherPriv, _, _ := GenerateX25519KeyPair()
	if _, err := UnwrapGrantKeyEnvelope(envBytes, otherPriv); err == nil ||
		!strings.Contains(err.Error(), "targets key") {
		t.Fatalf("expected target mismatch error, got %v", err)
	}

	// Unknown format is rejected.
	var env WrappedGrantKeyEnvelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.Format = "enbox/other@1"
	if _, err := UnwrapGrantKeyEnvelopeStruct(&env, delegatePriv); err == nil {
		t.Fatal("expected unknown format to be rejected")
	}
}

func TestUnwrapGrantKeyEnvelopeRejectsInconsistentPayload(t *testing.T) {
	const proto = "https://example.com/mesh"
	ownerRoot, _, _ := GenerateX25519KeyPair()
	delegatePriv, delegatePub, _ := GenerateX25519KeyPair()

	// derivationPath does not match the scope (scope says whole protocol,
	// path says network subtree).
	payload := &GrantKeyPayload{
		GrantID: "bafygrant2",
		Scope: GrantKeyScope{
			Scheme:   DerivationSchemeProtocolPath,
			Protocol: proto,
		},
		KeyMaterial: *buildSubtreeKeyMaterial(t, ownerRoot, []string{"protocolPath", proto, "network"}),
	}
	envBytes := buildWrappedGrantKeyEnvelope(t, payload, delegatePub)
	if _, err := UnwrapGrantKeyEnvelope(envBytes, delegatePriv); err == nil ||
		!strings.Contains(err.Error(), "derivationPath") {
		t.Fatalf("expected derivationPath mismatch error, got %v", err)
	}
}

// --- BuildWriteEncryption ------------------------------------------------------

type fakeAudienceSource struct {
	keys  map[string]struct{ pub []byte }
	calls []string
}

func (f *fakeAudienceSource) Current(_ context.Context, protocol, rolePath, contextID string) ([]byte, string, error) {
	key := protocol + "|" + rolePath + "|" + contextID
	f.calls = append(f.calls, key)
	entry, ok := f.keys[key]
	if !ok {
		return nil, "", fmt.Errorf("no audience for tuple %s", key)
	}
	return entry.pub, thumbprintForPublicKey(entry.pub), nil
}

const buildWriteTestProto = "https://example.com/mesh"

func buildWriteTestDefinition(t *testing.T, ownerRoot []byte) json.RawMessage {
	t.Helper()
	def := json.RawMessage(`{
		"protocol": "` + buildWriteTestProto + `",
		"structure": {
			"admin": { "$role": true },
			"network": {
				"node": { "$role": true },
				"writer": { "$role": true },
				"peer": {
					"$actions": [
						{ "role": "network/node", "can": ["read"] },
						{ "role": "admin", "can": ["read", "update"] },
						{ "role": "network/writer", "can": ["create", "update"] },
						{ "role": "ext:thing/member", "can": ["read"] },
						{ "who": "anyone", "can": ["create"] }
					]
				}
			}
		}
	}`)
	injected, err := InjectEncryptionDirectives(def, ownerRoot)
	if err != nil {
		t.Fatalf("InjectEncryptionDirectives: %v", err)
	}
	return injected
}

func TestBuildWriteEncryption(t *testing.T) {
	ownerRoot, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	def := buildWriteTestDefinition(t, ownerRoot)

	_, nodeAudiencePub, _ := GenerateX25519KeyPair()
	_, adminAudiencePub, _ := GenerateX25519KeyPair()
	audiences := &fakeAudienceSource{keys: map[string]struct{ pub []byte }{
		buildWriteTestProto + "|network/node|ctx-network": {pub: nodeAudiencePub},
		buildWriteTestProto + "|admin|":                   {pub: adminAudiencePub},
	}}

	inputs, err := BuildWriteEncryption(context.Background(), def, "network/peer", "ctx-network", audiences)
	if err != nil {
		t.Fatalf("BuildWriteEncryption: %v", err)
	}
	if len(inputs) != 3 {
		t.Fatalf("inputs = %d, want 3 (protocolPath + 2 roleAudience): %+v", len(inputs), inputs)
	}

	// Entry 0: protocolPath to the rule set's $keyAgreement key.
	wantLeafPriv, wantLeafPub, err := DerivePrivateKey(ownerRoot, BuildProtocolPathDerivation(buildWriteTestProto, "network", "peer"))
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}
	clear(wantLeafPriv)
	if inputs[0].DerivationScheme != DerivationSchemeProtocolPath || !bytes.Equal(inputs[0].PublicKey, wantLeafPub) {
		t.Fatalf("input[0] = %+v, want protocolPath to derived $keyAgreement key", inputs[0])
	}

	// Entry 1: nested reading role, contextId = first segment of parent.
	if inputs[1].DerivationScheme != DerivationSchemeRoleAudience ||
		inputs[1].Protocol != buildWriteTestProto ||
		inputs[1].RolePath != "network/node" ||
		!bytes.Equal(inputs[1].PublicKey, nodeAudiencePub) {
		t.Fatalf("input[1] = %+v", inputs[1])
	}

	// Entry 2: root-level reading role, contextId = "".
	if inputs[2].RolePath != "admin" || !bytes.Equal(inputs[2].PublicKey, adminAudiencePub) {
		t.Fatalf("input[2] = %+v", inputs[2])
	}

	// Only the two local reading roles were resolved (no write-only role, no
	// cross-protocol alias role).
	wantCalls := []string{
		buildWriteTestProto + "|network/node|ctx-network",
		buildWriteTestProto + "|admin|",
	}
	if len(audiences.calls) != len(wantCalls) || audiences.calls[0] != wantCalls[0] || audiences.calls[1] != wantCalls[1] {
		t.Fatalf("audience calls = %v, want %v", audiences.calls, wantCalls)
	}

	// The inputs feed EncryptData and both audiences can decrypt is covered
	// by TestRoleAudienceEncryptDecryptRoundTrip; here just check the wire
	// entries carry the tuples.
	ct, enc, err := EncryptData([]byte("payload"), inputs)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	_ = ct
	if len(enc.KeyEncryption) != 3 {
		t.Fatalf("keyEncryption entries = %d, want 3", len(enc.KeyEncryption))
	}
	if enc.KeyEncryption[1].RolePath != "network/node" || enc.KeyEncryption[2].RolePath != "admin" {
		t.Fatalf("unexpected roleAudience entries: %+v", enc.KeyEncryption[1:])
	}
}

func TestBuildWriteEncryptionErrors(t *testing.T) {
	ownerRoot, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	def := buildWriteTestDefinition(t, ownerRoot)
	ctx := context.Background()

	// Missing audience for a reading role.
	empty := &fakeAudienceSource{keys: map[string]struct{ pub []byte }{}}
	if _, err := BuildWriteEncryption(ctx, def, "network/peer", "ctx-network", empty); err == nil {
		t.Fatal("expected missing audience to fail the write build")
	}

	// Nested reading role with an empty parent contextId cannot resolve its
	// audience tuple.
	_, pub, _ := GenerateX25519KeyPair()
	src := &fakeAudienceSource{keys: map[string]struct{ pub []byte }{
		buildWriteTestProto + "|network/node|": {pub: pub},
		buildWriteTestProto + "|admin|":        {pub: pub},
	}}
	if _, err := BuildWriteEncryption(ctx, def, "network/peer", "", src); err == nil {
		t.Fatal("expected empty parent contextId with nested role to fail")
	}

	// keyId mismatch between the advertised keyId and the public key.
	lying := &lyingAudienceSource{pub: pub}
	if _, err := BuildWriteEncryption(ctx, def, "network/peer", "ctx-network", lying); err == nil ||
		!strings.Contains(err.Error(), "thumbprint") {
		t.Fatalf("expected keyId thumbprint mismatch error, got %v", err)
	}

	// A path without $keyAgreement (definition not injected).
	plain := json.RawMessage(`{"protocol":"` + buildWriteTestProto + `","structure":{"thing":{}}}`)
	if _, err := BuildWriteEncryption(ctx, plain, "thing", "", empty); err == nil ||
		!strings.Contains(err.Error(), "$keyAgreement") {
		t.Fatalf("expected missing $keyAgreement error, got %v", err)
	}

	// Unknown protocol path.
	if _, err := BuildWriteEncryption(ctx, def, "nope/nothing", "", empty); err == nil {
		t.Fatal("expected unknown protocol path to fail")
	}
}

type lyingAudienceSource struct {
	pub []byte
}

func (l *lyingAudienceSource) Current(context.Context, string, string, string) ([]byte, string, error) {
	return l.pub, strings.Repeat("A", 43), nil
}

func TestKeyAgreementPublicKeyAtPath(t *testing.T) {
	ownerRoot, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	def := buildWriteTestDefinition(t, ownerRoot)

	pub, keyID, err := KeyAgreementPublicKeyAtPath(def, "network/node")
	if err != nil {
		t.Fatalf("KeyAgreementPublicKeyAtPath: %v", err)
	}
	wantPriv, wantPub, err := DerivePrivateKey(ownerRoot, BuildProtocolPathDerivation(buildWriteTestProto, "network", "node"))
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}
	clear(wantPriv)
	if !bytes.Equal(pub, wantPub) {
		t.Fatal("returned public key does not match the injected $keyAgreement key")
	}
	if keyID != thumbprintForPublicKey(wantPub) {
		t.Fatalf("keyID = %q, want RFC 7638 thumbprint of the $keyAgreement key", keyID)
	}

	// Root-level rule set works too.
	if _, _, err := KeyAgreementPublicKeyAtPath(def, "admin"); err != nil {
		t.Fatalf("KeyAgreementPublicKeyAtPath(admin): %v", err)
	}

	// Errors: unknown path, missing $keyAgreement, empty path.
	if _, _, err := KeyAgreementPublicKeyAtPath(def, "nope"); err == nil {
		t.Fatal("expected unknown path to fail")
	}
	plain := json.RawMessage(`{"protocol":"` + buildWriteTestProto + `","structure":{"thing":{}}}`)
	if _, _, err := KeyAgreementPublicKeyAtPath(plain, "thing"); err == nil ||
		!strings.Contains(err.Error(), "$keyAgreement") {
		t.Fatalf("expected missing $keyAgreement error, got %v", err)
	}
	if _, _, err := KeyAgreementPublicKeyAtPath(def, ""); err == nil {
		t.Fatal("expected empty protocolPath to fail")
	}
}

// --- RoleAudienceContextID -----------------------------------------------------

func TestRoleAudienceContextID(t *testing.T) {
	got, err := RoleAudienceContextID("admin", "anything/here")
	if err != nil || got != "" {
		t.Fatalf("root-level role: got (%q, %v), want (\"\", nil)", got, err)
	}
	got, err = RoleAudienceContextID("network/node", "ctx1/ctx2")
	if err != nil || got != "ctx1" {
		t.Fatalf("depth-1 role: got (%q, %v), want (\"ctx1\", nil)", got, err)
	}
	got, err = RoleAudienceContextID("a/b/c", "ctx1/ctx2/ctx3")
	if err != nil || got != "ctx1/ctx2" {
		t.Fatalf("depth-2 role: got (%q, %v), want (\"ctx1/ctx2\", nil)", got, err)
	}
	if _, err := RoleAudienceContextID("a/b/c", "ctx1"); err == nil {
		t.Fatal("expected too-short contextId to fail")
	}
	if _, err := RoleAudienceContextID("network/node", ""); err == nil {
		t.Fatal("expected empty contextId with nested role to fail")
	}
}
