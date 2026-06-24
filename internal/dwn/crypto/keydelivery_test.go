package crypto

import (
	"encoding/json"
	"testing"
)

func TestDerivedPrivateJwk(t *testing.T) {
	t.Run("NewDerivedPrivateJwk creates valid structure", func(t *testing.T) {
		priv, pub, err := GenerateX25519KeyPair()
		if err != nil {
			t.Fatal(err)
		}

		dpk, err := NewDerivedPrivateJwk(
			"did:example:alice#enc-1",
			DerivationSchemeProtocolContext,
			[]string{"protocolContext", "bafyreiabc123"},
			priv,
		)
		if err != nil {
			t.Fatal(err)
		}

		if dpk.RootKeyID != "did:example:alice#enc-1" {
			t.Errorf("RootKeyID = %q, want %q", dpk.RootKeyID, "did:example:alice#enc-1")
		}
		if dpk.DerivationScheme != DerivationSchemeProtocolContext {
			t.Errorf("DerivationScheme = %q, want %q", dpk.DerivationScheme, DerivationSchemeProtocolContext)
		}
		if len(dpk.DerivationPath) != 2 {
			t.Errorf("DerivationPath length = %d, want 2", len(dpk.DerivationPath))
		}
		if dpk.DerivedPrivateKey.Kty != "OKP" {
			t.Errorf("Kty = %q, want %q", dpk.DerivedPrivateKey.Kty, "OKP")
		}
		if dpk.DerivedPrivateKey.Crv != "X25519" {
			t.Errorf("Crv = %q, want %q", dpk.DerivedPrivateKey.Crv, "X25519")
		}
		if dpk.DerivedPrivateKey.D == "" {
			t.Error("DerivedPrivateKey.D is empty")
		}
		if dpk.DerivedPrivateKey.X == "" {
			t.Error("DerivedPrivateKey.X is empty")
		}

		// Verify round-trip of key bytes.
		gotPriv, err := dpk.PrivateKeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		if len(gotPriv) != len(priv) {
			t.Fatalf("PrivateKeyBytes length = %d, want %d", len(gotPriv), len(priv))
		}
		for i := range priv {
			if gotPriv[i] != priv[i] {
				t.Fatalf("PrivateKeyBytes mismatch at byte %d", i)
			}
		}

		gotPub, err := dpk.PublicKeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		if len(gotPub) != len(pub) {
			t.Fatalf("PublicKeyBytes length = %d, want %d", len(gotPub), len(pub))
		}
		for i := range pub {
			if gotPub[i] != pub[i] {
				t.Fatalf("PublicKeyBytes mismatch at byte %d", i)
			}
		}
	})

	t.Run("MarshalPayload and ParseDerivedPrivateJwk round-trip", func(t *testing.T) {
		priv, _, err := GenerateX25519KeyPair()
		if err != nil {
			t.Fatal(err)
		}

		original, err := NewDerivedPrivateJwk(
			"did:dht:abc123#enc",
			DerivationSchemeProtocolContext,
			[]string{"protocolContext", "bafyreiabc"},
			priv,
		)
		if err != nil {
			t.Fatal(err)
		}

		payload, err := original.MarshalPayload()
		if err != nil {
			t.Fatal(err)
		}

		parsed, err := ParseDerivedPrivateJwk(payload)
		if err != nil {
			t.Fatal(err)
		}

		if parsed.RootKeyID != original.RootKeyID {
			t.Errorf("RootKeyID = %q, want %q", parsed.RootKeyID, original.RootKeyID)
		}
		if parsed.DerivationScheme != original.DerivationScheme {
			t.Errorf("DerivationScheme = %q, want %q", parsed.DerivationScheme, original.DerivationScheme)
		}
		if parsed.DerivedPrivateKey.D != original.DerivedPrivateKey.D {
			t.Errorf("DerivedPrivateKey.D mismatch")
		}
	})

	t.Run("ParseDerivedPrivateJwk rejects invalid JSON", func(t *testing.T) {
		_, err := ParseDerivedPrivateJwk([]byte(`not json`))
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("ParseDerivedPrivateJwk rejects missing fields", func(t *testing.T) {
		tests := map[string]struct {
			payload string
		}{
			"missing rootKeyId": {
				payload: `{"derivationScheme":"protocolContext","derivationPath":["x"],"derivedPrivateKey":{"kty":"OKP","crv":"X25519","x":"a","d":"b"}}`,
			},
			"missing derivationScheme": {
				payload: `{"rootKeyId":"did:example:a#enc","derivationPath":["x"],"derivedPrivateKey":{"kty":"OKP","crv":"X25519","x":"a","d":"b"}}`,
			},
			"missing derivedPrivateKey.d": {
				payload: `{"rootKeyId":"did:example:a#enc","derivationScheme":"protocolContext","derivationPath":["x"],"derivedPrivateKey":{"kty":"OKP","crv":"X25519","x":"a"}}`,
			},
		}

		for name, tc := range tests {
			t.Run(name, func(t *testing.T) {
				_, err := ParseDerivedPrivateJwk([]byte(tc.payload))
				if err == nil {
					t.Error("expected error")
				}
			})
		}
	})
}

func TestDeriveContextKey(t *testing.T) {
	t.Run("derives deterministic context key", func(t *testing.T) {
		rootKey := make([]byte, 32)
		for i := range rootKey {
			rootKey[i] = byte(i)
		}

		key1, err := DeriveContextKey(rootKey, "bafyreiabc123")
		if err != nil {
			t.Fatal(err)
		}
		if len(key1) != 32 {
			t.Fatalf("key length = %d, want 32", len(key1))
		}

		// Same root + same context → same key.
		key2, err := DeriveContextKey(rootKey, "bafyreiabc123")
		if err != nil {
			t.Fatal(err)
		}
		for i := range key1 {
			if key1[i] != key2[i] {
				t.Fatalf("keys differ at byte %d: determinism broken", i)
			}
		}

		// Different context → different key.
		key3, err := DeriveContextKey(rootKey, "bafyreidifferent")
		if err != nil {
			t.Fatal(err)
		}
		same := true
		for i := range key1 {
			if key1[i] != key3[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("different context IDs produced the same key")
		}
	})

	t.Run("DeriveContextKeyJwk creates valid payload", func(t *testing.T) {
		rootKey := make([]byte, 32)
		for i := range rootKey {
			rootKey[i] = byte(i + 10)
		}

		dpk, err := DeriveContextKeyJwk(rootKey, "did:dht:owner#enc", "ctx-abc")
		if err != nil {
			t.Fatal(err)
		}

		if dpk.RootKeyID != "did:dht:owner#enc" {
			t.Errorf("RootKeyID = %q", dpk.RootKeyID)
		}
		if dpk.DerivationScheme != DerivationSchemeProtocolContext {
			t.Errorf("DerivationScheme = %q", dpk.DerivationScheme)
		}
		if len(dpk.DerivationPath) != 2 || dpk.DerivationPath[0] != "protocolContext" || dpk.DerivationPath[1] != "ctx-abc" {
			t.Errorf("DerivationPath = %v", dpk.DerivationPath)
		}

		// Verify the private key matches what DeriveContextKey produces.
		expectedPriv, err := DeriveContextKey(rootKey, "ctx-abc")
		if err != nil {
			t.Fatal(err)
		}
		gotPriv, err := dpk.PrivateKeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		for i := range expectedPriv {
			if gotPriv[i] != expectedPriv[i] {
				t.Fatalf("private key mismatch at byte %d", i)
			}
		}
	})
}

func TestEncryptionKeyManagerContextKeys(t *testing.T) {
	rootKey := make([]byte, 32)
	for i := range rootKey {
		rootKey[i] = byte(i)
	}

	t.Run("owner derives context key from root", func(t *testing.T) {
		mgr := &EncryptionKeyManager{
			RootPrivateKey: rootKey,
			RootKeyID:      "did:dht:owner#enc",
			ProtocolURI:    "https://example.com/proto",
		}

		key, err := mgr.DeriveContextDecryptionKey("ctx-123")
		if err != nil {
			t.Fatal(err)
		}
		if len(key) != 32 {
			t.Fatalf("key length = %d, want 32", len(key))
		}

		// Should match DeriveContextKey directly.
		expected, _ := DeriveContextKey(rootKey, "ctx-123")
		for i := range key {
			if key[i] != expected[i] {
				t.Fatalf("key mismatch at byte %d", i)
			}
		}
	})

	t.Run("non-owner uses stored context key", func(t *testing.T) {
		mgr := &EncryptionKeyManager{
			// No RootPrivateKey → not owner.
			RootKeyID:   "did:dht:other#enc",
			ProtocolURI: "https://example.com/proto",
		}

		// Without stored key, should fail.
		_, err := mgr.DeriveContextDecryptionKey("ctx-123")
		if err == nil {
			t.Error("expected error for non-owner without stored key")
		}

		// Store a key.
		fakeKey := make([]byte, 32)
		for i := range fakeKey {
			fakeKey[i] = byte(i + 100)
		}
		mgr.StoreContextKey("ctx-123", fakeKey)

		// Should succeed now.
		key, err := mgr.DeriveContextDecryptionKey("ctx-123")
		if err != nil {
			t.Fatal(err)
		}
		for i := range fakeKey {
			if key[i] != fakeKey[i] {
				t.Fatalf("stored key mismatch at byte %d", i)
			}
		}
	})

	t.Run("stored key takes precedence over derivation", func(t *testing.T) {
		mgr := &EncryptionKeyManager{
			RootPrivateKey: rootKey,
			RootKeyID:      "did:dht:owner#enc",
			ProtocolURI:    "https://example.com/proto",
		}

		// Store a custom key (different from derived).
		customKey := make([]byte, 32)
		for i := range customKey {
			customKey[i] = 0xFF
		}
		mgr.StoreContextKey("ctx-stored", customKey)

		key, err := mgr.DeriveContextDecryptionKey("ctx-stored")
		if err != nil {
			t.Fatal(err)
		}

		// Should be the stored key, not the derived one.
		for i := range customKey {
			if key[i] != customKey[i] {
				t.Fatalf("expected stored key, got derived at byte %d", i)
			}
		}
	})

	t.Run("DeriveContextWriteEncryption produces valid inputs", func(t *testing.T) {
		mgr := &EncryptionKeyManager{
			RootPrivateKey: rootKey,
			RootKeyID:      "did:dht:owner#enc",
			ProtocolURI:    "https://example.com/proto",
		}

		inputs, err := mgr.DeriveContextWriteEncryption("ctx-abc")
		if err != nil {
			t.Fatal(err)
		}
		if len(inputs) != 1 {
			t.Fatalf("expected 1 input, got %d", len(inputs))
		}
		if inputs[0].DerivationScheme != DerivationSchemeProtocolContext {
			t.Errorf("DerivationScheme = %q, want %q", inputs[0].DerivationScheme, DerivationSchemeProtocolContext)
		}
		if len(inputs[0].PublicKey) != 32 {
			t.Errorf("PublicKey length = %d, want 32", len(inputs[0].PublicKey))
		}
	})

	t.Run("DeriveContextKeyJwk on manager", func(t *testing.T) {
		mgr := &EncryptionKeyManager{
			RootPrivateKey: rootKey,
			RootKeyID:      "did:dht:owner#enc",
			ProtocolURI:    "https://example.com/proto",
		}

		dpk, err := mgr.DeriveContextKeyJwk("ctx-xyz")
		if err != nil {
			t.Fatal(err)
		}
		if dpk.RootKeyID != mgr.RootKeyID {
			t.Errorf("RootKeyID = %q", dpk.RootKeyID)
		}

		// Non-owner should fail.
		mgrNonOwner := &EncryptionKeyManager{
			RootKeyID:   "did:dht:other#enc",
			ProtocolURI: "https://example.com/proto",
		}
		_, err = mgrNonOwner.DeriveContextKeyJwk("ctx-xyz")
		if err == nil {
			t.Error("expected error for non-owner")
		}
	})

	t.Run("HasContextKey and GetContextKey", func(t *testing.T) {
		mgr := &EncryptionKeyManager{
			RootKeyID:   "did:dht:test#enc",
			ProtocolURI: "https://example.com/proto",
		}

		if mgr.HasContextKey("ctx-1") {
			t.Error("expected false before storing")
		}
		if mgr.GetContextKey("ctx-1") != nil {
			t.Error("expected nil before storing")
		}

		mgr.StoreContextKey("ctx-1", make([]byte, 32))

		if !mgr.HasContextKey("ctx-1") {
			t.Error("expected true after storing")
		}
		if mgr.GetContextKey("ctx-1") == nil {
			t.Error("expected non-nil after storing")
		}
	})
}

func TestContextEncryptionRoundTrip(t *testing.T) {
	t.Run("encrypt with context key, decrypt with same key", func(t *testing.T) {
		rootKey := make([]byte, 32)
		for i := range rootKey {
			rootKey[i] = byte(i + 42)
		}
		contextID := "bafyrei-test-context"

		// Owner derives context key and builds write encryption inputs.
		ownerMgr := &EncryptionKeyManager{
			RootPrivateKey: rootKey,
			RootKeyID:      "did:dht:owner#enc",
			ProtocolURI:    "https://example.com/proto",
		}

		inputs, err := ownerMgr.DeriveContextWriteEncryption(contextID)
		if err != nil {
			t.Fatal(err)
		}

		// Encrypt some data.
		plaintext := []byte(`{"message":"hello from context encryption"}`)
		ciphertext, enc, err := EncryptData(plaintext, inputs)
		if err != nil {
			t.Fatal(err)
		}

		// Verify the JWE has protocolContext scheme.
		if len(enc.Recipients) != 1 {
			t.Fatalf("expected 1 recipient, got %d", len(enc.Recipients))
		}
		if enc.Recipients[0].Header.DerivationScheme != DerivationSchemeProtocolContext {
			t.Errorf("scheme = %q, want %q", enc.Recipients[0].Header.DerivationScheme, DerivationSchemeProtocolContext)
		}
		// Protocol Context should include derivedPublicKey.
		if enc.Recipients[0].Header.DerivedPublicKey == nil {
			t.Error("expected derivedPublicKey for protocolContext scheme")
		}

		// Owner decrypts (derives from root).
		contextPrivKey, err := ownerMgr.DeriveContextDecryptionKey(contextID)
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := DecryptDataWithScheme(ciphertext, enc, contextPrivKey, DerivationSchemeProtocolContext)
		if err != nil {
			t.Fatal(err)
		}
		if string(decrypted) != string(plaintext) {
			t.Errorf("decrypted = %q, want %q", string(decrypted), string(plaintext))
		}

		// Non-owner with delivered key also decrypts.
		deliveredKey, err := DeriveContextKey(rootKey, contextID)
		if err != nil {
			t.Fatal(err)
		}

		peerMgr := &EncryptionKeyManager{
			RootKeyID:   "did:dht:peer#enc",
			ProtocolURI: "https://example.com/proto",
		}
		peerMgr.StoreContextKey(contextID, deliveredKey)

		peerPrivKey, err := peerMgr.DeriveContextDecryptionKey(contextID)
		if err != nil {
			t.Fatal(err)
		}
		decryptedByPeer, err := DecryptDataWithScheme(ciphertext, enc, peerPrivKey, DerivationSchemeProtocolContext)
		if err != nil {
			t.Fatalf("peer decryption failed: %v", err)
		}
		if string(decryptedByPeer) != string(plaintext) {
			t.Errorf("peer decrypted = %q, want %q", string(decryptedByPeer), string(plaintext))
		}
	})
}

func TestKeyDeliveryProtocolEncryptionInjection(t *testing.T) {
	t.Run("key-delivery protocol accepts encryption injection", func(t *testing.T) {
		rootKey := make([]byte, 32)
		for i := range rootKey {
			rootKey[i] = byte(i)
		}

		protoJSON := []byte(`{
			"protocol": "https://identity.foundation/protocols/key-delivery",
			"published": false,
			"types": {
				"contextKey": {
					"dataFormats": ["application/json"]
				}
			},
			"structure": {
				"contextKey": {
					"$actions": [
						{ "who": "recipient", "of": "contextKey", "can": ["read"] }
					]
				}
			}
		}`)

		result, err := InjectEncryptionDirectives(protoJSON, rootKey, "did:dht:test#enc")
		if err != nil {
			t.Fatal(err)
		}

		var parsed map[string]any
		if err := json.Unmarshal(result, &parsed); err != nil {
			t.Fatal(err)
		}

		structure := parsed["structure"].(map[string]any)
		contextKey := structure["contextKey"].(map[string]any)
		encryption, ok := contextKey["$encryption"].(map[string]any)
		if !ok {
			t.Fatal("$encryption not found on contextKey")
		}

		if encryption["rootKeyId"] != "did:dht:test#enc" {
			t.Errorf("rootKeyId = %v", encryption["rootKeyId"])
		}
		pubJwk := encryption["publicKeyJwk"].(map[string]any)
		if pubJwk["kty"] != "OKP" {
			t.Errorf("kty = %v", pubJwk["kty"])
		}
		if pubJwk["crv"] != "X25519" {
			t.Errorf("crv = %v", pubJwk["crv"])
		}
		if pubJwk["x"] == "" || pubJwk["x"] == nil {
			t.Error("x is empty")
		}
	})
}
