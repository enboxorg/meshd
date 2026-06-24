package mesh

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/protocols"
)

func TestContextKeyMatchesContext(t *testing.T) {
	keyForNetwork := &dwncrypto.DerivedPrivateJwk{
		DerivationScheme: dwncrypto.DerivationSchemeProtocolContext,
		DerivationPath:   dwncrypto.BuildProtocolContextDerivation("network-1"),
	}

	tests := []struct {
		name      string
		key       *dwncrypto.DerivedPrivateJwk
		contextID string
		want      bool
	}{
		{
			name:      "empty expected context accepts key",
			key:       keyForNetwork,
			contextID: "",
			want:      true,
		},
		{
			name:      "matching protocol context",
			key:       keyForNetwork,
			contextID: "network-1",
			want:      true,
		},
		{
			name:      "different network context",
			key:       keyForNetwork,
			contextID: "network-2",
			want:      false,
		},
		{
			name: "wrong derivation scheme",
			key: &dwncrypto.DerivedPrivateJwk{
				DerivationScheme: dwncrypto.DerivationSchemeProtocolPath,
				DerivationPath:   []string{dwncrypto.DerivationSchemeProtocolPath, "protocol", "contextKey"},
			},
			contextID: "network-1",
			want:      false,
		},
		{
			name:      "nil key",
			key:       nil,
			contextID: "network-1",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := contextKeyMatchesContext(tt.key, tt.contextID); got != tt.want {
				t.Fatalf("contextKeyMatchesContext() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeliverableContextKeyJwkUsesCachedContextKey(t *testing.T) {
	contextID := "network-1"
	contextKey := bytes.Repeat([]byte{0x7a}, 32)
	mgr := &dwncrypto.EncryptionKeyManager{
		RootKeyID:   "did:jwk:node#enc",
		ProtocolURI: "https://enbox.id/protocols/wireguard-mesh",
	}
	mgr.StoreContextKey(contextID, contextKey)

	got, err := deliverableContextKeyJwk(mgr, contextID)
	if err != nil {
		t.Fatalf("deliverableContextKeyJwk: %v", err)
	}
	if got.RootKeyID != mgr.RootKeyID {
		t.Fatalf("root key id = %q, want %q", got.RootKeyID, mgr.RootKeyID)
	}
	if got.DerivationScheme != dwncrypto.DerivationSchemeProtocolContext {
		t.Fatalf("derivation scheme = %q", got.DerivationScheme)
	}
	gotKey, err := got.PrivateKeyBytes()
	if err != nil {
		t.Fatalf("PrivateKeyBytes: %v", err)
	}
	if !bytes.Equal(gotKey, contextKey) {
		t.Fatalf("context key mismatch")
	}
}

func TestDeliverableContextKeyJwkPrefersCachedContextKeyOverLocalRoot(t *testing.T) {
	contextID := "network-1"
	contextKey := bytes.Repeat([]byte{0x5c}, 32)
	rootKey, _, err := dwncrypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	mgr := &dwncrypto.EncryptionKeyManager{
		RootPrivateKey: rootKey,
		RootKeyID:      "did:jwk:node#enc",
		ProtocolURI:    "https://enbox.id/protocols/wireguard-mesh",
	}
	mgr.StoreContextKey(contextID, contextKey)

	got, err := deliverableContextKeyJwk(mgr, contextID)
	if err != nil {
		t.Fatalf("deliverableContextKeyJwk: %v", err)
	}
	gotKey, err := got.PrivateKeyBytes()
	if err != nil {
		t.Fatalf("PrivateKeyBytes: %v", err)
	}
	if !bytes.Equal(gotKey, contextKey) {
		t.Fatalf("derived from local root instead of cached context key")
	}
}

func TestDeliverableContextKeyJwkRequiresOwnerOrCachedKey(t *testing.T) {
	mgr := &dwncrypto.EncryptionKeyManager{
		RootKeyID:   "did:jwk:node#enc",
		ProtocolURI: "https://enbox.id/protocols/wireguard-mesh",
	}
	if _, err := deliverableContextKeyJwk(mgr, "network-1"); err == nil {
		t.Fatal("expected missing cached context key to fail")
	}
}

func TestKeyDeliveryEncryptionRecipients(t *testing.T) {
	rootKeyID := "did:jwk:node#enc"
	rootKey, _, err := dwncrypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	public, err := dwncrypto.NewKeyDeliveryPublic(rootKey, rootKeyID, protocols.KeyDeliveryProtocolURI)
	if err != nil {
		t.Fatalf("NewKeyDeliveryPublic: %v", err)
	}

	recipients, err := keyDeliveryEncryptionRecipients(public)
	if err != nil {
		t.Fatalf("keyDeliveryEncryptionRecipients: %v", err)
	}
	if len(recipients) != 1 {
		t.Fatalf("recipients len = %d, want 1", len(recipients))
	}
	if recipients[0].PublicKeyID != rootKeyID {
		t.Fatalf("PublicKeyID = %q, want %q", recipients[0].PublicKeyID, rootKeyID)
	}
	if recipients[0].DerivationScheme != dwncrypto.DerivationSchemeProtocolPath {
		t.Fatalf("DerivationScheme = %q", recipients[0].DerivationScheme)
	}
	if len(recipients[0].PublicKey) == 0 {
		t.Fatal("PublicKey is empty")
	}

	recipients, err = keyDeliveryEncryptionRecipients(nil)
	if err != nil {
		t.Fatalf("nil key delivery should not fail: %v", err)
	}
	if recipients != nil {
		t.Fatalf("nil key delivery recipients = %+v, want nil", recipients)
	}
}

func TestParseContextKeyRecordDataPlaintext(t *testing.T) {
	contextID := "network-1"
	contextKey := bytes.Repeat([]byte{0x3a}, 32)
	want, err := dwncrypto.NewDerivedPrivateJwk(
		"did:jwk:wallet#enc",
		dwncrypto.DerivationSchemeProtocolContext,
		dwncrypto.BuildProtocolContextDerivation(contextID),
		contextKey,
	)
	if err != nil {
		t.Fatalf("NewDerivedPrivateJwk: %v", err)
	}
	payload, err := want.MarshalPayload()
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}

	got, err := parseContextKeyRecordData(nil, payload, nil)
	if err != nil {
		t.Fatalf("parseContextKeyRecordData: %v", err)
	}
	if !contextKeyMatchesContext(got, contextID) {
		t.Fatal("parsed key does not match context")
	}
}

func TestParseContextKeyRecordDataDecryptsWalletEncryptedRecord(t *testing.T) {
	contextID := "network-1"
	nodeRootKeyID := "did:jwk:node#enc"
	nodeRootKey, _, err := dwncrypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	nodeEncMgr := &dwncrypto.EncryptionKeyManager{
		RootPrivateKey: nodeRootKey,
		RootKeyID:      nodeRootKeyID,
		ProtocolURI:    protocols.MeshProtocolURI,
	}

	contextKey := bytes.Repeat([]byte{0x4b}, 32)
	delivered, err := dwncrypto.NewDerivedPrivateJwk(
		"did:jwk:wallet#enc",
		dwncrypto.DerivationSchemeProtocolContext,
		dwncrypto.BuildProtocolContextDerivation(contextID),
		contextKey,
	)
	if err != nil {
		t.Fatalf("NewDerivedPrivateJwk: %v", err)
	}
	plaintext, err := delivered.MarshalPayload()
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}

	publicJWK, err := dwncrypto.DeriveKeyDeliveryPublicJWK(nodeRootKey, nodeRootKeyID, protocols.KeyDeliveryProtocolURI)
	if err != nil {
		t.Fatalf("DeriveKeyDeliveryPublicJWK: %v", err)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(publicJWK.X)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	ciphertext, enc, err := dwncrypto.EncryptData(plaintext, []dwncrypto.KeyEncryptionInput{
		{
			PublicKeyID:      nodeRootKeyID,
			PublicKey:        publicKey,
			DerivationScheme: dwncrypto.DerivationSchemeProtocolPath,
		},
	})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	rawEntry, err := json.Marshal(map[string]any{
		"recordsWrite": map[string]any{"encryption": enc},
	})
	if err != nil {
		t.Fatalf("Marshal rawEntry: %v", err)
	}

	got, err := parseContextKeyRecordData(rawEntry, ciphertext, nodeEncMgr)
	if err != nil {
		t.Fatalf("parseContextKeyRecordData: %v", err)
	}
	gotKey, err := got.PrivateKeyBytes()
	if err != nil {
		t.Fatalf("PrivateKeyBytes: %v", err)
	}
	if !bytes.Equal(gotKey, contextKey) {
		t.Fatal("decrypted context key mismatch")
	}
	if !contextKeyMatchesContext(got, contextID) {
		t.Fatal("decrypted key does not match context")
	}

	if _, err := parseContextKeyRecordData(rawEntry, ciphertext, nil); err == nil {
		t.Fatal("expected encrypted contextKey to require an encryption key manager")
	}
}
