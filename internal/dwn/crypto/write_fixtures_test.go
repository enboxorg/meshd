package crypto

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// TestEncryptionV1WriteRoleAudienceFixture is the correctness gate for the
// role-audience WRITE path. It drives BuildWriteEncryption + EncryptData from a
// genuine SDK fixture and asserts the produced record matches the SDK output
// structurally, then decrypts the Go output both ways (owner protocolPath key
// and role audience key) back to the SDK plaintext.
func TestEncryptionV1WriteRoleAudienceFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/v1/writeroleaudience.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var fx struct {
		Protocol                    string          `json:"protocol"`
		PlaintextB64                string          `json:"plaintext_b64"`
		InstalledProtocolDefinition json.RawMessage `json:"installedProtocolDefinition"`
		WriteTarget                 struct {
			ProtocolPath    string `json:"protocolPath"`
			ParentContextID string `json:"parentContextId"`
		} `json:"writeTarget"`
		AudienceEpochs []struct {
			Protocol     string       `json:"protocol"`
			ContextID    string       `json:"contextId"`
			Role         string       `json:"role"`
			Epoch        int          `json:"epoch"`
			KeyID        string       `json:"keyId"`
			PublicKeyJwk PublicKeyJWK `json:"publicKeyJwk"`
		} `json:"audienceEpochs"`
		AudiencePrivateKeysByRole map[string]PrivateKeyJWK `json:"audiencePrivateKeysByRole"`
		OwnerEncPrivateKeyJwk     PrivateKeyJWK            `json:"ownerEncPrivateKeyJwk"`
		SDKWrittenRecord          struct {
			Encryption Encryption `json:"encryption"`
		} `json:"sdkWrittenRecord"`
		SDKWrittenRoleAudienceEntry KeyEncryption `json:"sdkWrittenRoleAudienceEntry"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	// Build the write inputs from the installed protocol definition + the write
	// target, backed by an AudienceEpochSource over the fixture's epochs.
	source := &fixtureEpochSource{epochs: fx.AudienceEpochs}
	inputs, err := BuildWriteEncryption(
		fx.InstalledProtocolDefinition,
		fx.WriteTarget.ProtocolPath,
		fx.WriteTarget.ParentContextID,
		source,
	)
	if err != nil {
		t.Fatalf("BuildWriteEncryption: %v", err)
	}

	plaintext := b64stdBytes(t, fx.PlaintextB64)
	ciphertext, enc, err := EncryptData(plaintext, inputs)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	// --- Structural comparison against the genuine SDK record ---
	sdkEntries := fx.SDKWrittenRecord.Encryption.KeyEncryption
	if len(enc.KeyEncryption) != len(sdkEntries) {
		t.Fatalf("keyEncryption count = %d, want %d", len(enc.KeyEncryption), len(sdkEntries))
	}
	for i := range sdkEntries {
		if enc.KeyEncryption[i].DerivationScheme != sdkEntries[i].DerivationScheme {
			t.Fatalf("entry[%d] derivationScheme = %q, want %q",
				i, enc.KeyEncryption[i].DerivationScheme, sdkEntries[i].DerivationScheme)
		}
	}

	goPP := FindKeyEncryption(enc, DerivationSchemeProtocolPath)
	if goPP == nil {
		t.Fatal("Go output has no protocolPath entry")
	}
	sdkPP := findEntry(sdkEntries, DerivationSchemeProtocolPath)
	if sdkPP == nil {
		t.Fatal("SDK record has no protocolPath entry")
	}
	if goPP.KeyID != sdkPP.KeyID {
		t.Fatalf("protocolPath keyId = %q, want %q", goPP.KeyID, sdkPP.KeyID)
	}

	goRA := FindKeyEncryption(enc, DerivationSchemeRoleAudience)
	if goRA == nil {
		t.Fatal("Go output has no roleAudience entry")
	}
	if goRA.KeyID != fx.AudienceEpochs[0].KeyID {
		t.Fatalf("roleAudience keyId = %q, want %q (audienceEpochs[0])", goRA.KeyID, fx.AudienceEpochs[0].KeyID)
	}
	if goRA.KeyID != fx.SDKWrittenRoleAudienceEntry.KeyID {
		t.Fatalf("roleAudience keyId = %q, want %q (sdkWrittenRoleAudienceEntry)", goRA.KeyID, fx.SDKWrittenRoleAudienceEntry.KeyID)
	}
	if goRA.Protocol != fx.SDKWrittenRoleAudienceEntry.Protocol ||
		goRA.Role != fx.SDKWrittenRoleAudienceEntry.Role ||
		goRA.Epoch != fx.SDKWrittenRoleAudienceEntry.Epoch {
		t.Fatalf("roleAudience metadata = {protocol:%q role:%q epoch:%d}, want {protocol:%q role:%q epoch:%d}",
			goRA.Protocol, goRA.Role, goRA.Epoch,
			fx.SDKWrittenRoleAudienceEntry.Protocol, fx.SDKWrittenRoleAudienceEntry.Role, fx.SDKWrittenRoleAudienceEntry.Epoch)
	}

	// --- (a) Decrypt the protocolPath entry with the owner's #enc root ---
	ownerRoot := b64urlBytes(t, fx.OwnerEncPrivateKeyJwk.D)
	leafPath := BuildProtocolPathDerivation(fx.Protocol, splitProtocolPath(fx.WriteTarget.ProtocolPath)...)
	leafPriv, err := DeriveKeyBytes(ownerRoot, leafPath)
	if err != nil {
		t.Fatalf("DeriveKeyBytes(owner protocolPath leaf): %v", err)
	}
	ownerPlaintext, err := DecryptData(ciphertext, enc, leafPriv)
	if err != nil {
		t.Fatalf("DecryptData(protocolPath): %v", err)
	}
	if string(ownerPlaintext) != string(plaintext) {
		t.Fatalf("protocolPath decrypt mismatch:\n got=%s\nwant=%s", ownerPlaintext, plaintext)
	}

	// --- (b) Decrypt the roleAudience entry with the audience private key ---
	audJWK, ok := fx.AudiencePrivateKeysByRole[goRA.Role]
	if !ok {
		t.Fatalf("no audience private key for role %q", goRA.Role)
	}
	audPriv := b64urlBytes(t, audJWK.D)
	cek, err := unwrapEntry(goRA, audPriv)
	if err != nil {
		t.Fatalf("unwrapEntry(roleAudience): %v", err)
	}
	rolePlaintext, err := decryptContent(enc, cek, ciphertext)
	if err != nil {
		t.Fatalf("decryptContent(roleAudience): %v", err)
	}
	if string(rolePlaintext) != string(plaintext) {
		t.Fatalf("roleAudience decrypt mismatch:\n got=%s\nwant=%s", rolePlaintext, plaintext)
	}
}

// fixtureEpochSource is an AudienceEpochSource backed by the write fixture's
// audienceEpochs array. It returns the highest-epoch entry for a matching
// (protocol, contextId, role) tuple.
type fixtureEpochSource struct {
	epochs []struct {
		Protocol     string       `json:"protocol"`
		ContextID    string       `json:"contextId"`
		Role         string       `json:"role"`
		Epoch        int          `json:"epoch"`
		KeyID        string       `json:"keyId"`
		PublicKeyJwk PublicKeyJWK `json:"publicKeyJwk"`
	}
}

func (s *fixtureEpochSource) Latest(protocol, contextID, role string) ([]byte, int, string, error) {
	bestIdx := -1
	for i, e := range s.epochs {
		if e.Protocol != protocol || e.ContextID != contextID || e.Role != role {
			continue
		}
		if bestIdx == -1 || e.Epoch > s.epochs[bestIdx].Epoch {
			bestIdx = i
		}
	}
	if bestIdx == -1 {
		return nil, 0, "", fmt.Errorf("missing audienceEpoch for protocol=%q context=%q role=%q", protocol, contextID, role)
	}
	best := s.epochs[bestIdx]
	pub, err := base64URLDecode(best.PublicKeyJwk.X)
	if err != nil {
		return nil, 0, "", fmt.Errorf("decoding audienceEpoch publicKeyJwk.x: %w", err)
	}
	return pub, best.Epoch, best.KeyID, nil
}

func findEntry(entries []KeyEncryption, scheme string) *KeyEncryption {
	for i := range entries {
		if entries[i].DerivationScheme == scheme {
			return &entries[i]
		}
	}
	return nil
}
