package crypto

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// These tests are the correctness gate for the encryption-v1 migration. Both
// fixtures are genuine @enbox SDK output; the decrypters must recover the
// SDK plaintext byte-for-byte.

func b64urlBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		if b, err = base64.URLEncoding.DecodeString(s); err != nil {
			t.Fatalf("base64url decode %q: %v", s, err)
		}
	}
	return b
}

func b64stdBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 std decode: %v", err)
	}
	return b
}

func TestEncryptionV1ProtocolPathFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/v1/protocolpath.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var fx struct {
		DerivationPath         []string `json:"derivationPath"`
		ReaderEncPrivateKeyJwk struct {
			D string `json:"d"`
		} `json:"readerEncPrivateKeyJwk"`
		RecordMessage struct {
			Encryption Encryption `json:"encryption"`
		} `json:"recordMessage"`
		CiphertextB64        string `json:"ciphertext_b64"`
		ExpectedPlaintextB64 string `json:"expectedPlaintext_b64"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	root := b64urlBytes(t, fx.ReaderEncPrivateKeyJwk.D)
	leafPriv, err := DeriveKeyBytes(root, fx.DerivationPath)
	if err != nil {
		t.Fatalf("DeriveKeyBytes: %v", err)
	}

	plaintext, err := DecryptData(
		b64stdBytes(t, fx.CiphertextB64),
		&fx.RecordMessage.Encryption,
		leafPriv,
	)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	want := b64stdBytes(t, fx.ExpectedPlaintextB64)
	if string(plaintext) != string(want) {
		t.Fatalf("plaintext mismatch:\n got=%s\nwant=%s", plaintext, want)
	}
}

func TestEncryptionV1RoleAudienceFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/v1/roleaudience.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var fx struct {
		NodeEncPrivateKeyJwk struct {
			D string `json:"d"`
		} `json:"nodeEncPrivateKeyJwk"`
		MeshRecordMessage struct {
			Encryption Encryption `json:"encryption"`
		} `json:"meshRecordMessage"`
		MeshCiphertextB64        string `json:"meshCiphertext_b64"`
		ExpectedPlaintextB64     string `json:"expectedPlaintext_b64"`
		AudienceKeyRecordMessage struct {
			Encryption Encryption `json:"encryption"`
		} `json:"audienceKeyRecordMessage"`
		AudienceKeyCiphertextB64    string `json:"audienceKeyCiphertext_b64"`
		AudienceKeyPayloadDecrypted struct {
			PrivateKeyJwk struct {
				D string `json:"d"`
			} `json:"privateKeyJwk"`
		} `json:"audienceKeyPayload_decrypted"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	nodeRoot := b64urlBytes(t, fx.NodeEncPrivateKeyJwk.D)

	plaintext, err := DecryptRoleAudienceRecord(RoleAudienceParams{
		MeshEncryption:        &fx.MeshRecordMessage.Encryption,
		MeshCiphertext:        b64stdBytes(t, fx.MeshCiphertextB64),
		NodeEncRootKey:        nodeRoot,
		AudienceKeyEncryption: &fx.AudienceKeyRecordMessage.Encryption,
		AudienceKeyCiphertext: b64stdBytes(t, fx.AudienceKeyCiphertextB64),
	})
	if err != nil {
		t.Fatalf("DecryptRoleAudienceRecord: %v", err)
	}

	want := b64stdBytes(t, fx.ExpectedPlaintextB64)
	if string(plaintext) != string(want) {
		t.Fatalf("plaintext mismatch:\n got=%s\nwant=%s", plaintext, want)
	}

	// Sanity: the intermediate audienceKey decryption recovers the SDK's
	// audience private key.
	payload, err := DecryptAudienceKeyRecord(
		nodeRoot,
		RoleAudienceEntryInfo(&fx.MeshRecordMessage.Encryption).Protocol,
		RoleAudienceEntryInfo(&fx.MeshRecordMessage.Encryption).Role,
		&fx.AudienceKeyRecordMessage.Encryption,
		b64stdBytes(t, fx.AudienceKeyCiphertextB64),
	)
	if err != nil {
		t.Fatalf("DecryptAudienceKeyRecord: %v", err)
	}
	if payload.PrivateKeyJwk.D != fx.AudienceKeyPayloadDecrypted.PrivateKeyJwk.D {
		t.Fatalf("audience private key mismatch:\n got=%s\nwant=%s",
			payload.PrivateKeyJwk.D, fx.AudienceKeyPayloadDecrypted.PrivateKeyJwk.D)
	}
}
