package dwn

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	dwncrypto "github.com/enboxorg/dwn-mesh/internal/dwn/crypto"
)

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return &Signer{
		DID:        "did:dht:test123",
		PrivateKey: priv,
	}
}

func TestComputeCID(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		cid1, err := ComputeCID(map[string]any{})
		if err != nil {
			t.Fatalf("ComputeCID: %v", err)
		}
		cid2, err := ComputeCID(map[string]any{})
		if err != nil {
			t.Fatalf("ComputeCID: %v", err)
		}
		if cid1 != cid2 {
			t.Errorf("CIDs differ for identical input: %q vs %q", cid1, cid2)
		}
	})

	t.Run("CIDv1 format", func(t *testing.T) {
		cid, err := ComputeCID(map[string]any{})
		if err != nil {
			t.Fatalf("ComputeCID: %v", err)
		}
		if !strings.HasPrefix(cid, "bafy") {
			t.Errorf("CID = %q, want bafy... prefix (base32lower CIDv1)", cid)
		}
	})

	t.Run("different inputs produce different CIDs", func(t *testing.T) {
		cid1, _ := ComputeCID(map[string]any{})
		cid2, _ := ComputeCID(map[string]any{"key": "value"})
		if cid1 == cid2 {
			t.Error("different inputs produced same CID")
		}
	})

	t.Run("field order does not matter", func(t *testing.T) {
		// DAG-CBOR canonicalizes map keys, so insertion order shouldn't matter.
		cid1, _ := ComputeCID(map[string]any{"a": 1, "b": 2})
		cid2, _ := ComputeCID(map[string]any{"b": 2, "a": 1})
		if cid1 != cid2 {
			t.Errorf("field order affected CID: %q vs %q", cid1, cid2)
		}
	})

	t.Run("float64 integers normalized to int64", func(t *testing.T) {
		// Go's json.Unmarshal produces float64 for JSON numbers.
		// The JS DAG-CBOR encoder treats integer-valued numbers as CBOR integers.
		// Our normalization must ensure the CIDs match.
		cidFromInt, _ := ComputeCID(map[string]any{"max": int64(10000)})
		cidFromFloat, _ := ComputeCID(map[string]any{"max": float64(10000)})
		if cidFromInt != cidFromFloat {
			t.Errorf("int64 vs float64 produced different CIDs: %q vs %q", cidFromInt, cidFromFloat)
		}
	})

	t.Run("nested float64 integers normalized", func(t *testing.T) {
		// Simulate a protocol definition with nested numeric fields like $size.max.
		nested := map[string]any{
			"structure": map[string]any{
				"node": map[string]any{
					"$size":        map[string]any{"max": float64(10000)},
					"$recordLimit": map[string]any{"max": float64(1)},
				},
			},
		}
		explicit := map[string]any{
			"structure": map[string]any{
				"node": map[string]any{
					"$size":        map[string]any{"max": int64(10000)},
					"$recordLimit": map[string]any{"max": int64(1)},
				},
			},
		}
		cidNested, _ := ComputeCID(nested)
		cidExplicit, _ := ComputeCID(explicit)
		if cidNested != cidExplicit {
			t.Errorf("nested normalization failed: %q vs %q", cidNested, cidExplicit)
		}
	})

	t.Run("non-integer floats preserved", func(t *testing.T) {
		cidFloat, _ := ComputeCID(map[string]any{"val": float64(3.14)})
		cidInt, _ := ComputeCID(map[string]any{"val": int64(3)})
		if cidFloat == cidInt {
			t.Error("non-integer float should produce different CID than int")
		}
	})
}

func TestComputeDataCID(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		data := []byte(`{"hello":"world"}`)
		cid1, _ := ComputeDataCID(data)
		cid2, _ := ComputeDataCID(data)
		if cid1 != cid2 {
			t.Errorf("data CIDs differ: %q vs %q", cid1, cid2)
		}
	})

	t.Run("different data produces different CIDs", func(t *testing.T) {
		cid1, _ := ComputeDataCID([]byte("a"))
		cid2, _ := ComputeDataCID([]byte("b"))
		if cid1 == cid2 {
			t.Error("different data produced same CID")
		}
	})
}

func TestSignJWS(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)

	payload := map[string]string{"descriptorCid": "bafy123"}
	kid := "did:dht:test#0"

	jws, err := SignJWS(payload, kid, priv)
	if err != nil {
		t.Fatalf("SignJWS: %v", err)
	}

	t.Run("single signature", func(t *testing.T) {
		if len(jws.Signatures) != 1 {
			t.Fatalf("expected 1 signature, got %d", len(jws.Signatures))
		}
	})

	t.Run("payload decodable", func(t *testing.T) {
		payloadBytes, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			t.Fatalf("decoding payload: %v", err)
		}
		var decoded map[string]string
		if err := json.Unmarshal(payloadBytes, &decoded); err != nil {
			t.Fatalf("unmarshaling payload: %v", err)
		}
		if decoded["descriptorCid"] != "bafy123" {
			t.Errorf("descriptorCid = %q", decoded["descriptorCid"])
		}
	})

	t.Run("protected header", func(t *testing.T) {
		headerBytes, _ := base64.RawURLEncoding.DecodeString(jws.Signatures[0].Protected)
		var header map[string]string
		json.Unmarshal(headerBytes, &header)
		if header["alg"] != "EdDSA" {
			t.Errorf("alg = %q, want EdDSA", header["alg"])
		}
		if header["kid"] != kid {
			t.Errorf("kid = %q, want %q", header["kid"], kid)
		}
	})

	t.Run("signature verifies", func(t *testing.T) {
		sigInput := jws.Signatures[0].Protected + "." + jws.Payload
		sigBytes, _ := base64.RawURLEncoding.DecodeString(jws.Signatures[0].Signature)
		if !ed25519.Verify(pub, []byte(sigInput), sigBytes) {
			t.Error("JWS signature verification failed")
		}
	})
}

func TestBuildRecordsWrite(t *testing.T) {
	s := newTestSigner(t)

	t.Run("initial write", func(t *testing.T) {
		result, err := BuildRecordsWrite(s, RecordsWriteOptions{
			Protocol:     "https://enbox.org/protocols/wireguard-mesh",
			ProtocolPath: "network",
			Schema:       "https://enbox.org/schemas/wireguard-mesh/network",
			DataFormat:   "application/json",
			Data:         []byte(`{"name":"test-net","meshCIDR":"10.200.0.0/16"}`),
		})
		if err != nil {
			t.Fatalf("BuildRecordsWrite: %v", err)
		}
		msg := result.Message

		if msg.RecordID == "" {
			t.Error("missing record ID")
		}
		if msg.ContextID != msg.RecordID {
			t.Errorf("root contextId = %q, want %q", msg.ContextID, msg.RecordID)
		}
		if msg.Descriptor["interface"] != "Records" {
			t.Errorf("interface = %v", msg.Descriptor["interface"])
		}
		if msg.Descriptor["method"] != "Write" {
			t.Errorf("method = %v", msg.Descriptor["method"])
		}
		if msg.Authorization == nil || msg.Authorization.Signature == nil {
			t.Fatal("missing authorization")
		}
		if msg.EncodedData != "" {
			t.Error("encodedData should not be set on writes (data goes in HTTP body)")
		}
	})

	t.Run("extended signature payload", func(t *testing.T) {
		result, _ := BuildRecordsWrite(s, RecordsWriteOptions{
			Protocol:     "https://example.com/test",
			ProtocolPath: "root",
			DataFormat:   "application/json",
			Data:         []byte(`{}`),
		})
		msg := result.Message

		// Decode the JWS payload and verify it has recordId and contextId.
		payloadBytes, _ := base64.RawURLEncoding.DecodeString(msg.Authorization.Signature.Payload)
		var payload map[string]any
		json.Unmarshal(payloadBytes, &payload)

		if _, ok := payload["recordId"]; !ok {
			t.Error("RecordsWrite signature payload missing recordId")
		}
		if _, ok := payload["descriptorCid"]; !ok {
			t.Error("RecordsWrite signature payload missing descriptorCid")
		}
	})

	t.Run("missing protocol returns error", func(t *testing.T) {
		_, err := BuildRecordsWrite(s, RecordsWriteOptions{
			DataFormat: "application/json",
			Data:       []byte(`{}`),
		})
		if err == nil {
			t.Error("expected error for missing protocol")
		}
	})

	t.Run("update preserves record ID", func(t *testing.T) {
		initialResult, _ := BuildRecordsWrite(s, RecordsWriteOptions{
			Protocol:     "https://example.com/test",
			ProtocolPath: "root",
			DataFormat:   "application/json",
			Data:         []byte(`{"v":1}`),
		})
		updateResult, _ := BuildRecordsWrite(s, RecordsWriteOptions{
			Protocol:     "https://example.com/test",
			ProtocolPath: "root",
			DataFormat:   "application/json",
			Data:         []byte(`{"v":2}`),
			RecordID:     initialResult.Message.RecordID,
			ContextID:    initialResult.Message.ContextID,
		})
		if updateResult.Message.RecordID != initialResult.Message.RecordID {
			t.Error("update should preserve record ID")
		}
	})
}

func TestBuildRecordsQuery(t *testing.T) {
	s := newTestSigner(t)

	msg, err := BuildRecordsQuery(s, RecordsFilter{
		Protocol:     "https://enbox.org/protocols/wireguard-mesh",
		ProtocolPath: "network/member",
	}, "createdAscending", nil, "network/member")
	if err != nil {
		t.Fatalf("BuildRecordsQuery: %v", err)
	}

	if msg.Descriptor["interface"] != "Records" || msg.Descriptor["method"] != "Query" {
		t.Errorf("interface/method = %v/%v", msg.Descriptor["interface"], msg.Descriptor["method"])
	}

	// Generic signature payload should NOT have recordId.
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(msg.Authorization.Signature.Payload)
	var payload map[string]any
	json.Unmarshal(payloadBytes, &payload)
	if _, ok := payload["recordId"]; ok {
		t.Error("RecordsQuery signature payload should not have recordId")
	}
}

func TestBuildRecordsDelete(t *testing.T) {
	s := newTestSigner(t)

	msg, err := BuildRecordsDelete(s, "bafy123", true, "")
	if err != nil {
		t.Fatalf("BuildRecordsDelete: %v", err)
	}

	if msg.Descriptor["interface"] != "Records" || msg.Descriptor["method"] != "Delete" {
		t.Error("wrong interface/method")
	}
	if msg.Descriptor["recordId"] != "bafy123" {
		t.Errorf("recordId = %v", msg.Descriptor["recordId"])
	}
	// prune is required and always present.
	if msg.Descriptor["prune"] != true {
		t.Errorf("prune = %v, want true", msg.Descriptor["prune"])
	}
}

func TestBuildProtocolsConfigure(t *testing.T) {
	s := newTestSigner(t)

	def := json.RawMessage(`{"protocol":"https://example.com/test","published":true,"types":{},"structure":{}}`)
	msg, err := BuildProtocolsConfigure(s, def)
	if err != nil {
		t.Fatalf("BuildProtocolsConfigure: %v", err)
	}

	if msg.Descriptor["interface"] != "Protocols" || msg.Descriptor["method"] != "Configure" {
		t.Error("wrong interface/method")
	}
	if msg.Descriptor["definition"] == nil {
		t.Error("missing definition")
	}
}

func TestBuildProtocolsQuery(t *testing.T) {
	s := newTestSigner(t)

	msg, err := BuildProtocolsQuery(s, "https://example.com/test")
	if err != nil {
		t.Fatalf("BuildProtocolsQuery: %v", err)
	}

	if msg.Descriptor["interface"] != "Protocols" || msg.Descriptor["method"] != "Query" {
		t.Error("wrong interface/method")
	}
}

func TestTimestamp(t *testing.T) {
	ts := Now()
	expected := len("2006-01-02T15:04:05.000000Z")
	if len(ts) != expected {
		t.Errorf("timestamp length = %d, want %d: %q", len(ts), expected, ts)
	}
	if ts[len(ts)-1] != 'Z' {
		t.Errorf("timestamp should end with Z: %q", ts)
	}
	if ts[10] != 'T' {
		t.Errorf("timestamp should have T separator: %q", ts)
	}
}

func TestHTTPToWS(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"http":    {input: "http://localhost:8787", want: "ws://localhost:8787"},
		"https":   {input: "https://dwn.example.com", want: "wss://dwn.example.com"},
		"already": {input: "ws://already.ws", want: "ws://already.ws"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := httpToWS(tc.input)
			if got != tc.want {
				t.Errorf("httpToWS(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestDescriptorOmitsZeroFields(t *testing.T) {
	s := newTestSigner(t)

	// Build a message with minimal fields — optional fields should be absent.
	result, err := BuildRecordsWrite(s, RecordsWriteOptions{
		Protocol:     "https://example.com/test",
		ProtocolPath: "root",
		DataFormat:   "application/json",
		Data:         []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("BuildRecordsWrite: %v", err)
	}
	msg := result.Message

	// Optional fields like schema, recipient, tags should NOT be in the descriptor.
	if _, ok := msg.Descriptor["schema"]; ok {
		t.Error("empty schema should be omitted from descriptor")
	}
	if _, ok := msg.Descriptor["recipient"]; ok {
		t.Error("empty recipient should be omitted from descriptor")
	}
	if _, ok := msg.Descriptor["tags"]; ok {
		t.Error("empty tags should be omitted from descriptor")
	}
	if _, ok := msg.Descriptor["parentId"]; ok {
		t.Error("empty parentId should be omitted from descriptor")
	}
	if _, ok := msg.Descriptor["published"]; ok {
		t.Error("nil published should be omitted from descriptor")
	}
}

func TestBuildRecordsWriteEncrypted(t *testing.T) {
	s := newTestSigner(t)
	plaintext := []byte(`{"name":"encrypted-network","cidr":"10.200.0.0/24"}`)

	// Generate recipient key pair.
	recipientPriv, recipientPub, err := dwncrypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	kid := "did:dht:recipient#enc-1"
	result, err := BuildRecordsWrite(s, RecordsWriteOptions{
		Protocol:     "https://enbox.org/protocols/wireguard-mesh",
		ProtocolPath: "network",
		DataFormat:   "application/json",
		Data:         plaintext,
		EncryptionRecipients: []dwncrypto.KeyEncryptionInput{{
			PublicKeyID:      kid,
			PublicKey:        recipientPub,
			DerivationScheme: dwncrypto.DerivationSchemeProtocolPath,
		}},
	})
	if err != nil {
		t.Fatalf("BuildRecordsWrite: %v", err)
	}
	msg := result.Message

	t.Run("encryption property is set", func(t *testing.T) {
		if msg.Encryption == nil {
			t.Fatal("encryption property should be set")
		}
		if len(msg.Encryption.Recipients) != 1 {
			t.Fatalf("recipients = %d, want 1", len(msg.Encryption.Recipients))
		}
		if msg.Encryption.Recipients[0].Header.KID != kid {
			t.Errorf("kid = %q, want %q", msg.Encryption.Recipients[0].Header.KID, kid)
		}
	})

	t.Run("wire data is ciphertext not plaintext", func(t *testing.T) {
		if bytes.Equal(result.WireData, plaintext) {
			t.Fatal("wire data should be ciphertext, not plaintext")
		}
		if len(result.WireData) == 0 {
			t.Fatal("wire data should not be empty")
		}
	})

	t.Run("encodedData not set on writes", func(t *testing.T) {
		if msg.EncodedData != "" {
			t.Fatal("encodedData should not be set on writes (data goes in HTTP body)")
		}
	})

	t.Run("wireData contains ciphertext", func(t *testing.T) {
		decoded := result.WireData
		if bytes.Equal(decoded, plaintext) {
			t.Fatal("wireData should contain ciphertext, not plaintext")
		}
	})

	t.Run("encryptionCid in signature payload", func(t *testing.T) {
		payloadBytes, _ := base64.RawURLEncoding.DecodeString(msg.Authorization.Signature.Payload)
		var payload map[string]any
		json.Unmarshal(payloadBytes, &payload)

		if _, ok := payload["encryptionCid"]; !ok {
			t.Error("signature payload should contain encryptionCid")
		}
	})

	t.Run("ciphertext decrypts to plaintext", func(t *testing.T) {
		decrypted, err := dwncrypto.DecryptData(result.WireData, msg.Encryption, recipientPriv, kid)
		if err != nil {
			t.Fatalf("DecryptData: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatal("decrypted data mismatch")
		}
	})
}

func TestBuildRecordsWriteUnencrypted(t *testing.T) {
	s := newTestSigner(t)
	plaintext := []byte(`{"name":"unencrypted"}`)

	result, err := BuildRecordsWrite(s, RecordsWriteOptions{
		Protocol:     "https://example.com/test",
		ProtocolPath: "root",
		DataFormat:   "application/json",
		Data:         plaintext,
	})
	if err != nil {
		t.Fatalf("BuildRecordsWrite: %v", err)
	}

	// No encryption property.
	if result.Message.Encryption != nil {
		t.Fatal("unencrypted write should not have encryption property")
	}

	// Wire data is the plaintext.
	if !bytes.Equal(result.WireData, plaintext) {
		t.Fatal("wire data should be plaintext for unencrypted write")
	}

	// No encryptionCid in signature.
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(result.Message.Authorization.Signature.Payload)
	var payload map[string]any
	json.Unmarshal(payloadBytes, &payload)
	if _, ok := payload["encryptionCid"]; ok {
		t.Error("unencrypted write should not have encryptionCid")
	}
}
