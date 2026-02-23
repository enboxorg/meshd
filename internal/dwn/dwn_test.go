package dwn

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
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
		msg, err := BuildRecordsWrite(s, RecordsWriteOptions{
			Protocol:     "https://enbox.org/protocols/wireguard-mesh",
			ProtocolPath: "network",
			Schema:       "https://enbox.org/schemas/wireguard-mesh/network",
			DataFormat:   "application/json",
			Data:         []byte(`{"name":"test-net","meshCIDR":"10.200.0.0/16"}`),
		})
		if err != nil {
			t.Fatalf("BuildRecordsWrite: %v", err)
		}

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
		if msg.EncodedData == "" {
			t.Error("missing encodedData for small payload")
		}
	})

	t.Run("extended signature payload", func(t *testing.T) {
		msg, _ := BuildRecordsWrite(s, RecordsWriteOptions{
			Protocol:     "https://example.com/test",
			ProtocolPath: "root",
			DataFormat:   "application/json",
			Data:         []byte(`{}`),
		})

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
		initial, _ := BuildRecordsWrite(s, RecordsWriteOptions{
			Protocol:     "https://example.com/test",
			ProtocolPath: "root",
			DataFormat:   "application/json",
			Data:         []byte(`{"v":1}`),
		})
		update, _ := BuildRecordsWrite(s, RecordsWriteOptions{
			Protocol:     "https://example.com/test",
			ProtocolPath: "root",
			DataFormat:   "application/json",
			Data:         []byte(`{"v":2}`),
			RecordID:     initial.RecordID,
			ContextID:    initial.ContextID,
		})
		if update.RecordID != initial.RecordID {
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
	msg, err := BuildRecordsWrite(s, RecordsWriteOptions{
		Protocol:     "https://example.com/test",
		ProtocolPath: "root",
		DataFormat:   "application/json",
		Data:         []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("BuildRecordsWrite: %v", err)
	}

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
