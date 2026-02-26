package dwn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestRecordFromWrite(t *testing.T) {
	s := newTestSigner(t)

	result, err := BuildRecordsWrite(s, RecordsWriteOptions{
		Protocol:     "https://example.com/test",
		ProtocolPath: "root",
		Schema:       "https://example.com/schemas/root",
		DataFormat:   "application/json",
		Data:         []byte(`{"name":"test"}`),
		Recipient:    "did:dht:recipient123",
	})
	if err != nil {
		t.Fatalf("BuildRecordsWrite: %v", err)
	}
	msg := result.Message

	agent := NewSimpleAgent("http://localhost:8080", s)
	// After a write the caller has the wire data; encode it for the local Record.
	encoded := base64.RawURLEncoding.EncodeToString(result.WireData)
	record := RecordFromWrite(agent, s.DID, msg, encoded)

	t.Run("record ID", func(t *testing.T) {
		if record.ID == "" {
			t.Error("record ID should not be empty")
		}
		if record.ID != msg.RecordID {
			t.Errorf("ID = %q, want %q", record.ID, msg.RecordID)
		}
	})

	t.Run("protocol fields", func(t *testing.T) {
		if record.Protocol != "https://example.com/test" {
			t.Errorf("Protocol = %q", record.Protocol)
		}
		if record.ProtocolPath != "root" {
			t.Errorf("ProtocolPath = %q", record.ProtocolPath)
		}
		if record.Schema != "https://example.com/schemas/root" {
			t.Errorf("Schema = %q", record.Schema)
		}
	})

	t.Run("recipient", func(t *testing.T) {
		if record.Recipient != "did:dht:recipient123" {
			t.Errorf("Recipient = %q", record.Recipient)
		}
	})

	t.Run("data format", func(t *testing.T) {
		if record.DataFormat != "application/json" {
			t.Errorf("DataFormat = %q", record.DataFormat)
		}
	})

	t.Run("has inline data", func(t *testing.T) {
		if record.encodedData == "" {
			t.Error("should have inline encoded data for small payload")
		}
	})
}

func TestRecordDataLazyAccess(t *testing.T) {
	s := newTestSigner(t)
	agent := NewSimpleAgent("http://localhost:8080", s)

	originalData := []byte(`{"hello":"world"}`)

	writeResult, _ := BuildRecordsWrite(s, RecordsWriteOptions{
		Protocol:     "https://example.com/test",
		ProtocolPath: "root",
		DataFormat:   "application/json",
		Data:         originalData,
	})
	msg := writeResult.Message

	encoded := base64.RawURLEncoding.EncodeToString(writeResult.WireData)
	record := RecordFromWrite(agent, s.DID, msg, encoded)

	t.Run("JSON", func(t *testing.T) {
		var result map[string]string
		err := record.Data().JSON(context.Background(), &result)
		if err != nil {
			t.Fatalf("Data().JSON: %v", err)
		}
		if result["hello"] != "world" {
			t.Errorf("result = %v", result)
		}
	})

	t.Run("Text after JSON consumes data", func(t *testing.T) {
		// Data was consumed by JSON call above. Since there's no server
		// to re-fetch from, and no raw data, this should fail.
		// But we can set up a new record for this test.
		record2 := RecordFromWrite(agent, s.DID, msg, encoded)
		text, err := record2.Data().Text(context.Background())
		if err != nil {
			t.Fatalf("Data().Text: %v", err)
		}
		if text != string(originalData) {
			t.Errorf("text = %q, want %q", text, string(originalData))
		}
	})

	t.Run("Bytes", func(t *testing.T) {
		record3 := RecordFromWrite(agent, s.DID, msg, encoded)
		data, err := record3.Data().Bytes(context.Background())
		if err != nil {
			t.Fatalf("Data().Bytes: %v", err)
		}
		if string(data) != string(originalData) {
			t.Errorf("data = %q, want %q", data, originalData)
		}
	})
}

func TestRecordDataFromRawBytes(t *testing.T) {
	s := newTestSigner(t)
	agent := NewSimpleAgent("http://localhost:8080", s)

	rawData := []byte("binary payload here")

	record := &Record{
		ID:       "rec123",
		Protocol: "https://example.com/test",
		agent:    agent,
		target:   s.DID,
		rawData:  rawData,
	}

	data, err := record.Data().Bytes(context.Background())
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if string(data) != string(rawData) {
		t.Errorf("data = %q, want %q", data, rawData)
	}

	// After consumption, rawData should be nil.
	if record.rawData != nil {
		t.Error("rawData should be nil after consumption")
	}
}

func TestRecordFromEntry(t *testing.T) {
	s := newTestSigner(t)
	agent := NewSimpleAgent("http://localhost:8080", s)

	entry := json.RawMessage(`{
		"recordId": "rec-abc",
		"contextId": "ctx-abc",
		"descriptor": {
			"interface": "Records",
			"method": "Write",
			"protocol": "https://example.com/mesh",
			"protocolPath": "network/node",
			"schema": "https://example.com/schemas/node",
			"dataFormat": "application/json",
			"dataCid": "bafy123",
			"dataSize": 42,
			"dateCreated": "2025-06-01T00:00:00.000000Z",
			"messageTimestamp": "2025-06-01T00:00:00.000000Z",
			"recipient": "did:dht:someone",
			"tags": {"role": "admin"}
		},
		"encodedData": "` + base64.RawURLEncoding.EncodeToString([]byte(`{"name":"Alice"}`)) + `"
	}`)

	record, err := RecordFromEntry(agent, s.DID, entry)
	if err != nil {
		t.Fatalf("RecordFromEntry: %v", err)
	}

	if record.ID != "rec-abc" {
		t.Errorf("ID = %q", record.ID)
	}
	if record.ContextID != "ctx-abc" {
		t.Errorf("ContextID = %q", record.ContextID)
	}
	if record.Protocol != "https://example.com/mesh" {
		t.Errorf("Protocol = %q", record.Protocol)
	}
	if record.ProtocolPath != "network/node" {
		t.Errorf("ProtocolPath = %q", record.ProtocolPath)
	}
	if record.Schema != "https://example.com/schemas/node" {
		t.Errorf("Schema = %q", record.Schema)
	}
	if record.DataSize != 42 {
		t.Errorf("DataSize = %d", record.DataSize)
	}
	if record.Recipient != "did:dht:someone" {
		t.Errorf("Recipient = %q", record.Recipient)
	}
	if record.Tags["role"] != "admin" {
		t.Errorf("Tags = %v", record.Tags)
	}

	// Can read inline data.
	var data map[string]string
	err = record.Data().JSON(context.Background(), &data)
	if err != nil {
		t.Fatalf("Data().JSON: %v", err)
	}
	if data["name"] != "Alice" {
		t.Errorf("data = %v", data)
	}
}

func TestRecordFromRead(t *testing.T) {
	s := newTestSigner(t)
	agent := NewSimpleAgent("http://localhost:8080", s)

	reply := &DwnReply{
		Status: Status{Code: 200, Detail: "OK"},
		Entry: json.RawMessage(`{
			"recordsWrite": {
				"recordId": "rec-read-1",
				"contextId": "ctx-read-1",
				"descriptor": {
					"interface": "Records",
					"method": "Write",
					"protocol": "https://example.com/test",
					"protocolPath": "root",
					"dataFormat": "application/json",
					"dataCid": "bafy789",
					"dataSize": 15,
					"dateCreated": "2025-06-15T12:00:00.000000Z",
					"messageTimestamp": "2025-06-15T12:00:00.000000Z"
				}
			}
		}`),
	}
	binaryData := []byte(`{"status":"ok"}`)

	record, err := RecordFromRead(agent, s.DID, reply, binaryData)
	if err != nil {
		t.Fatalf("RecordFromRead: %v", err)
	}

	if record.ID != "rec-read-1" {
		t.Errorf("ID = %q", record.ID)
	}
	if record.Protocol != "https://example.com/test" {
		t.Errorf("Protocol = %q", record.Protocol)
	}

	// Data should come from binary body.
	text, err := record.Data().Text(context.Background())
	if err != nil {
		t.Fatalf("Data().Text: %v", err)
	}
	if text != `{"status":"ok"}` {
		t.Errorf("text = %q", text)
	}
}

func TestRecordDataNoAgent(t *testing.T) {
	// A record without an agent and no cached data should fail on re-fetch.
	record := &Record{
		ID:     "rec-orphan",
		agent:  nil,
		target: "did:dht:test",
	}

	_, err := record.Data().Bytes(context.Background())
	if err == nil {
		t.Error("expected error when no agent and no cached data")
	}
}
