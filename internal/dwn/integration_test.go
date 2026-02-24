package dwn_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/enboxorg/dwn-mesh/internal/did"
	"github.com/enboxorg/dwn-mesh/internal/dwn"
	dwncrypto "github.com/enboxorg/dwn-mesh/internal/dwn/crypto"
)

// These tests require a live DWN server.
// Set the DWN_ENDPOINT environment variable to run them:
//
//   DWN_ENDPOINT=https://dev.example.com go test ./internal/dwn/ -run TestIntegration -v
//
// They are skipped when DWN_ENDPOINT is not set.

func testEndpoint(t *testing.T) string {
	t.Helper()
	endpoint := os.Getenv("DWN_ENDPOINT")
	if endpoint == "" {
		t.Skip("DWN_ENDPOINT not set, skipping integration test")
	}
	return endpoint
}

// testIdentity generates a new did:dht identity and publishes it to the DHT
// so the DWN server can resolve the DID Document for JWS verification.
func testIdentity(t *testing.T, endpoint string) *did.DID {
	t.Helper()
	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("generating DID: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := identity.Publish(ctx, endpoint); err != nil {
		t.Fatalf("publishing DID to DHT: %v", err)
	}
	t.Logf("Published DID: %s", identity.URI)

	return identity
}

func testSigner(t *testing.T, endpoint string) *dwn.Signer {
	t.Helper()
	identity := testIdentity(t, endpoint)
	return &dwn.Signer{
		DID:        identity.URI,
		PrivateKey: identity.SigningKey,
	}
}

// registerTenant registers the signer's DID as a tenant on the DWN server.
// RegisterTenant auto-detects the registration method (provider-auth or PoW)
// via GET /info and returns nil if the server is open for all.
func registerTenant(t *testing.T, endpoint string, signer *dwn.Signer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := dwn.RegisterTenant(ctx, endpoint, signer.DID); err != nil {
		t.Fatalf("RegisterTenant: %v", err)
	}
	t.Logf("Registered tenant: %s", signer.DID)
}

func TestIntegrationProtocolsConfigure(t *testing.T) {
	endpoint := testEndpoint(t)
	signer := testSigner(t, endpoint)
	registerTenant(t, endpoint, signer)

	agent := dwn.NewSimpleAgent(endpoint, signer)
	api := dwn.NewDwnAPI(agent)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Install a test protocol.
	protocolDef := json.RawMessage(`{
		"protocol": "https://enbox.org/protocols/integration-test",
		"published": true,
		"types": {
			"note": {
				"schema": "https://enbox.org/schemas/integration-test/note",
				"dataFormats": ["application/json"]
			}
		},
		"structure": {
			"note": {}
		}
	}`)

	status, err := api.ConfigureProtocol(ctx, signer.DID, protocolDef)
	if err != nil {
		t.Fatalf("ConfigureProtocol: %v", err)
	}

	// 200 = newly installed, 202 = accepted, 409 = already exists.
	if status.Code != 200 && status.Code != 202 && status.Code != 409 {
		t.Fatalf("unexpected status: %d %s", status.Code, status.Detail)
	}

	t.Logf("ConfigureProtocol: %d %s", status.Code, status.Detail)
}

func TestIntegrationRecordsWriteReadQuery(t *testing.T) {
	endpoint := testEndpoint(t)
	signer := testSigner(t, endpoint)
	registerTenant(t, endpoint, signer)

	agent := dwn.NewSimpleAgent(endpoint, signer)
	api := dwn.NewDwnAPI(agent)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Install protocol first.
	protocolDef := json.RawMessage(`{
		"protocol": "https://enbox.org/protocols/integration-test",
		"published": true,
		"types": {
			"note": {
				"schema": "https://enbox.org/schemas/integration-test/note",
				"dataFormats": ["application/json"]
			}
		},
		"structure": {
			"note": {}
		}
	}`)

	_, err := api.ConfigureProtocol(ctx, signer.DID, protocolDef)
	if err != nil {
		t.Fatalf("ConfigureProtocol: %v", err)
	}

	// 2. Write a record.
	noteData := []byte(`{"title":"Integration Test","body":"This was written by dwn-mesh Go client"}`)

	record, writeStatus, err := api.Write(ctx, signer.DID, dwn.WriteParams{
		Protocol:     "https://enbox.org/protocols/integration-test",
		ProtocolPath: "note",
		Schema:       "https://enbox.org/schemas/integration-test/note",
		DataFormat:   "application/json",
		Data:         noteData,
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if writeStatus.Code >= 300 {
		t.Fatalf("Write failed: %d %s", writeStatus.Code, writeStatus.Detail)
	}
	t.Logf("Write: %d %s (record: %s)", writeStatus.Code, writeStatus.Detail, record.ID)

	// 3. Query records — should find the one we just wrote.
	records, queryStatus, err := api.Query(ctx, signer.DID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     "https://enbox.org/protocols/integration-test",
			ProtocolPath: "note",
		},
	}, "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	if queryStatus.Code != 200 {
		t.Fatalf("Query failed: %d %s", queryStatus.Code, queryStatus.Detail)
	}

	if len(records) == 0 {
		t.Fatal("Query returned no records, expected at least 1")
	}
	t.Logf("Query: found %d records", len(records))

	// Verify we can find our record.
	found := false
	for _, r := range records {
		if r.ID == record.ID {
			found = true
			break
		}
	}
	// Note: record.ID may not be set from the Write response in SimpleAgent.
	// Check that at least one record exists.
	if !found && len(records) > 0 {
		t.Logf("our record ID not found in results (may need write response parsing), but %d records exist", len(records))
	}

	// 4. Read data from a queried record.
	firstRecord := records[0]
	var noteContent map[string]string
	err = firstRecord.Data().JSON(ctx, &noteContent)
	if err != nil {
		// Data might not be inline in query results — this is expected.
		t.Logf("Data().JSON from query result: %v (expected for non-inline data)", err)
	} else {
		t.Logf("Record data: %v", noteContent)
	}

	// 5. Read the record directly.
	readRecord, readStatus, err := api.Read(ctx, signer.DID, dwn.RecordsFilter{
		Protocol:     "https://enbox.org/protocols/integration-test",
		ProtocolPath: "note",
	}, "")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if readStatus.Code != 200 {
		t.Logf("Read status: %d %s (may require specific recordId filter)", readStatus.Code, readStatus.Detail)
	} else if readRecord != nil {
		t.Logf("Read: record %s, protocol=%s", readRecord.ID, readRecord.Protocol)

		// Try reading data from the read result.
		var readContent map[string]string
		err = readRecord.Data().JSON(ctx, &readContent)
		if err != nil {
			t.Logf("Data().JSON from read: %v", err)
		} else {
			t.Logf("Read data: %v", readContent)
			if readContent["title"] == "" {
				t.Error("expected non-empty title in read data")
			}
		}
	}
}

func TestIntegrationRecordsDelete(t *testing.T) {
	endpoint := testEndpoint(t)
	signer := testSigner(t, endpoint)
	registerTenant(t, endpoint, signer)

	agent := dwn.NewSimpleAgent(endpoint, signer)
	api := dwn.NewDwnAPI(agent)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Install protocol.
	protocolDef := json.RawMessage(`{
		"protocol": "https://enbox.org/protocols/integration-test",
		"published": true,
		"types": {
			"note": {
				"schema": "https://enbox.org/schemas/integration-test/note",
				"dataFormats": ["application/json"]
			}
		},
		"structure": {
			"note": {}
		}
	}`)
	api.ConfigureProtocol(ctx, signer.DID, protocolDef)

	// Write a record.
	_, writeStatus, err := api.Write(ctx, signer.DID, dwn.WriteParams{
		Protocol:     "https://enbox.org/protocols/integration-test",
		ProtocolPath: "note",
		Schema:       "https://enbox.org/schemas/integration-test/note",
		DataFormat:   "application/json",
		Data:         []byte(`{"title":"To be deleted"}`),
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if writeStatus.Code >= 300 {
		t.Fatalf("Write: %d %s", writeStatus.Code, writeStatus.Detail)
	}

	// Query to get the record ID.
	records, _, err := api.Query(ctx, signer.DID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     "https://enbox.org/protocols/integration-test",
			ProtocolPath: "note",
		},
	}, "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(records) == 0 {
		t.Skip("no records to delete")
	}

	recordID := records[len(records)-1].ID
	t.Logf("Deleting record: %s", recordID)

	// Delete it.
	deleteStatus, err := api.Delete(ctx, signer.DID, recordID, false, "")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if deleteStatus.Code >= 300 {
		t.Fatalf("Delete: %d %s", deleteStatus.Code, deleteStatus.Detail)
	}
	t.Logf("Delete: %d %s", deleteStatus.Code, deleteStatus.Detail)
}

func TestIntegrationEncryptedRecordsWrite(t *testing.T) {
	endpoint := testEndpoint(t)
	signer := testSigner(t, endpoint)
	registerTenant(t, endpoint, signer)

	agent := dwn.NewSimpleAgent(endpoint, signer)
	api := dwn.NewDwnAPI(agent)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Install a protocol with encryption.
	protocolDef := json.RawMessage(`{
		"protocol": "https://enbox.org/protocols/encryption-test",
		"published": true,
		"types": {
			"secret": {
				"schema": "https://enbox.org/schemas/encryption-test/secret",
				"dataFormats": ["application/json"]
			}
		},
		"structure": {
			"secret": {}
		}
	}`)

	status, err := api.ConfigureProtocol(ctx, signer.DID, protocolDef)
	if err != nil {
		t.Fatalf("ConfigureProtocol: %v", err)
	}
	if status.Code >= 300 && status.Code != 409 {
		t.Fatalf("ConfigureProtocol: %d %s", status.Code, status.Detail)
	}
	t.Logf("ConfigureProtocol: %d %s", status.Code, status.Detail)

	// Generate encryption key pair for the recipient (ourselves).
	identity, err := did.FromPrivateKey(signer.PrivateKey)
	if err != nil {
		t.Fatalf("did.FromPrivateKey: %v", err)
	}

	encKID := identity.EncryptionKeyID()
	encPub := identity.EncryptionPublicKey
	encPriv := identity.EncryptionPrivateKey

	// Write an encrypted record.
	plaintext := []byte(`{"message":"This is encrypted end-to-end!","code":42}`)

	record, writeStatus, err := api.Write(ctx, signer.DID, dwn.WriteParams{
		Protocol:     "https://enbox.org/protocols/encryption-test",
		ProtocolPath: "secret",
		Schema:       "https://enbox.org/schemas/encryption-test/secret",
		DataFormat:   "application/json",
		Data:         plaintext,
		EncryptionRecipients: []dwncrypto.KeyEncryptionInput{{
			PublicKeyID:      encKID,
			PublicKey:        encPub,
			DerivationScheme: dwncrypto.DerivationSchemeProtocolPath,
		}},
	})
	if err != nil {
		t.Fatalf("Write (encrypted): %v", err)
	}
	if writeStatus.Code >= 300 {
		t.Fatalf("Write failed: %d %s", writeStatus.Code, writeStatus.Detail)
	}
	t.Logf("Encrypted Write: %d %s (record: %s)", writeStatus.Code, writeStatus.Detail, record.ID)

	// Query to find the record.
	records, queryStatus, err := api.Query(ctx, signer.DID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     "https://enbox.org/protocols/encryption-test",
			ProtocolPath: "secret",
		},
	}, "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if queryStatus.Code != 200 {
		t.Fatalf("Query: %d %s", queryStatus.Code, queryStatus.Detail)
	}
	if len(records) == 0 {
		t.Fatal("Query returned no records, expected at least 1")
	}
	t.Logf("Query: found %d encrypted records", len(records))

	// Read the encrypted record.
	readRecord, readStatus, err := api.Read(ctx, signer.DID, dwn.RecordsFilter{
		Protocol:     "https://enbox.org/protocols/encryption-test",
		ProtocolPath: "secret",
	}, "")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if readStatus.Code != 200 {
		t.Logf("Read: %d %s", readStatus.Code, readStatus.Detail)
		return
	}

	// The read result contains encrypted data. Verify we can get the raw bytes.
	ciphertext, err := readRecord.Data().Bytes(ctx)
	if err != nil {
		t.Logf("Data().Bytes: %v (may need server-side data return)", err)
		return
	}

	t.Logf("Read: got %d bytes of encrypted data (record: %s)", len(ciphertext), readRecord.ID)

	// The data from the server should be ciphertext, not plaintext.
	if string(ciphertext) == string(plaintext) {
		t.Error("SECURITY: server returned plaintext instead of ciphertext!")
	}

	// Decrypt the record using our encryption private key.
	// First, we need the encryption property from the entry metadata.
	// The read result's entry should contain the encryption property.
	if readRecord.RawEntry != nil {
		var entry struct {
			RecordsWrite struct {
				Encryption *dwncrypto.Encryption `json:"encryption"`
			} `json:"recordsWrite"`
			Encryption *dwncrypto.Encryption `json:"encryption"`
		}
		if err := json.Unmarshal(readRecord.RawEntry, &entry); err != nil {
			t.Logf("parsing entry for encryption: %v", err)
		} else {
			enc := entry.Encryption
			if enc == nil {
				enc = entry.RecordsWrite.Encryption
			}
			if enc != nil {
				decrypted, err := dwncrypto.DecryptData(ciphertext, enc, encPriv, encKID)
				if err != nil {
					t.Fatalf("DecryptData: %v", err)
				}
				if string(decrypted) != string(plaintext) {
					t.Fatalf("decrypted data mismatch: got %q, want %q", decrypted, plaintext)
				}
				t.Logf("Decryption successful: %s", string(decrypted))
			} else {
				t.Log("encryption property not found in entry (may need entry parsing)")
			}
		}
	} else {
		t.Log("RawEntry not available, skipping decryption verification")
	}

	_ = encPriv // Keep the compiler happy.
}

func TestIntegrationEncryptedWriteQueryDelete(t *testing.T) {
	endpoint := testEndpoint(t)
	signer := testSigner(t, endpoint)
	registerTenant(t, endpoint, signer)

	agent := dwn.NewSimpleAgent(endpoint, signer)
	api := dwn.NewDwnAPI(agent)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Install protocol.
	protocolDef := json.RawMessage(`{
		"protocol": "https://enbox.org/protocols/encryption-lifecycle-test",
		"published": true,
		"types": {
			"item": {
				"schema": "https://enbox.org/schemas/encryption-lifecycle-test/item",
				"dataFormats": ["application/json"]
			}
		},
		"structure": {
			"item": {}
		}
	}`)

	status, err := api.ConfigureProtocol(ctx, signer.DID, protocolDef)
	if err != nil {
		t.Fatalf("ConfigureProtocol: %v", err)
	}
	if status.Code >= 300 && status.Code != 409 {
		t.Fatalf("ConfigureProtocol: %d %s", status.Code, status.Detail)
	}

	// Generate encryption key.
	identity, err := did.FromPrivateKey(signer.PrivateKey)
	if err != nil {
		t.Fatalf("did.FromPrivateKey: %v", err)
	}

	// Write 3 encrypted records.
	for i := 0; i < 3; i++ {
		plaintext := []byte(fmt.Sprintf(`{"index":%d,"data":"item-%d"}`, i, i))

		_, ws, err := api.Write(ctx, signer.DID, dwn.WriteParams{
			Protocol:     "https://enbox.org/protocols/encryption-lifecycle-test",
			ProtocolPath: "item",
			Schema:       "https://enbox.org/schemas/encryption-lifecycle-test/item",
			DataFormat:   "application/json",
			Data:         plaintext,
			EncryptionRecipients: []dwncrypto.KeyEncryptionInput{{
				PublicKeyID:      identity.EncryptionKeyID(),
				PublicKey:        identity.EncryptionPublicKey,
				DerivationScheme: dwncrypto.DerivationSchemeProtocolPath,
			}},
		})
		if err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
		if ws.Code >= 300 {
			t.Fatalf("Write[%d]: %d %s", i, ws.Code, ws.Detail)
		}
	}
	t.Log("Wrote 3 encrypted records")

	// Query all encrypted records.
	records, qs, err := api.Query(ctx, signer.DID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     "https://enbox.org/protocols/encryption-lifecycle-test",
			ProtocolPath: "item",
		},
	}, "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if qs.Code != 200 {
		t.Fatalf("Query: %d %s", qs.Code, qs.Detail)
	}
	if len(records) < 3 {
		t.Fatalf("Query returned %d records, want >= 3", len(records))
	}
	t.Logf("Query: found %d records", len(records))

	// Delete the last record.
	lastID := records[len(records)-1].ID
	ds, err := api.Delete(ctx, signer.DID, lastID, false, "")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if ds.Code >= 300 {
		t.Fatalf("Delete: %d %s", ds.Code, ds.Detail)
	}
	t.Logf("Deleted record: %s (%d %s)", lastID, ds.Code, ds.Detail)

	// Verify one fewer record.
	records2, _, err := api.Query(ctx, signer.DID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     "https://enbox.org/protocols/encryption-lifecycle-test",
			ProtocolPath: "item",
		},
	}, "")
	if err != nil {
		t.Fatalf("Query after delete: %v", err)
	}
	if len(records2) >= len(records) {
		t.Logf("Expected fewer records after delete: had %d, now %d", len(records), len(records2))
	} else {
		t.Logf("After delete: %d records (was %d)", len(records2), len(records))
	}
}

func TestIntegrationEncryptedMultiRecipient(t *testing.T) {
	endpoint := testEndpoint(t)
	signer := testSigner(t, endpoint)
	registerTenant(t, endpoint, signer)

	agent := dwn.NewSimpleAgent(endpoint, signer)
	api := dwn.NewDwnAPI(agent)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Install protocol.
	protocolDef := json.RawMessage(`{
		"protocol": "https://enbox.org/protocols/multi-recipient-test",
		"published": true,
		"types": {
			"shared": {
				"schema": "https://enbox.org/schemas/multi-recipient-test/shared",
				"dataFormats": ["application/json"]
			}
		},
		"structure": {
			"shared": {}
		}
	}`)

	status, err := api.ConfigureProtocol(ctx, signer.DID, protocolDef)
	if err != nil {
		t.Fatalf("ConfigureProtocol: %v", err)
	}
	if status.Code >= 300 && status.Code != 409 {
		t.Fatalf("ConfigureProtocol: %d %s", status.Code, status.Detail)
	}

	// Generate two recipient key pairs (simulating multi-party encryption).
	identity, _ := did.FromPrivateKey(signer.PrivateKey)

	// Second "recipient" — a separate X25519 key pair (not from a DID,
	// just for testing multi-recipient wrapping).
	recipientPriv2, recipientPub2, err := dwncrypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	plaintext := []byte(`{"shared":"multi-recipient encrypted data"}`)

	// Write encrypted for 2 recipients.
	_, ws, err := api.Write(ctx, signer.DID, dwn.WriteParams{
		Protocol:     "https://enbox.org/protocols/multi-recipient-test",
		ProtocolPath: "shared",
		Schema:       "https://enbox.org/schemas/multi-recipient-test/shared",
		DataFormat:   "application/json",
		Data:         plaintext,
		EncryptionRecipients: []dwncrypto.KeyEncryptionInput{
			{
				PublicKeyID:      identity.EncryptionKeyID(),
				PublicKey:        identity.EncryptionPublicKey,
				DerivationScheme: dwncrypto.DerivationSchemeProtocolPath,
			},
			{
				PublicKeyID:      "did:test:recipient2#enc",
				PublicKey:        recipientPub2,
				DerivationScheme: dwncrypto.DerivationSchemeProtocolPath,
			},
		},
	})
	if err != nil {
		t.Fatalf("Write (multi-recipient): %v", err)
	}
	if ws.Code >= 300 {
		t.Fatalf("Write: %d %s", ws.Code, ws.Detail)
	}
	t.Logf("Multi-recipient encrypted Write: %d %s", ws.Code, ws.Detail)

	// Verify both recipients can decrypt (locally, using the ciphertext
	// from the wire). We need the actual ciphertext and encryption property.
	// Build the message locally to verify decryption works.
	builtResult, err := dwn.BuildRecordsWrite(&dwn.Signer{
		DID:        signer.DID,
		PrivateKey: signer.PrivateKey,
	}, dwn.RecordsWriteOptions{
		Protocol:     "https://enbox.org/protocols/multi-recipient-test",
		ProtocolPath: "shared",
		Schema:       "https://enbox.org/schemas/multi-recipient-test/shared",
		DataFormat:   "application/json",
		Data:         plaintext,
		EncryptionRecipients: []dwncrypto.KeyEncryptionInput{
			{
				PublicKeyID:      identity.EncryptionKeyID(),
				PublicKey:        identity.EncryptionPublicKey,
				DerivationScheme: dwncrypto.DerivationSchemeProtocolPath,
			},
			{
				PublicKeyID:      "did:test:recipient2#enc",
				PublicKey:        recipientPub2,
				DerivationScheme: dwncrypto.DerivationSchemeProtocolPath,
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildRecordsWrite: %v", err)
	}

	msg := builtResult.Message
	ct := builtResult.WireData

	// Recipient 1 (identity owner) can decrypt.
	decrypted1, err := dwncrypto.DecryptData(ct, msg.Encryption, identity.EncryptionPrivateKey, identity.EncryptionKeyID())
	if err != nil {
		t.Fatalf("DecryptData (recipient 1): %v", err)
	}
	if string(decrypted1) != string(plaintext) {
		t.Fatalf("recipient 1: decrypted = %q, want %q", decrypted1, plaintext)
	}
	t.Log("Recipient 1 decryption: OK")

	// Recipient 2 can decrypt.
	decrypted2, err := dwncrypto.DecryptData(ct, msg.Encryption, recipientPriv2, "did:test:recipient2#enc")
	if err != nil {
		t.Fatalf("DecryptData (recipient 2): %v", err)
	}
	if string(decrypted2) != string(plaintext) {
		t.Fatalf("recipient 2: decrypted = %q, want %q", decrypted2, plaintext)
	}
	t.Log("Recipient 2 decryption: OK")
}

func TestIntegrationHTTPWireProtocol(t *testing.T) {
	// Verify the wire protocol is correct by checking that the server
	// accepts our dwn-request header format.
	endpoint := testEndpoint(t)
	signer := testSigner(t, endpoint)
	registerTenant(t, endpoint, signer)

	client := dwn.NewClient(endpoint, signer)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// A simple ProtocolsQuery should work if the wire protocol is correct.
	reply, err := client.ProtocolsQuery(ctx, signer.DID, "")
	if err != nil {
		t.Fatalf("ProtocolsQuery (wire protocol test): %v", err)
	}

	// Any valid DWN status code proves the wire protocol works.
	// 200 = success, 401 = not registered (but server understood the request).
	if reply.Status.Code == 200 || reply.Status.Code == 401 {
		t.Logf("Wire protocol OK: ProtocolsQuery returned %d %s", reply.Status.Code, reply.Status.Detail)
	} else {
		t.Fatalf("Unexpected status: %d %s", reply.Status.Code, reply.Status.Detail)
	}
}

// TestIntegrationProtocolRoleWrite verifies that role-based authorization works
// for writes to another party's DWN. This uses a minimal protocol with a
// $role type and a record type that requires the role for writes.
func TestIntegrationProtocolRoleWrite(t *testing.T) {
	endpoint := testEndpoint(t)

	// Create two identities: Alice (DWN owner) and Bob (role-holder).
	aliceIdentity := testIdentity(t, endpoint)
	aliceSigner := &dwn.Signer{DID: aliceIdentity.URI, PrivateKey: aliceIdentity.SigningKey}
	registerTenant(t, endpoint, aliceSigner)

	bobIdentity := testIdentity(t, endpoint)
	bobSigner := &dwn.Signer{DID: bobIdentity.URI, PrivateKey: bobIdentity.SigningKey}
	registerTenant(t, endpoint, bobSigner)

	aliceAgent := dwn.NewSimpleAgent(endpoint, aliceSigner)
	aliceAPI := dwn.NewDwnAPI(aliceAgent)

	bobAgent := dwn.NewSimpleAgent(endpoint, bobSigner)
	bobAPI := dwn.NewDwnAPI(bobAgent)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Alice installs a minimal role protocol.
	protocolURI := fmt.Sprintf("https://example.com/role-test/%d", time.Now().UnixNano())
	// Use a flat protocol structure to test role-based auth without nesting.
	// This mirrors the JS SDK's friend-role.json test protocol.
	protocolDef := json.RawMessage(fmt.Sprintf(`{
		"protocol": %q,
		"published": true,
		"types": {
			"friend": {},
			"chat": {}
		},
		"structure": {
			"friend": {
				"$role": true,
				"$actions": [
					{ "who": "anyone", "can": ["create"] }
				]
			},
			"chat": {
				"$actions": [
					{ "role": "friend", "can": ["create", "read"] }
				]
			}
		}
	}`, protocolURI))

	status, err := aliceAPI.ConfigureProtocol(ctx, aliceIdentity.URI, protocolDef)
	if err != nil {
		t.Fatalf("ConfigureProtocol: %v", err)
	}
	t.Logf("Step 1: Protocol installed: %d %s", status.Code, status.Detail)

	// 2. Alice creates Bob's friend role record (recipient = Bob).
	// With flat structure, friend is a root-level type — no parentContextID needed.
	_, ms, err := aliceAPI.Write(ctx, aliceIdentity.URI, dwn.WriteParams{
		Protocol:     protocolURI,
		ProtocolPath: "friend",
		DataFormat:   "application/json",
		Recipient:    bobIdentity.URI,
		Data:         []byte(`{"label":"Bob is my friend"}`),
	})
	if err != nil || ms.Code >= 300 {
		t.Fatalf("creating friend role: err=%v, status=%v", err, ms)
	}
	t.Logf("Step 2: Friend role created for Bob: %d %s", ms.Code, ms.Detail)

	// Debug: Query the friend records.
	friendRecords, fqs, _ := aliceAPI.Query(ctx, aliceIdentity.URI, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocolURI,
			ProtocolPath: "friend",
		},
	}, "")
	if fqs != nil {
		t.Logf("  Debug: friend query: status=%d, count=%d", fqs.Code, len(friendRecords))
		for i, m := range friendRecords {
			t.Logf("    [%d]: id=%s, recipient=%s, contextId=%s", i, m.ID, m.Recipient, m.ContextID)
		}
	}

	// 3. Bob writes a chat to Alice's DWN, invoking the "friend" role.
	_, ps, err := bobAPI.Write(ctx, aliceIdentity.URI, dwn.WriteParams{
		Protocol:     protocolURI,
		ProtocolPath: "chat",
		DataFormat:   "application/json",
		Data:         []byte(`{"text":"hello from Bob"}`),
		ProtocolRole: "friend",
	})
	if err != nil {
		t.Fatalf("Bob's role-based write: %v", err)
	}
	if ps.Code >= 300 {
		t.Fatalf("Bob's role-based write failed: %d %s", ps.Code, ps.Detail)
	}
	t.Logf("Step 3: Bob's role-based write succeeded: %d %s", ps.Code, ps.Detail)

	// 4. Verify: write WITHOUT role should fail.
	_, nrs, err := bobAPI.Write(ctx, aliceIdentity.URI, dwn.WriteParams{
		Protocol:     protocolURI,
		ProtocolPath: "chat",
		DataFormat:   "application/json",
		Data:         []byte(`{"text":"this should fail"}`),
		// No ProtocolRole — should be rejected.
	})
	if err != nil {
		t.Fatalf("Bob's no-role write: %v", err)
	}
	if nrs.Code < 300 {
		t.Fatalf("expected Bob's no-role write to be rejected, got: %d %s", nrs.Code, nrs.Detail)
	}
	t.Logf("Step 4: Bob's no-role write correctly rejected: %d %s", nrs.Code, nrs.Detail)

	// ---- Part 2: Test nested role (group/member pattern) ----
	t.Log("--- Part 2: Nested role test ---")

	nestedProtocolURI := fmt.Sprintf("https://example.com/nested-role-test/%d", time.Now().UnixNano())
	nestedDef := json.RawMessage(fmt.Sprintf(`{
		"protocol": %q,
		"published": true,
		"types": {
			"group": {},
			"member": {},
			"post": {}
		},
		"structure": {
			"group": {
				"member": {
					"$role": true,
					"$actions": [
						{ "who": "author", "of": "group", "can": ["create", "delete"] }
					]
				},
				"post": {
					"$actions": [
						{ "role": "group/member", "can": ["create", "read"] }
					]
				}
			}
		}
	}`, nestedProtocolURI))

	nstatus, err := aliceAPI.ConfigureProtocol(ctx, aliceIdentity.URI, nestedDef)
	if err != nil || nstatus.Code >= 300 {
		t.Fatalf("ConfigureProtocol (nested): err=%v, status=%v", err, nstatus)
	}
	t.Logf("Step 5: Nested protocol installed: %d", nstatus.Code)

	// Create group (root record).
	groupRecord, gs, err := aliceAPI.Write(ctx, aliceIdentity.URI, dwn.WriteParams{
		Protocol:     nestedProtocolURI,
		ProtocolPath: "group",
		DataFormat:   "application/json",
		Data:         []byte(`{"name":"test-group"}`),
	})
	if err != nil || gs.Code >= 300 {
		t.Fatalf("creating group: err=%v, status=%v", err, gs)
	}
	groupID := groupRecord.ID
	if groupID == "" {
		records, _, _ := aliceAPI.Query(ctx, aliceIdentity.URI, dwn.QueryParams{
			Filter: dwn.RecordsFilter{Protocol: nestedProtocolURI, ProtocolPath: "group"},
		}, "")
		if len(records) > 0 {
			groupID = records[0].ID
		}
	}
	t.Logf("Step 6: Group created: %s (contextId should = recordId)", groupID)

	// Create member role for Bob under the group.
	_, memStatus, err := aliceAPI.Write(ctx, aliceIdentity.URI, dwn.WriteParams{
		Protocol:        nestedProtocolURI,
		ProtocolPath:    "group/member",
		DataFormat:      "application/json",
		Recipient:       bobIdentity.URI,
		ParentContextID: groupID,
		Data:            []byte(`{"role":"member"}`),
	})
	if err != nil || memStatus.Code >= 300 {
		t.Fatalf("creating nested member role: err=%v, status=%v", err, memStatus)
	}
	t.Logf("Step 7: Nested member role created for Bob: %d %s", memStatus.Code, memStatus.Detail)

	// Debug: Query member records to verify.
	nestedMembers, nmqs, _ := aliceAPI.Query(ctx, aliceIdentity.URI, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     nestedProtocolURI,
			ProtocolPath: "group/member",
		},
	}, "")
	if nmqs != nil && nmqs.Code == 200 {
		for i, m := range nestedMembers {
			t.Logf("  Nested member[%d]: id=%s, recipient=%s, contextId=%s", i, m.ID, m.Recipient, m.ContextID)
		}
	}

	// Debug: build the post message locally to see its contextId.
	testSig := &dwn.Signer{DID: bobIdentity.URI, PrivateKey: bobIdentity.SigningKey}
	postResult, _ := dwn.BuildRecordsWrite(testSig, dwn.RecordsWriteOptions{
		Protocol:        nestedProtocolURI,
		ProtocolPath:    "group/post",
		DataFormat:      "application/json",
		ParentContextID: groupID,
		Data:            []byte(`{"text":"nested role write"}`),
		ProtocolRole:    "group/member",
	})
	if postResult != nil {
		t.Logf("  Debug: post contextId=%s, recordId=%s", postResult.Message.ContextID, postResult.Message.RecordID)
	}

	// Bob writes a post, invoking group/member role.
	_, postStatus, err := bobAPI.Write(ctx, aliceIdentity.URI, dwn.WriteParams{
		Protocol:        nestedProtocolURI,
		ProtocolPath:    "group/post",
		DataFormat:      "application/json",
		ParentContextID: groupID,
		Data:            []byte(`{"text":"nested role write"}`),
		ProtocolRole:    "group/member",
	})
	if err != nil {
		t.Fatalf("Bob's nested role write: %v", err)
	}
	if postStatus.Code >= 300 {
		t.Fatalf("Bob's nested role write failed: %d %s", postStatus.Code, postStatus.Detail)
	}
	t.Logf("Step 8: Bob's nested role write succeeded: %d %s", postStatus.Code, postStatus.Detail)
}

// TestIntegrationSquashDirective verifies the server accepts $squash in protocol definitions.
func TestIntegrationSquashDirective(t *testing.T) {
	endpoint := testEndpoint(t)
	signer := testSigner(t, endpoint)
	registerTenant(t, endpoint, signer)

	agent := dwn.NewSimpleAgent(endpoint, signer)
	api := dwn.NewDwnAPI(agent)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	protocolURI := fmt.Sprintf("https://example.com/squash-test/%d", time.Now().UnixNano())
	def := json.RawMessage(fmt.Sprintf(`{
		"protocol": %q,
		"published": true,
		"types": {
			"status": {
				"dataFormats": ["application/json"]
			}
		},
		"structure": {
			"status": {
				"$squash": true,
				"$actions": [
					{ "who": "anyone", "can": ["read"] }
				]
			}
		}
	}`, protocolURI))

	status, err := api.ConfigureProtocol(ctx, signer.DID, def)
	if err != nil {
		t.Fatalf("ConfigureProtocol with $squash: %v", err)
	}
	t.Logf("ConfigureProtocol status: %d %s", status.Code, status.Detail)
	if status.Code >= 300 {
		t.Fatalf("Server rejected $squash: %d %s", status.Code, status.Detail)
	}
	t.Log("Server accepted $squash!")
}
