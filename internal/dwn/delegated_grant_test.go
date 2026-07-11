package dwn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// testDelegatedGrant returns a synthetic delegated grant RecordsWrite message
// (including encodedData) issued by did:jwk:wallet to did:jwk:node.
func testDelegatedGrant(t *testing.T) json.RawMessage {
	t.Helper()
	return testDelegatedGrantMessage(t, "grant-delegated", "did:jwk:wallet", "did:jwk:node", PermissionScope{
		Interface: DwnScopeInterfaceRecords,
		Method:    DwnScopeMethodWrite,
		Protocol:  "https://enbox.id/protocols/wireguard-mesh",
	}, "2026-06-24T00:00:00Z")
}

// decodeSignaturePayload decodes the base64url JWS payload of a message.
func decodeSignaturePayload(t *testing.T, msg *Message) map[string]any {
	t.Helper()
	if msg.Authorization == nil || msg.Authorization.Signature == nil {
		t.Fatal("missing authorization signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(msg.Authorization.Signature.Payload)
	if err != nil {
		t.Fatalf("decoding signature payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing signature payload: %v", err)
	}
	return payload
}

func TestComputeDelegatedGrantID(t *testing.T) {
	t.Run("strips truthy encodedData", func(t *testing.T) {
		grant := testDelegatedGrant(t)

		var m map[string]any
		if err := json.Unmarshal(grant, &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m["encodedData"]; !ok {
			t.Fatal("test grant must carry encodedData")
		}

		withEncodedData, err := ComputeCID(m)
		if err != nil {
			t.Fatalf("ComputeCID: %v", err)
		}

		var stripped map[string]any
		if err := json.Unmarshal(grant, &stripped); err != nil {
			t.Fatal(err)
		}
		delete(stripped, "encodedData")
		want, err := ComputeCID(stripped)
		if err != nil {
			t.Fatalf("ComputeCID: %v", err)
		}

		got, err := ComputeDelegatedGrantID(grant)
		if err != nil {
			t.Fatalf("ComputeDelegatedGrantID: %v", err)
		}
		if got != want {
			t.Errorf("ComputeDelegatedGrantID = %s, want %s (encodedData stripped)", got, want)
		}
		if got == withEncodedData {
			t.Error("ComputeDelegatedGrantID must not include encodedData in the CID input")
		}
	})

	t.Run("keeps falsy encodedData", func(t *testing.T) {
		// dwn-sdk-js uses `if (rawMessage.encodedData)` — an empty string is
		// falsy in JS and therefore NOT deleted before CID computation.
		msg := map[string]any{
			"recordId":    "abc",
			"encodedData": "",
			"descriptor":  map[string]any{"interface": "Records", "method": "Write"},
		}
		raw, err := json.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}

		want, err := ComputeCID(map[string]any{
			"recordId":    "abc",
			"encodedData": "",
			"descriptor":  map[string]any{"interface": "Records", "method": "Write"},
		})
		if err != nil {
			t.Fatal(err)
		}

		got, err := ComputeDelegatedGrantID(raw)
		if err != nil {
			t.Fatalf("ComputeDelegatedGrantID: %v", err)
		}
		if got != want {
			t.Errorf("ComputeDelegatedGrantID = %s, want %s (empty encodedData kept)", got, want)
		}
	})

	t.Run("rejects invalid JSON", func(t *testing.T) {
		if _, err := ComputeDelegatedGrantID(json.RawMessage(`not json`)); err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

// TestComputeDelegatedGrantIDInterop pins ComputeDelegatedGrantID to a value
// produced by the real dwn-sdk-js at monorepo HEAD:
//
//	const cid = await Message.getCid(grant)  // core/message.js
//
// run via bun against packages/dwn-sdk-js/dist with the exact grant message
// below (including its truthy encodedData, which getCid strips).
func TestComputeDelegatedGrantIDInterop(t *testing.T) {
	grant := json.RawMessage(`{"recordId":"bafyreib2wblahblahtestrecordid","contextId":"bafyreib2wblahblahtestrecordid","descriptor":{"interface":"Records","method":"Write","protocol":"https://identity.foundation/dwn/permissions","protocolPath":"grant","recipient":"did:jwk:node","dataCid":"bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy","dataSize":156,"dateCreated":"2026-06-23T00:00:00.000000Z","messageTimestamp":"2026-06-23T00:00:00.000000Z","dataFormat":"application/json"},"authorization":{"signature":{"payload":"eyJ0ZXN0IjoxfQ","signatures":[{"protected":"eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpqd2s6d2FsbGV0IzAifQ","signature":"c2ln"}]}},"encodedData":"eyJkYXRlRXhwaXJlcyI6IjIwMjYtMDYtMjRUMDA6MDA6MDBaIiwiZGVsZWdhdGVkIjp0cnVlfQ"}`)
	const want = "bafyreidjxd7sq3z47btue2aortfy5q74jx7uoqlszt2gavh6iseetprvqy"

	got, err := ComputeDelegatedGrantID(grant)
	if err != nil {
		t.Fatalf("ComputeDelegatedGrantID: %v", err)
	}
	if got != want {
		t.Errorf("ComputeDelegatedGrantID = %s, want %s (dwn-sdk-js Message.getCid)", got, want)
	}
}

//
// --- SDK fixture interop (LANE B, genuine dwn-sdk-js output) ---
//

// delegatedGrantFixtureInvocation is a delegate-signed message that the DWN
// accepted, as captured by the fixture generator.
type delegatedGrantFixtureInvocation struct {
	RecordID      string         `json:"recordId"`
	ContextID     string         `json:"contextId"`
	Descriptor    map[string]any `json:"descriptor"`
	Authorization struct {
		Signature            *GeneralJWS     `json:"signature"`
		AuthorDelegatedGrant json.RawMessage `json:"authorDelegatedGrant"`
	} `json:"authorization"`
}

type delegatedGrantFixtureBundle struct {
	DelegatedGrant           json.RawMessage                 `json:"delegatedGrant"`
	ExpectedDelegatedGrantID string                          `json:"expectedDelegatedGrantId"`
	GrantScope               PermissionScope                 `json:"grantScope"`
	Invocation               delegatedGrantFixtureInvocation `json:"invocation"`
	DecodedSignaturePayload  map[string]any                  `json:"decodedSignaturePayload"`
}

type delegatedGrantFixture struct {
	OwnerDID string `json:"ownerDid"`
	Delegate struct {
		DID string `json:"did"`
	} `json:"delegate"`
	RecordsWrite delegatedGrantFixtureBundle `json:"recordsWrite"`
	RecordsQuery delegatedGrantFixtureBundle `json:"recordsQuery"`
}

func loadDelegatedGrantFixture(t *testing.T) *delegatedGrantFixture {
	t.Helper()
	path := filepath.Join("crypto", "testdata", "v1", "delegated_grant.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	var fx delegatedGrantFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("parsing fixture %s: %v", path, err)
	}
	if fx.OwnerDID == "" || fx.Delegate.DID == "" ||
		fx.RecordsWrite.ExpectedDelegatedGrantID == "" || fx.RecordsQuery.ExpectedDelegatedGrantID == "" {
		t.Fatalf("fixture %s missing required fields", path)
	}
	return &fx
}

// grantActiveTime returns a time at which the fixture grant is active,
// derived from the grant itself so the test survives fixture regeneration.
func grantActiveTime(t *testing.T, grant json.RawMessage) time.Time {
	t.Helper()
	var msg struct {
		Descriptor struct {
			DateCreated string `json:"dateCreated"`
		} `json:"descriptor"`
	}
	if err := json.Unmarshal(grant, &msg); err != nil {
		t.Fatalf("parsing grant: %v", err)
	}
	created, err := time.Parse(time.RFC3339, msg.Descriptor.DateCreated)
	if err != nil {
		t.Fatalf("parsing grant dateCreated: %v", err)
	}
	return created.Add(time.Minute)
}

// TestDelegatedGrantFixture verifies wire compatibility against a genuine
// SDK-generated fixture: grant-CID computation, descriptor-CID computation,
// the exact signed payload shape, entry-ID (recordId) semantics for delegated
// writes, and FindDelegatedGrant matching.
func TestDelegatedGrantFixture(t *testing.T) {
	fx := loadDelegatedGrantFixture(t)

	bundles := []struct {
		name        string
		bundle      *delegatedGrantFixtureBundle
		messageType DwnInterface
	}{
		{"recordsWrite", &fx.RecordsWrite, InterfaceRecordsWrite},
		{"recordsQuery", &fx.RecordsQuery, InterfaceRecordsQuery},
	}

	for _, tc := range bundles {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.bundle

			t.Run("grant CID matches SDK getCid", func(t *testing.T) {
				got, err := ComputeDelegatedGrantID(b.DelegatedGrant)
				if err != nil {
					t.Fatalf("ComputeDelegatedGrantID: %v", err)
				}
				if got != b.ExpectedDelegatedGrantID {
					t.Errorf("ComputeDelegatedGrantID = %s, want %s", got, b.ExpectedDelegatedGrantID)
				}

				// The grant embedded in the accepted invocation must produce
				// the same CID (encodedData included in the embedding).
				embedded, err := ComputeDelegatedGrantID(b.Invocation.Authorization.AuthorDelegatedGrant)
				if err != nil {
					t.Fatalf("ComputeDelegatedGrantID(embedded): %v", err)
				}
				if embedded != b.ExpectedDelegatedGrantID {
					t.Errorf("embedded grant CID = %s, want %s", embedded, b.ExpectedDelegatedGrantID)
				}
			})

			t.Run("descriptor CID matches signed payload", func(t *testing.T) {
				got, err := ComputeCID(b.Invocation.Descriptor)
				if err != nil {
					t.Fatalf("ComputeCID(descriptor): %v", err)
				}
				if got != b.DecodedSignaturePayload["descriptorCid"] {
					t.Errorf("descriptor CID = %s, want %v", got, b.DecodedSignaturePayload["descriptorCid"])
				}
			})

			t.Run("signature payload shape", func(t *testing.T) {
				payloadBytes, err := base64.RawURLEncoding.DecodeString(b.Invocation.Authorization.Signature.Payload)
				if err != nil {
					t.Fatalf("decoding invocation payload: %v", err)
				}
				var payload map[string]any
				if err := json.Unmarshal(payloadBytes, &payload); err != nil {
					t.Fatalf("parsing invocation payload: %v", err)
				}
				if !reflect.DeepEqual(payload, b.DecodedSignaturePayload) {
					t.Errorf("signed payload = %v, want %v", payload, b.DecodedSignaturePayload)
				}
				if payload["delegatedGrantId"] != b.ExpectedDelegatedGrantID {
					t.Errorf("payload delegatedGrantId = %v, want %s", payload["delegatedGrantId"], b.ExpectedDelegatedGrantID)
				}
			})

			t.Run("FindDelegatedGrant matches", func(t *testing.T) {
				raw, grant, err := FindDelegatedGrant([]json.RawMessage{b.DelegatedGrant}, PermissionGrantMatch{
					Grantor:     fx.OwnerDID,
					Grantee:     fx.Delegate.DID,
					MessageType: tc.messageType,
					Protocol:    b.GrantScope.Protocol,
					Now:         grantActiveTime(t, b.DelegatedGrant),
				})
				if err != nil {
					t.Fatalf("FindDelegatedGrant: %v", err)
				}
				if grant == nil {
					t.Fatal("FindDelegatedGrant found no match")
				}
				if !grant.Delegated {
					t.Error("fixture grant not parsed as delegated")
				}
				if grant.Scope != b.GrantScope {
					t.Errorf("grant scope = %+v, want %+v", grant.Scope, b.GrantScope)
				}
				if !bytes.Equal(raw, b.DelegatedGrant) {
					t.Error("raw grant bytes not returned verbatim")
				}
			})
		})
	}

	t.Run("recordsWrite entry ID uses grantor as author", func(t *testing.T) {
		inv := fx.RecordsWrite.Invocation

		// Replicate BuildRecordsWrite's entry-ID computation for the
		// fixture's descriptor with author = grantor (owner) and assert it
		// reproduces the recordId the DWN accepted.
		entryIDInput := make(map[string]any, len(inv.Descriptor)+1)
		for k, v := range inv.Descriptor {
			entryIDInput[k] = v
		}
		entryIDInput["author"] = fx.OwnerDID
		got, err := ComputeCID(entryIDInput)
		if err != nil {
			t.Fatalf("ComputeCID(entry ID): %v", err)
		}
		if got != inv.RecordID {
			t.Errorf("entry ID with grantor author = %s, want %s", got, inv.RecordID)
		}

		// Sanity: the delegate (signer) as author must NOT reproduce it.
		entryIDInput["author"] = fx.Delegate.DID
		signerID, err := ComputeCID(entryIDInput)
		if err != nil {
			t.Fatalf("ComputeCID(entry ID, delegate): %v", err)
		}
		if signerID == inv.RecordID {
			t.Error("entry ID must derive from the grantor, not the delegate signer")
		}

		if inv.ContextID != inv.RecordID {
			t.Errorf("root record contextId = %s, want %s", inv.ContextID, inv.RecordID)
		}
	})
}

func TestBuildRecordsWriteDelegated(t *testing.T) {
	s := newTestSigner(t)
	grant := testDelegatedGrant(t)

	result, err := BuildRecordsWrite(s, RecordsWriteOptions{
		Protocol:       "https://enbox.id/protocols/wireguard-mesh",
		ProtocolPath:   "network",
		DataFormat:     "application/json",
		Data:           []byte(`{"name":"test-net"}`),
		DelegatedGrant: grant,
	})
	if err != nil {
		t.Fatalf("BuildRecordsWrite: %v", err)
	}
	msg := result.Message

	t.Run("authorDelegatedGrant preserved verbatim", func(t *testing.T) {
		wire, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("marshaling message: %v", err)
		}
		var envelope struct {
			Authorization struct {
				AuthorDelegatedGrant json.RawMessage `json:"authorDelegatedGrant"`
			} `json:"authorization"`
		}
		if err := json.Unmarshal(wire, &envelope); err != nil {
			t.Fatalf("parsing wire message: %v", err)
		}
		if !bytes.Equal(envelope.Authorization.AuthorDelegatedGrant, grant) {
			t.Errorf("authorDelegatedGrant bytes altered:\n got %s\nwant %s",
				envelope.Authorization.AuthorDelegatedGrant, grant)
		}
	})

	t.Run("delegatedGrantId in signed payload", func(t *testing.T) {
		payload := decodeSignaturePayload(t, msg)

		wantID, err := ComputeDelegatedGrantID(grant)
		if err != nil {
			t.Fatalf("ComputeDelegatedGrantID: %v", err)
		}
		if payload["delegatedGrantId"] != wantID {
			t.Errorf("delegatedGrantId = %v, want %s", payload["delegatedGrantId"], wantID)
		}
		if _, ok := payload["permissionGrantId"]; ok {
			t.Error("permissionGrantId must not appear in a delegated payload")
		}
	})

	t.Run("no permissionGrantId in descriptor", func(t *testing.T) {
		if _, ok := msg.Descriptor["permissionGrantId"]; ok {
			t.Error("descriptor must not carry permissionGrantId for delegated writes")
		}
	})

	t.Run("entry ID uses grantor as author", func(t *testing.T) {
		// The logical author of a delegated write is the grantor.
		entryIDInput := make(map[string]any, len(msg.Descriptor)+1)
		for k, v := range msg.Descriptor {
			entryIDInput[k] = v
		}
		entryIDInput["author"] = "did:jwk:wallet"
		want, err := ComputeCID(entryIDInput)
		if err != nil {
			t.Fatalf("ComputeCID: %v", err)
		}
		if msg.RecordID != want {
			t.Errorf("recordId = %s, want %s (entry ID with grantor as author)", msg.RecordID, want)
		}

		entryIDInput["author"] = s.DID
		signerID, err := ComputeCID(entryIDInput)
		if err != nil {
			t.Fatalf("ComputeCID: %v", err)
		}
		if msg.RecordID == signerID {
			t.Error("recordId derived from signer DID, want grantor DID")
		}
	})
}

func TestBuildRecordsWriteWithoutDelegatedGrantOmitsAuthorDelegatedGrant(t *testing.T) {
	s := newTestSigner(t)

	result, err := BuildRecordsWrite(s, RecordsWriteOptions{
		Protocol:     "https://enbox.id/protocols/wireguard-mesh",
		ProtocolPath: "network",
		DataFormat:   "application/json",
		Data:         []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("BuildRecordsWrite: %v", err)
	}

	wire, err := json.Marshal(result.Message)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Authorization map[string]json.RawMessage `json:"authorization"`
	}
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	if _, ok := envelope.Authorization["authorDelegatedGrant"]; ok {
		t.Error("authorDelegatedGrant must be omitted when no delegated grant is used")
	}
	payload := decodeSignaturePayload(t, result.Message)
	if _, ok := payload["delegatedGrantId"]; ok {
		t.Error("delegatedGrantId must be omitted when no delegated grant is used")
	}
}

func TestGrantInvocationMutualExclusion(t *testing.T) {
	s := newTestSigner(t)
	grant := testDelegatedGrant(t)

	t.Run("RecordsWrite", func(t *testing.T) {
		_, err := BuildRecordsWrite(s, RecordsWriteOptions{
			Protocol:          "https://enbox.id/protocols/wireguard-mesh",
			ProtocolPath:      "network",
			DataFormat:        "application/json",
			Data:              []byte(`{}`),
			PermissionGrantID: "some-grant-id",
			DelegatedGrant:    grant,
		})
		if !errors.Is(err, ErrGrantInvocationConflict) {
			t.Fatalf("err = %v, want ErrGrantInvocationConflict", err)
		}
	})

	t.Run("RecordsRead", func(t *testing.T) {
		_, err := BuildRecordsReadWithAuth(s, RecordsFilter{RecordID: "abc"}, MessageAuth{
			PermissionGrantID: "some-grant-id",
			DelegatedGrant:    grant,
		})
		if !errors.Is(err, ErrGrantInvocationConflict) {
			t.Fatalf("err = %v, want ErrGrantInvocationConflict", err)
		}
	})

	t.Run("RecordsQuery", func(t *testing.T) {
		_, err := BuildRecordsQueryWithAuth(s, RecordsFilter{Protocol: "https://example.com/p"}, "", nil, MessageAuth{
			PermissionGrantID: "some-grant-id",
			DelegatedGrant:    grant,
		})
		if !errors.Is(err, ErrGrantInvocationConflict) {
			t.Fatalf("err = %v, want ErrGrantInvocationConflict", err)
		}
	})

	t.Run("RecordsDelete", func(t *testing.T) {
		_, err := BuildRecordsDeleteWithAuth(s, "record-id", false, MessageAuth{
			PermissionGrantID: "some-grant-id",
			DelegatedGrant:    grant,
		})
		if !errors.Is(err, ErrGrantInvocationConflict) {
			t.Fatalf("err = %v, want ErrGrantInvocationConflict", err)
		}
	})

	t.Run("RecordsSubscribe", func(t *testing.T) {
		_, err := buildSubscribeMessage(s, RecordsFilter{Protocol: "https://example.com/p"}, nil, MessageAuth{
			PermissionGrantID: "some-grant-id",
			DelegatedGrant:    grant,
		})
		if !errors.Is(err, ErrGrantInvocationConflict) {
			t.Fatalf("err = %v, want ErrGrantInvocationConflict", err)
		}
	})
}

// assertDelegatedGenericMessage checks the shared delegated-grant shape of a
// non-RecordsWrite message: grant embedded verbatim, delegatedGrantId in the
// signed payload, nothing in the descriptor.
func assertDelegatedGenericMessage(t *testing.T, msg *Message, grant json.RawMessage) {
	t.Helper()

	wire, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshaling message: %v", err)
	}
	var envelope struct {
		Authorization struct {
			AuthorDelegatedGrant json.RawMessage `json:"authorDelegatedGrant"`
		} `json:"authorization"`
	}
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatalf("parsing wire message: %v", err)
	}
	if !bytes.Equal(envelope.Authorization.AuthorDelegatedGrant, grant) {
		t.Error("authorDelegatedGrant bytes not preserved verbatim")
	}

	wantID, err := ComputeDelegatedGrantID(grant)
	if err != nil {
		t.Fatalf("ComputeDelegatedGrantID: %v", err)
	}
	payload := decodeSignaturePayload(t, msg)
	if payload["delegatedGrantId"] != wantID {
		t.Errorf("delegatedGrantId = %v, want %s", payload["delegatedGrantId"], wantID)
	}
	if _, ok := payload["permissionGrantId"]; ok {
		t.Error("permissionGrantId must not appear in a delegated payload")
	}
	if _, ok := msg.Descriptor["permissionGrantId"]; ok {
		t.Error("descriptor must not carry permissionGrantId for delegated messages")
	}
}

func TestBuildRecordsReadQueryDeleteDelegated(t *testing.T) {
	s := newTestSigner(t)
	grant := testDelegatedGrant(t)
	auth := MessageAuth{DelegatedGrant: grant, ProtocolRole: "network/admin"}

	t.Run("read", func(t *testing.T) {
		msg, err := BuildRecordsReadWithAuth(s, RecordsFilter{RecordID: "abc"}, auth)
		if err != nil {
			t.Fatalf("BuildRecordsReadWithAuth: %v", err)
		}
		assertDelegatedGenericMessage(t, msg, grant)
		payload := decodeSignaturePayload(t, msg)
		if payload["protocolRole"] != "network/admin" {
			t.Errorf("protocolRole = %v, want network/admin", payload["protocolRole"])
		}
	})

	t.Run("query", func(t *testing.T) {
		msg, err := BuildRecordsQueryWithAuth(s, RecordsFilter{Protocol: "https://example.com/p"}, "", nil, MessageAuth{DelegatedGrant: grant})
		if err != nil {
			t.Fatalf("BuildRecordsQueryWithAuth: %v", err)
		}
		assertDelegatedGenericMessage(t, msg, grant)
	})

	t.Run("delete", func(t *testing.T) {
		msg, err := BuildRecordsDeleteWithAuth(s, "record-id", true, MessageAuth{DelegatedGrant: grant})
		if err != nil {
			t.Fatalf("BuildRecordsDeleteWithAuth: %v", err)
		}
		assertDelegatedGenericMessage(t, msg, grant)
	})
}

// TestBuildRecordsReadPlainGrantUnchanged guards the legacy plain-grant path:
// permissionGrantId in descriptor and payload, no authorDelegatedGrant.
func TestBuildRecordsReadPlainGrantUnchanged(t *testing.T) {
	s := newTestSigner(t)

	msg, err := BuildRecordsRead(s, RecordsFilter{RecordID: "abc"}, "", "plain-grant-id")
	if err != nil {
		t.Fatalf("BuildRecordsRead: %v", err)
	}
	if msg.Descriptor["permissionGrantId"] != "plain-grant-id" {
		t.Errorf("descriptor permissionGrantId = %v, want plain-grant-id", msg.Descriptor["permissionGrantId"])
	}
	payload := decodeSignaturePayload(t, msg)
	if payload["permissionGrantId"] != "plain-grant-id" {
		t.Errorf("payload permissionGrantId = %v, want plain-grant-id", payload["permissionGrantId"])
	}
	if msg.Authorization.AuthorDelegatedGrant != nil {
		t.Error("authorDelegatedGrant must be absent for plain grants")
	}
	if _, ok := payload["delegatedGrantId"]; ok {
		t.Error("delegatedGrantId must be absent for plain grants")
	}
}

func TestBuildSubscribeMessageAuthParity(t *testing.T) {
	s := newTestSigner(t)
	grant := testDelegatedGrant(t)
	filter := RecordsFilter{Protocol: "https://example.com/p", ProtocolPath: "network"}

	t.Run("plain grant", func(t *testing.T) {
		msg, err := buildSubscribeMessage(s, filter, &ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1"}, MessageAuth{PermissionGrantID: "plain-grant-id"})
		if err != nil {
			t.Fatalf("buildSubscribeMessage: %v", err)
		}
		if msg.Descriptor["permissionGrantId"] != "plain-grant-id" {
			t.Errorf("descriptor permissionGrantId = %v, want plain-grant-id", msg.Descriptor["permissionGrantId"])
		}
		cursor, ok := msg.Descriptor["cursor"].(ProgressToken)
		if !ok || cursor.StreamID != "stream" || cursor.Epoch != "epoch" || cursor.Position != "1" {
			t.Errorf("descriptor cursor = %#v, want structured progress token", msg.Descriptor["cursor"])
		}
		payload := decodeSignaturePayload(t, msg)
		if payload["permissionGrantId"] != "plain-grant-id" {
			t.Errorf("payload permissionGrantId = %v, want plain-grant-id", payload["permissionGrantId"])
		}
	})

	t.Run("protocol role", func(t *testing.T) {
		msg, err := buildSubscribeMessage(s, filter, nil, MessageAuth{ProtocolRole: "network/node"})
		if err != nil {
			t.Fatalf("buildSubscribeMessage: %v", err)
		}
		payload := decodeSignaturePayload(t, msg)
		if payload["protocolRole"] != "network/node" {
			t.Errorf("payload protocolRole = %v, want network/node", payload["protocolRole"])
		}
	})

	t.Run("delegated grant", func(t *testing.T) {
		msg, err := buildSubscribeMessage(s, filter, nil, MessageAuth{DelegatedGrant: grant})
		if err != nil {
			t.Fatalf("buildSubscribeMessage: %v", err)
		}
		assertDelegatedGenericMessage(t, msg, grant)
		if msg.Descriptor["interface"] != "Records" || msg.Descriptor["method"] != "Subscribe" {
			t.Errorf("descriptor interface/method = %v/%v", msg.Descriptor["interface"], msg.Descriptor["method"])
		}
	})
}
