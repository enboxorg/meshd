package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/protocols"
)

// sealedTestOwner creates a network owner identity with its signer, encryption
// key manager, and INSTALLED mesh protocol definition (with $keyAgreement
// public keys injected from the owner's encryption root).
func sealedTestOwner(t *testing.T) (*did.DID, *dwn.Signer, *dwncrypto.EncryptionKeyManager, json.RawMessage) {
	t.Helper()

	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("generating DID: %v", err)
	}
	signer := &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey}
	mgr := &dwncrypto.EncryptionKeyManager{
		RootPrivateKey: identity.EncryptionPrivateKey,
		RootKeyID:      identity.EncryptionKeyID(),
		ProtocolURI:    protocols.MeshProtocolURI,
	}
	def, err := dwncrypto.InjectEncryptionDirectives(protocols.MeshProtocolJSON, identity.EncryptionPrivateKey)
	if err != nil {
		t.Fatalf("InjectEncryptionDirectives: %v", err)
	}
	return identity, signer, mgr, def
}

// sealedMockReply writes a JSON-RPC DWN reply with the given entries.
func sealedMockReply(t *testing.T, w http.ResponseWriter, id string, status dwn.Status, entries []json.RawMessage) {
	t.Helper()

	var entriesJSON json.RawMessage
	if entries != nil {
		var err error
		entriesJSON, err = json.Marshal(entries)
		if err != nil {
			t.Fatalf("marshal entries: %v", err)
		}
	}
	reply := &dwn.JsonRpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: &dwn.JsonRpcResult{
			Reply: &dwn.DwnReply{Status: status, Entries: entriesJSON},
		},
	}
	if err := json.NewEncoder(w).Encode(reply); err != nil {
		t.Fatalf("write DWN reply: %v", err)
	}
}

// audienceQueryEntry builds a `$encryption/audience` query entry carrying the
// given payload inline.
func audienceQueryEntry(t *testing.T, recordID string, payload *dwncrypto.AudiencePayload) json.RawMessage {
	t.Helper()

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal audience payload: %v", err)
	}
	entry, err := json.Marshal(map[string]any{
		"recordId": recordID,
		"descriptor": map[string]any{
			"interface":    "Records",
			"method":       "Write",
			"protocol":     payload.Protocol,
			"protocolPath": dwncrypto.EncryptionControlAudiencePath,
			"dateCreated":  "2026-01-01T00:00:00.000000Z",
		},
		"encodedData": base64.RawURLEncoding.EncodeToString(data),
	})
	if err != nil {
		t.Fatalf("marshal audience entry: %v", err)
	}
	return entry
}

// TestSealedAudienceSourceServesExistingAudience covers the sealed read/write
// chain against a mock DWN serving an existing `$encryption/audience` record:
// Current() resolves the advertised audience key without minting, and the
// owner recovers the audience PRIVATE key by unsealing the record with its
// role-path seal key, decrypting a roleAudience-encrypted record.
func TestSealedAudienceSourceServesExistingAudience(t *testing.T) {
	owner, signer, mgr, def := sealedTestOwner(t)

	const rolePath = "network/node"
	const contextID = "net-root"

	// Pre-mint an audience key sealed to the owner's role-path $keyAgreement
	// key (what the wallet/SDK would have written).
	sealingPub, _, err := dwncrypto.KeyAgreementPublicKeyAtPath(def, rolePath)
	if err != nil {
		t.Fatalf("KeyAgreementPublicKeyAtPath: %v", err)
	}
	km, err := dwncrypto.GenerateAudienceKey()
	if err != nil {
		t.Fatalf("GenerateAudienceKey: %v", err)
	}
	payload, err := dwncrypto.BuildAudiencePayload(km, sealingPub, protocols.MeshProtocolURI, rolePath, contextID)
	if err != nil {
		t.Fatalf("BuildAudiencePayload: %v", err)
	}

	var (
		mintMu     sync.Mutex
		mintWrites int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rpcReq dwn.JsonRpcRequest
		if err := json.Unmarshal([]byte(r.Header.Get("dwn-request")), &rpcReq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		msg := rpcReq.Params.Message
		switch descriptorStringValue(msg.Descriptor, "method") {
		case "Query":
			filter, _ := msg.Descriptor["filter"].(map[string]any)
			if descriptorStringValue(filter, "protocolPath") != dwncrypto.EncryptionControlAudiencePath {
				sealedMockReply(t, w, rpcReq.ID, dwn.Status{Code: 200, Detail: "OK"}, nil)
				return
			}
			sealedMockReply(t, w, rpcReq.ID, dwn.Status{Code: 200, Detail: "OK"}, []json.RawMessage{
				audienceQueryEntry(t, "audience-1", payload),
			})
		case "Write":
			mintMu.Lock()
			mintWrites++
			mintMu.Unlock()
			sealedMockReply(t, w, rpcReq.ID, dwn.Status{Code: 202, Detail: "Accepted"}, nil)
		default:
			sealedMockReply(t, w, rpcReq.ID, dwn.Status{Code: 400, Detail: "Unexpected method"}, nil)
		}
	}))
	defer server.Close()

	src := NewSealedAudienceSource(SealedAudienceSourceConfig{
		Client:             dwn.NewClient(server.URL, signer),
		Tenant:             owner.URI,
		ProtocolDefinition: def,
		SealKeys:           OwnerRolePathKeys{Manager: mgr},
	})

	ctx := context.Background()
	pub, keyID, err := src.Current(ctx, protocols.MeshProtocolURI, rolePath, contextID)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if keyID != km.KeyID {
		t.Fatalf("keyID = %q, want %q", keyID, km.KeyID)
	}
	if got := base64.RawURLEncoding.EncodeToString(pub); got != km.PublicKeyJwk.X {
		t.Fatalf("public key = %q, want %q", got, km.PublicKeyJwk.X)
	}
	mintMu.Lock()
	gotMints := mintWrites
	mintMu.Unlock()
	if gotMints != 0 {
		t.Fatalf("mintWrites = %d, want 0 (an audience record already exists)", gotMints)
	}

	// Role-audience decryption: a writer wraps the CEK to the audience key;
	// the owner unseals the audience record to recover the private key.
	plaintext := []byte(`{"meshIP":"10.200.0.9","addedAt":"2026-01-01T00:00:00Z"}`)
	ciphertext, enc, err := dwncrypto.EncryptData(plaintext, []dwncrypto.KeyEncryptionInput{
		{
			PublicKey:        pub,
			DerivationScheme: dwncrypto.DerivationSchemeRoleAudience,
			Protocol:         protocols.MeshProtocolURI,
			RolePath:         rolePath,
		},
	})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	audiencePriv, err := src.AudiencePrivateKeyByKeyID(ctx, protocols.MeshProtocolURI, rolePath, keyID)
	if err != nil {
		t.Fatalf("AudiencePrivateKeyByKeyID: %v", err)
	}
	dec, err := dwncrypto.NewRoleAudienceDecrypter(audiencePriv)
	if err != nil {
		t.Fatalf("NewRoleAudienceDecrypter: %v", err)
	}
	defer dec.Close()

	got, err := dec.Decrypt(ciphertext, enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted = %q, want %q", got, plaintext)
	}
}

// TestSealedAudienceSourceMintsOnMiss verifies mint-on-miss: when no audience
// record exists for a tuple, the source generates a fresh audience key, seals
// its private half to the owner's role-path key, writes the audience record
// (with the required path, schema, and tags), and returns the new key.
func TestSealedAudienceSourceMintsOnMiss(t *testing.T) {
	owner, signer, mgr, def := sealedTestOwner(t)

	const rolePath = "network/member"
	const contextID = "net-root"

	var (
		mu           sync.Mutex
		mintedData   []byte
		mintedPath   string
		mintedSchema string
		mintedTags   map[string]any
		queryCount   int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rpcReq dwn.JsonRpcRequest
		if err := json.Unmarshal([]byte(r.Header.Get("dwn-request")), &rpcReq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		msg := rpcReq.Params.Message
		switch descriptorStringValue(msg.Descriptor, "method") {
		case "Query":
			mu.Lock()
			queryCount++
			mu.Unlock()
			sealedMockReply(t, w, rpcReq.ID, dwn.Status{Code: 200, Detail: "OK"}, nil)
		case "Write":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			mintedData = body
			mintedPath = descriptorStringValue(msg.Descriptor, "protocolPath")
			mintedSchema = descriptorStringValue(msg.Descriptor, "schema")
			mintedTags, _ = msg.Descriptor["tags"].(map[string]any)
			mu.Unlock()
			sealedMockReply(t, w, rpcReq.ID, dwn.Status{Code: 202, Detail: "Accepted"}, nil)
		default:
			sealedMockReply(t, w, rpcReq.ID, dwn.Status{Code: 400, Detail: "Unexpected method"}, nil)
		}
	}))
	defer server.Close()

	src := NewSealedAudienceSource(SealedAudienceSourceConfig{
		Client:             dwn.NewClient(server.URL, signer),
		Tenant:             owner.URI,
		ProtocolDefinition: def,
		SealKeys:           OwnerRolePathKeys{Manager: mgr},
	})

	ctx := context.Background()
	pub, keyID, err := src.Current(ctx, protocols.MeshProtocolURI, rolePath, contextID)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	mu.Lock()
	gotData := mintedData
	gotPath := mintedPath
	gotSchema := mintedSchema
	gotTags := mintedTags
	queriesBefore := queryCount
	mu.Unlock()

	if gotData == nil {
		t.Fatal("no audience record was minted")
	}
	if gotPath != dwncrypto.EncryptionControlAudiencePath {
		t.Errorf("minted protocolPath = %q, want %q", gotPath, dwncrypto.EncryptionControlAudiencePath)
	}
	if gotSchema != dwncrypto.EncryptionControlAudienceSchemaURI {
		t.Errorf("minted schema = %q, want %q", gotSchema, dwncrypto.EncryptionControlAudienceSchemaURI)
	}
	wantTags := map[string]string{
		"protocol":  protocols.MeshProtocolURI,
		"rolePath":  rolePath,
		"contextId": contextID,
		"keyId":     keyID,
	}
	for tag, want := range wantTags {
		if got, _ := gotTags[tag].(string); got != want {
			t.Errorf("minted tag %q = %q, want %q", tag, got, want)
		}
	}

	// The minted record must unseal with the owner's role-path key and
	// derive the public key Current returned.
	var payload dwncrypto.AudiencePayload
	if err := json.Unmarshal(gotData, &payload); err != nil {
		t.Fatalf("parsing minted payload: %v", err)
	}
	if payload.KeyID != keyID {
		t.Fatalf("minted keyId = %q, want %q", payload.KeyID, keyID)
	}
	sealKey, err := mgr.DeriveDecryptionKey(rolePath)
	if err != nil {
		t.Fatalf("DeriveDecryptionKey: %v", err)
	}
	audiencePriv, err := dwncrypto.UnsealAudienceRecord(&payload, sealKey)
	if err != nil {
		t.Fatalf("UnsealAudienceRecord: %v", err)
	}
	derivedPub, err := dwncrypto.X25519PublicKey(audiencePriv)
	if err != nil {
		t.Fatalf("X25519PublicKey: %v", err)
	}
	if !bytes.Equal(derivedPub, pub) {
		t.Fatal("unsealed audience private key does not derive the returned public key")
	}

	// A second Current for the same tuple is served from the cache.
	pub2, keyID2, err := src.Current(ctx, protocols.MeshProtocolURI, rolePath, contextID)
	if err != nil {
		t.Fatalf("Current (cached): %v", err)
	}
	if keyID2 != keyID || !bytes.Equal(pub2, pub) {
		t.Fatal("cached Current returned a different audience key")
	}
	mu.Lock()
	queriesAfter := queryCount
	mu.Unlock()
	if queriesAfter != queriesBefore {
		t.Errorf("cached Current issued %d extra queries", queriesAfter-queriesBefore)
	}
}

// TestSealedAudienceSourceRefusesMintWithoutSealKeys verifies the seal
// coverage guard: a source without seal keys must not mint (an unsealable
// audience record would be unrecoverable).
func TestSealedAudienceSourceRefusesMintWithoutSealKeys(t *testing.T) {
	owner, signer, _, def := sealedTestOwner(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rpcReq dwn.JsonRpcRequest
		if err := json.Unmarshal([]byte(r.Header.Get("dwn-request")), &rpcReq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if descriptorStringValue(rpcReq.Params.Message.Descriptor, "method") == "Write" {
			t.Error("read-only audience source attempted a mint write")
		}
		sealedMockReply(t, w, rpcReq.ID, dwn.Status{Code: 200, Detail: "OK"}, nil)
	}))
	defer server.Close()

	src := NewSealedAudienceSource(SealedAudienceSourceConfig{
		Client:             dwn.NewClient(server.URL, signer),
		Tenant:             owner.URI,
		ProtocolDefinition: def,
		// No SealKeys: read-only.
	})

	if _, _, err := src.Current(context.Background(), protocols.MeshProtocolURI, "network/node", "net-root"); err == nil {
		t.Fatal("expected Current to fail without seal keys when no audience record exists")
	}
}

// TestGrantKeySetSubtreeDecryption covers the delegate decryption chain: a
// grantKey-delivered whole-protocol subtree key derives the same role-path
// seal keys as the owner root and decrypts protocolPath-encrypted records at
// covered paths.
func TestGrantKeySetSubtreeDecryption(t *testing.T) {
	_, _, mgr, _ := sealedTestOwner(t)
	protocol := protocols.MeshProtocolURI

	// Owner side: derive the whole-protocol subtree key a wallet would
	// deliver via a grantKey record for a protocol-wide Read grant.
	subtreePriv, err := dwncrypto.DeriveKeyBytes(mgr.RootPrivateKey, []string{
		dwncrypto.DerivationSchemeProtocolPath, protocol,
	})
	if err != nil {
		t.Fatalf("DeriveKeyBytes: %v", err)
	}
	subtreePub, err := dwncrypto.X25519PublicKey(subtreePriv)
	if err != nil {
		t.Fatalf("X25519PublicKey: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(subtreePub)

	payload := &dwncrypto.GrantKeyPayload{
		GrantID: "grant-1",
		Scope: dwncrypto.GrantKeyScope{
			Scheme:   dwncrypto.DerivationSchemeProtocolPath,
			Protocol: protocol,
		},
		KeyMaterial: dwncrypto.ProtocolPathKeyMaterial{
			Algorithm:        dwncrypto.AlgX25519HKDFA256KW,
			DerivationScheme: dwncrypto.DerivationSchemeProtocolPath,
			DerivationPath:   []string{dwncrypto.DerivationSchemeProtocolPath, protocol},
			KeyID:            dwncrypto.JWKThumbprintX25519(x),
			PublicKeyJwk:     dwncrypto.PublicKeyJWK{KTY: "OKP", CRV: "X25519", X: x},
			PrivateKeyJwk: dwncrypto.PrivateKeyJWK{
				KTY: "OKP", CRV: "X25519", X: x,
				D: base64.RawURLEncoding.EncodeToString(subtreePriv),
			},
		},
	}

	dec, err := dwncrypto.NewSubtreeDecrypterFromGrantKey(payload)
	if err != nil {
		t.Fatalf("NewSubtreeDecrypterFromGrantKey: %v", err)
	}
	set := &GrantKeySet{decrypters: []*dwncrypto.SubtreeDecrypter{dec}}
	defer set.Close()

	if set.Empty() {
		t.Fatal("GrantKeySet reports empty")
	}

	// Role-path seal key parity with the owner root: holding the covering
	// subtree key authorizes minting/unsealing audience records.
	sealKey, err := set.RolePathPrivateKey(protocol, "network/node")
	if err != nil {
		t.Fatalf("RolePathPrivateKey: %v", err)
	}
	ownerSealKey, err := mgr.DeriveDecryptionKey("network/node")
	if err != nil {
		t.Fatalf("DeriveDecryptionKey: %v", err)
	}
	if !bytes.Equal(sealKey, ownerSealKey) {
		t.Fatal("grant-key role-path seal key differs from the owner-derived key")
	}

	// Subtree decryption of a protocolPath-encrypted record at a covered path.
	_, leafPub, err := dwncrypto.DerivePrivateKey(
		mgr.RootPrivateKey,
		dwncrypto.BuildProtocolPathDerivation(protocol, "network", "node", "endpoint"),
	)
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}
	plaintext := []byte(`{"natType":"full-cone"}`)
	ciphertext, enc, err := dwncrypto.EncryptData(plaintext, []dwncrypto.KeyEncryptionInput{
		{PublicKey: leafPub, DerivationScheme: dwncrypto.DerivationSchemeProtocolPath},
	})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	covering := set.DecrypterFor(protocol, "network/node/endpoint")
	if covering == nil {
		t.Fatal("no decrypter covers network/node/endpoint")
	}
	got, err := covering.Decrypt(ciphertext, enc, protocol, "network/node/endpoint")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted = %q, want %q", got, plaintext)
	}

	// An uncovered protocol is rejected.
	if set.DecrypterFor("https://example.com/other", "network/node") != nil {
		t.Fatal("decrypter claims to cover a foreign protocol")
	}
}

// descriptorStringValue returns the string value of a descriptor field.
func descriptorStringValue(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}
