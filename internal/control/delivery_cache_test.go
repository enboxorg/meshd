package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
)

type deliveryTestMaterial struct {
	manager        *dwncrypto.EncryptionKeyManager
	deliveryEntry  json.RawMessage
	audiencePublic []byte
	protocol       string
	rolePath       string
}

func newDeliveryTestMaterial(t *testing.T, protocol, rolePath string) *deliveryTestMaterial {
	t.Helper()

	holderRoot, _, err := dwncrypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair(holder): %v", err)
	}
	holderRolePrivate, err := dwncrypto.DeriveRolePathKey(holderRoot, protocol, rolePath)
	if err != nil {
		t.Fatalf("DeriveRolePathKey(holder): %v", err)
	}
	holderRolePublic, err := dwncrypto.X25519PublicKey(holderRolePrivate)
	clear(holderRolePrivate)
	if err != nil {
		t.Fatalf("X25519PublicKey(holder role): %v", err)
	}

	audience, err := dwncrypto.GenerateAudienceKey()
	if err != nil {
		t.Fatalf("GenerateAudienceKey: %v", err)
	}
	audiencePublic, err := base64.RawURLEncoding.DecodeString(audience.PublicKeyJwk.X)
	if err != nil {
		t.Fatalf("decode audience public key: %v", err)
	}
	payload := dwncrypto.DeliveryPayload{
		Protocol:    protocol,
		RolePath:    rolePath,
		ContextID:   "network-record",
		KeyID:       audience.KeyID,
		KeyMaterial: *audience,
	}
	payloadJSON, err := json.Marshal(&payload)
	if err != nil {
		t.Fatalf("marshal delivery payload: %v", err)
	}
	deliveryData, deliveryEncryption, err := dwncrypto.EncryptData(payloadJSON, []dwncrypto.KeyEncryptionInput{
		{PublicKey: holderRolePublic, DerivationScheme: dwncrypto.DerivationSchemeProtocolPath},
	})
	if err != nil {
		t.Fatalf("encrypt delivery payload: %v", err)
	}
	deliveryEntry, err := json.Marshal(map[string]any{
		"recordId":    "delivery-record",
		"encodedData": base64.RawURLEncoding.EncodeToString(deliveryData),
		"encryption":  deliveryEncryption,
	})
	if err != nil {
		t.Fatalf("marshal delivery entry: %v", err)
	}

	return &deliveryTestMaterial{
		manager: &dwncrypto.EncryptionKeyManager{
			RootPrivateKey: holderRoot,
			ProtocolURI:    protocol,
		},
		deliveryEntry:  deliveryEntry,
		audiencePublic: audiencePublic,
		protocol:       protocol,
		rolePath:       rolePath,
	}
}

func (m *deliveryTestMaterial) encryptRecord(t *testing.T, plaintext []byte) ([]byte, *dwncrypto.Encryption, *dwncrypto.RoleAudienceInfo) {
	t.Helper()

	ciphertext, encryption, err := dwncrypto.EncryptData(plaintext, []dwncrypto.KeyEncryptionInput{
		{
			PublicKey:        m.audiencePublic,
			DerivationScheme: dwncrypto.DerivationSchemeRoleAudience,
			Protocol:         m.protocol,
			RolePath:         m.rolePath,
		},
	})
	if err != nil {
		t.Fatalf("encrypt role-audience record: %v", err)
	}
	info := dwncrypto.RoleAudienceEntryInfo(encryption)
	if info == nil {
		t.Fatal("encrypted record has no role-audience info")
	}
	return ciphertext, encryption, info
}

func newDeliveryTestClient(t *testing.T, endpoint string, material *deliveryTestMaterial) *DWNClient {
	t.Helper()

	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("generate query signer: %v", err)
	}
	signer := &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey}
	return NewDWNClient(
		endpoint,
		"did:example:anchor",
		"network-record",
		identity.URI,
		signer,
		WithEncryptionKeyManager(material.manager),
		WithProtocolRole(material.rolePath),
	)
}

func TestDecryptViaDeliveryCachesAudienceKey(t *testing.T) {
	material := newDeliveryTestMaterial(t, "https://example.com/mesh", "network/member")
	var queries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		queries.Add(1)
		sealedMockReply(t, w, "query", dwn.Status{Code: http.StatusOK, Detail: "OK"}, []json.RawMessage{
			material.deliveryEntry,
		})
	}))
	defer server.Close()

	client := newDeliveryTestClient(t, server.URL, material)
	for _, plaintext := range [][]byte{[]byte("first record"), []byte("second record")} {
		ciphertext, encryption, info := material.encryptRecord(t, plaintext)
		got, err := client.decryptViaDelivery(context.Background(), ciphertext, encryption, info)
		if err != nil {
			t.Fatalf("decryptViaDelivery(%q): %v", plaintext, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext = %q, want %q", got, plaintext)
		}
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("delivery queries = %d, want 1 for shared audience key", got)
	}
}

func TestDecryptViaDeliveryRetriesDWNReplyRateLimitThenCaches(t *testing.T) {
	material := newDeliveryTestMaterial(t, "https://example.com/mesh", "network/member")
	var queries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if queries.Add(1) == 1 {
			// The HTTP request succeeds; the DWN reply itself carries the 429.
			sealedMockReply(t, w, "query", dwn.Status{
				Code: http.StatusTooManyRequests, Detail: "RateLimitExceeded: retry after 0s",
			}, nil)
			return
		}
		sealedMockReply(t, w, "query", dwn.Status{Code: http.StatusOK, Detail: "OK"}, []json.RawMessage{
			material.deliveryEntry,
		})
	}))
	defer server.Close()

	client := newDeliveryTestClient(t, server.URL, material)
	for _, plaintext := range [][]byte{[]byte("after retry"), []byte("from cache")} {
		ciphertext, encryption, info := material.encryptRecord(t, plaintext)
		got, err := client.decryptViaDelivery(context.Background(), ciphertext, encryption, info)
		if err != nil {
			t.Fatalf("decryptViaDelivery(%q): %v", plaintext, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext = %q, want %q", got, plaintext)
		}
	}
	if got := queries.Load(); got != 2 {
		t.Fatalf("delivery queries = %d, want first 429 plus one successful retry", got)
	}
}

func TestDecryptViaDeliveryDefersLongRetryToNextPoll(t *testing.T) {
	material := newDeliveryTestMaterial(t, "https://example.com/mesh", "network/member")
	var queries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		queries.Add(1)
		w.Header().Set("Retry-After", "6")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(dwn.JsonRpcResponse{
			JSONRPC: "2.0",
			Error: &dwn.JsonRpcError{
				Code:    dwn.JsonRpcTooManyRequests,
				Message: "tenant rate limit exceeded",
			},
		})
	}))
	defer server.Close()

	client := newDeliveryTestClient(t, server.URL, material)
	ciphertext, encryption, info := material.encryptRecord(t, []byte("record"))
	_, err := client.decryptViaDelivery(context.Background(), ciphertext, encryption, info)
	if !errors.Is(err, dwn.ErrRateLimited) {
		t.Fatalf("decryptViaDelivery error = %v, want ErrRateLimited", err)
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("delivery queries = %d, want 1 when Retry-After exceeds bound", got)
	}
}
