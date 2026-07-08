package enboxconnect

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/enboxorg/meshd/pkg/dids/didjwk"
)

const testProtocolURI = "https://example.org/protocols/wireguard-mesh"

var testProtocolDefinition = json.RawMessage(fmt.Sprintf(
	`{"protocol":%q,"published":false,"types":{"node":{"schema":"https://example.org/schemas/node.json"}},"structure":{"node":{}}}`,
	testProtocolURI))

// fakeRelay is an httptest-backed connect relay implementing the dwn-server
// routes from http-api.ts #matchConnectRoutes: POST /par,
// GET /authorize/:id.jwt, POST /callback, GET /token/:state.jwt.
// Token responses are served exactly once (single-use).
type fakeRelay struct {
	t      *testing.T
	server *httptest.Server

	mu          sync.Mutex
	requests    map[string]string
	responses   map[string]string
	served      map[string]bool
	nextID      int
	tokenGets   int
	tokenServes int
	servedPolls int // token polls arriving after the response was served
}

func newFakeRelay(t *testing.T) *fakeRelay {
	t.Helper()
	r := &fakeRelay{
		t:         t,
		requests:  map[string]string{},
		responses: map[string]string{},
		served:    map[string]bool{},
	}
	r.server = httptest.NewServer(http.HandlerFunc(r.handle))
	t.Cleanup(r.server.Close)
	return r
}

func (r *fakeRelay) handle(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch {
	case req.Method == http.MethodPost && req.URL.Path == "/par":
		var body struct {
			Request string `json:"request"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.Request == "" {
			http.Error(w, "missing request", http.StatusBadRequest)
			return
		}
		r.nextID++
		id := fmt.Sprintf("req-%d", r.nextID)
		r.requests[id] = body.Request
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"request_uri":%q,"expires_in":600}`, r.server.URL+"/authorize/"+id+".jwt")

	case req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/authorize/"):
		id := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, "/authorize/"), ".jwt")
		jwe, found := r.requests[id]
		if !found {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		io.WriteString(w, jwe)

	case req.Method == http.MethodPost && req.URL.Path == "/callback":
		if err := req.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		idToken := req.PostForm.Get("id_token")
		state := req.PostForm.Get("state")
		if idToken == "" || state == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		r.responses[state] = idToken
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"ok":true}`)

	case req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/token/"):
		state := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, "/token/"), ".jwt")
		r.tokenGets++
		if r.served[state] {
			r.servedPolls++
		}
		idToken, found := r.responses[state]
		if !found {
			http.Error(w, `{"ok":false}`, http.StatusNotFound)
			return
		}
		delete(r.responses, state) // single-use
		r.served[state] = true
		r.tokenServes++
		w.Header().Set("Content-Type", "application/jwt")
		io.WriteString(w, idToken)

	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// testWallet simulates the wallet (provider) side of the connect flow: it
// fetches the request JWE from the relay, decrypts and verifies it, builds
// grants and the signed response, and POSTs the response JWE to the relay
// callback the way enbox-connect-protocol.ts submitConnectResponse does.
type testWallet struct {
	relay    *fakeRelay
	pin      string
	provider *didjwk.Identity

	deny           bool
	granteeDID     string // overrides the request's delegateDid as grantee
	tamperResponse func(*EnboxConnectResponse)
	replaceGrants  func(req *EnboxConnectRequest, grants []json.RawMessage, revocations []SessionRevocation) ([]json.RawMessage, []SessionRevocation)

	gotRequest *EnboxConnectRequest
}

func newTestWallet(t *testing.T, relay *fakeRelay, pin string) *testWallet {
	t.Helper()
	provider, err := didjwk.Create()
	if err != nil {
		t.Fatalf("creating provider identity: %v", err)
	}
	return &testWallet{relay: relay, pin: pin, provider: provider}
}

// handle drives the wallet side for the given wallet URI.
func (wlt *testWallet) handle(t *testing.T, walletURI string) {
	t.Helper()

	u, err := url.Parse(walletURI)
	if err != nil {
		t.Fatalf("parsing wallet URI: %v", err)
	}
	requestURI := u.Query().Get("request_uri")
	encryptionKey, err := base64.RawURLEncoding.DecodeString(u.Query().Get("encryption_key"))
	if err != nil {
		t.Fatalf("decoding encryption_key: %v", err)
	}
	if len(encryptionKey) != 32 {
		t.Fatalf("encryption key length = %d, want 32", len(encryptionKey))
	}

	// Fetch the request JWE from the relay's authorize endpoint.
	resp, err := http.Get(requestURI)
	if err != nil {
		t.Fatalf("fetching request JWE: %v", err)
	}
	jweBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("fetching request JWE: status=%d err=%v", resp.StatusCode, err)
	}

	requestJWT := walletDecryptRequestJWE(t, string(jweBytes), encryptionKey)

	payload, err := verifyJWT(requestJWT)
	if err != nil {
		t.Fatalf("verifying request JWT: %v", err)
	}
	var request EnboxConnectRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatalf("parsing request payload: %v", err)
	}
	wlt.gotRequest = &request

	if wlt.deny {
		wlt.postCallback(t, request.CallbackURL, "DENIED", request.State)
		return
	}

	grantee := request.DelegateDID
	if wlt.granteeDID != "" {
		grantee = wlt.granteeDID
	}

	grants, revocations := wlt.buildGrants(t, &request, grantee)
	if wlt.replaceGrants != nil {
		grants, revocations = wlt.replaceGrants(&request, grants, revocations)
	}

	now := time.Now().Unix()
	response := EnboxConnectResponse{
		ProviderDID:        wlt.provider.URI,
		DelegateDID:        request.DelegateDID,
		Audience:           request.ClientDID,
		IssuedAt:           now,
		ExpiresAt:          now + 600,
		Nonce:              request.Nonce,
		DelegateGrants:     grants,
		SessionRevocations: revocations,
	}
	if wlt.tamperResponse != nil {
		wlt.tamperResponse(&response)
	}

	responseJWE := wlt.sealResponse(t, &request, &response)
	wlt.postCallback(t, request.CallbackURL, responseJWE, request.State)
}

// walletDecryptRequestJWE decrypts a request JWE the way the wallet does
// (enbox-connect-protocol.ts decryptRequest), asserting the byte-exact
// protected header layout on the way.
func walletDecryptRequestJWE(t *testing.T, jwe string, key []byte) string {
	t.Helper()

	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		t.Fatalf("request JWE has %d segments, want 5", len(parts))
	}
	if parts[1] != "" {
		t.Fatalf("request JWE second segment = %q, want empty", parts[1])
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decoding protected header: %v", err)
	}
	if string(headerRaw) != `{"alg":"dir","cty":"JWT","enc":"XC20P","typ":"JWT"}` {
		t.Fatalf("protected header = %s, want the exact SDK byte layout", headerRaw)
	}

	nonce, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding nonce: %v", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		t.Fatalf("decoding ciphertext: %v", err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("decoding tag: %v", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("creating aead: %v", err)
	}
	jwt, err := aead.Open(nil, nonce, append(ciphertext, tag...), headerRaw)
	if err != nil {
		t.Fatalf("decrypting request JWE: %v", err)
	}
	return string(jwt)
}

// buildGrants creates one delegated grant per requested scope plus a
// session-revocation grant for the first one.
func (wlt *testWallet) buildGrants(t *testing.T, request *EnboxConnectRequest, grantee string) ([]json.RawMessage, []SessionRevocation) {
	t.Helper()

	var grants []json.RawMessage
	grantIndex := 0
	for _, permissionRequest := range request.PermissionRequests {
		for _, scope := range permissionRequest.PermissionScopes {
			grantIndex++
			grants = append(grants, makeGrantMessage(t,
				fmt.Sprintf("grant-%d", grantIndex), grantee, wlt.provider.URI+"#0", scopeToMap(t, scope), true))
		}
	}
	if len(grants) == 0 {
		return grants, nil
	}

	revocationScope := map[string]any{
		"interface": "Records",
		"method":    "Write",
		"protocol":  permissionsProtocolURI,
		"contextId": "grant-1",
	}
	grants = append(grants, makeGrantMessage(t, "rev-1", grantee, wlt.provider.URI+"#0", revocationScope, true))
	return grants, []SessionRevocation{{GrantID: "grant-1", RevocationGrantID: "rev-1"}}
}

// sealResponse signs the response JWT with an ephemeral responder did:jwk
// and encrypts it the way enbox-connect-protocol.ts encryptResponse does,
// constructing the protected header and the PIN-bearing AAD literally so
// the byte layout is independent of the code under test.
func (wlt *testWallet) sealResponse(t *testing.T, request *EnboxConnectRequest, response *EnboxConnectResponse) string {
	t.Helper()

	responder, err := didjwk.Create()
	if err != nil {
		t.Fatalf("creating responder identity: %v", err)
	}
	responseJWT, err := signJWT(response, responder.URI+"#0", responder.PrivateKey)
	if err != nil {
		t.Fatalf("signing response JWT: %v", err)
	}

	clientEdPub := ed25519PubFromDIDJWK(t, request.ClientDID)
	sharedKey, err := deriveResponseSharedKey(responder.X25519PrivateKey, clientEdPub)
	if err != nil {
		t.Fatalf("deriving shared key: %v", err)
	}

	epkX := base64.RawURLEncoding.EncodeToString(responder.PublicKey)
	header := fmt.Sprintf(`{"alg":"dir","cty":"JWT","enc":"XC20P","typ":"JWT","epk":{"kty":"OKP","crv":"Ed25519","x":"%s"}}`, epkX)
	aad := header
	if wlt.pin != "" {
		aad = fmt.Sprintf(`{"alg":"dir","cty":"JWT","enc":"XC20P","typ":"JWT","epk":{"kty":"OKP","crv":"Ed25519","x":"%s"},"pin":"%s"}`, epkX, wlt.pin)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}
	aead, err := chacha20poly1305.NewX(sharedKey)
	if err != nil {
		t.Fatalf("creating aead: %v", err)
	}
	ciphertextAndTag := aead.Seal(nil, nonce, []byte(responseJWT), []byte(aad))
	tagOffset := len(ciphertextAndTag) - aead.Overhead()

	return strings.Join([]string{
		base64.RawURLEncoding.EncodeToString([]byte(header)),
		"",
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString(ciphertextAndTag[:tagOffset]),
		base64.RawURLEncoding.EncodeToString(ciphertextAndTag[tagOffset:]),
	}, ".")
}

func (wlt *testWallet) postCallback(t *testing.T, callbackURL, idToken, state string) {
	t.Helper()
	form := url.Values{"id_token": {idToken}, "state": {state}}
	resp, err := http.PostForm(callbackURL, form)
	if err != nil {
		t.Fatalf("posting callback: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("callback status = %d, want 201", resp.StatusCode)
	}
}

// makeGrantMessage builds a minimal grant RecordsWrite message with the
// structural fields grant validation reads.
func makeGrantMessage(t *testing.T, recordID, grantee, grantorKID string, scope map[string]any, delegated bool) json.RawMessage {
	t.Helper()

	dataJSON, err := json.Marshal(map[string]any{
		"dateExpires": "2100-01-01T00:00:00.000000Z",
		"delegated":   delegated,
		"scope":       scope,
	})
	if err != nil {
		t.Fatalf("marshaling grant data: %v", err)
	}
	protectedJSON, err := json.Marshal(map[string]string{"alg": "EdDSA", "kid": grantorKID})
	if err != nil {
		t.Fatalf("marshaling protected header: %v", err)
	}

	msg, err := json.Marshal(map[string]any{
		"recordId": recordID,
		"descriptor": map[string]any{
			"interface":   "Records",
			"method":      "Write",
			"recipient":   grantee,
			"dateCreated": "2026-01-01T00:00:00.000000Z",
		},
		"authorization": map[string]any{
			"signature": map[string]any{
				"payload": "cGF5bG9hZA",
				"signatures": []map[string]string{{
					"protected": base64.RawURLEncoding.EncodeToString(protectedJSON),
					"signature": "c2ln",
				}},
			},
		},
		"encodedData": base64.RawURLEncoding.EncodeToString(dataJSON),
	})
	if err != nil {
		t.Fatalf("marshaling grant message: %v", err)
	}
	return msg
}

func scopeToMap(t *testing.T, scope PermissionScope) map[string]any {
	t.Helper()
	scopeJSON, err := json.Marshal(scope)
	if err != nil {
		t.Fatalf("marshaling scope: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(scopeJSON, &m); err != nil {
		t.Fatalf("unmarshaling scope: %v", err)
	}
	return m
}

// ed25519PubFromDIDJWK extracts the Ed25519 public key embedded in a
// did:jwk URI.
func ed25519PubFromDIDJWK(t *testing.T, uri string) ed25519.PublicKey {
	t.Helper()
	encoded := strings.TrimPrefix(uri, "did:jwk:")
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decoding did:jwk: %v", err)
	}
	var k struct {
		X string `json:"x"`
	}
	if err := json.Unmarshal(decoded, &k); err != nil {
		t.Fatalf("parsing did:jwk JWK: %v", err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		t.Fatalf("decoding public key: %v", err)
	}
	return ed25519.PublicKey(pub)
}

// testOptions returns a working Options wired to the fake relay and wallet.
func testOptions(t *testing.T, relay *fakeRelay, wallet *testWallet, delegateDID string) Options {
	t.Helper()
	return Options{
		AppName:          "meshd test",
		WalletURL:        "https://wallet.example",
		ConnectServerURL: relay.server.URL,
		DelegateDID:      delegateDID,
		PermissionRequests: []PermissionRequest{{
			ProtocolDefinition: testProtocolDefinition,
			Permissions:        []string{"read", "write"},
		}},
		OnWalletURI:  func(uri string) { wallet.handle(t, uri) },
		PINPrompt:    func() (string, error) { return wallet.pin, nil },
		PollInterval: 20 * time.Millisecond,
		Timeout:      5 * time.Second,
	}
}

func newDelegateDID(t *testing.T) string {
	t.Helper()
	delegate, err := didjwk.Create()
	if err != nil {
		t.Fatalf("creating delegate DID: %v", err)
	}
	return delegate.URI
}

func TestConnectHappyPath(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")
	delegateDID := newDelegateDID(t)

	result, err := Connect(context.Background(), testOptions(t, relay, wallet, delegateDID))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if result.OwnerDID != wallet.provider.URI {
		t.Errorf("OwnerDID = %q, want %q", result.OwnerDID, wallet.provider.URI)
	}
	if result.DelegateDID != delegateDID {
		t.Errorf("DelegateDID = %q, want %q", result.DelegateDID, delegateDID)
	}
	// 4 requested scopes (Protocols/Query, Messages/Read, Records/Read,
	// Records/Write) + 1 revocation grant.
	if len(result.Grants) != 5 {
		t.Errorf("len(Grants) = %d, want 5", len(result.Grants))
	}
	if len(result.SessionRevocations) != 1 || result.SessionRevocations[0].GrantID != "grant-1" ||
		result.SessionRevocations[0].RevocationGrantID != "rev-1" {
		t.Errorf("SessionRevocations = %+v", result.SessionRevocations)
	}

	// Request payload assertions (what the wallet saw).
	request := wallet.gotRequest
	if request == nil {
		t.Fatal("wallet never received the request")
	}
	if request.AppName != "meshd test" {
		t.Errorf("appName = %q", request.AppName)
	}
	if request.DelegateDID != delegateDID {
		t.Errorf("delegateDid = %q, want %q", request.DelegateDID, delegateDID)
	}
	if request.ResponseMode != "direct_post" {
		t.Errorf("responseMode = %q, want direct_post", request.ResponseMode)
	}
	if want := relay.server.URL + "/callback"; request.CallbackURL != want {
		t.Errorf("callbackUrl = %q, want %q", request.CallbackURL, want)
	}
	if !reflect.DeepEqual(request.SupportedDIDMethods, []string{"did:dht", "did:jwk"}) {
		t.Errorf("supportedDidMethods = %v", request.SupportedDIDMethods)
	}
	if request.RequestedSessionTTLSeconds != DefaultSessionTTLSeconds {
		t.Errorf("requestedSessionTtlSeconds = %d, want %d", request.RequestedSessionTTLSeconds, DefaultSessionTTLSeconds)
	}
	for name, value := range map[string]string{"nonce": request.Nonce, "state": request.State} {
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(raw) != 16 {
			t.Errorf("%s = %q, want base64url of 16 random bytes", name, value)
		}
	}
	wantScopes := []PermissionScope{
		{Interface: "Protocols", Method: "Query", Protocol: testProtocolURI},
		{Interface: "Messages", Method: "Read", Protocol: testProtocolURI},
		{Interface: "Records", Method: "Read", Protocol: testProtocolURI},
		{Interface: "Records", Method: "Write", Protocol: testProtocolURI},
	}
	if len(request.PermissionRequests) != 1 {
		t.Fatalf("len(permissionRequests) = %d, want 1", len(request.PermissionRequests))
	}
	if !reflect.DeepEqual(request.PermissionRequests[0].PermissionScopes, wantScopes) {
		t.Errorf("permissionScopes = %+v, want %+v", request.PermissionRequests[0].PermissionScopes, wantScopes)
	}

	// Single-use: the token was served exactly once and Connect never
	// polled again after the 200.
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.tokenServes != 1 {
		t.Errorf("tokenServes = %d, want 1", relay.tokenServes)
	}
	if relay.servedPolls != 0 {
		t.Errorf("token polled %d times after being served, want 0", relay.servedPolls)
	}
}

func TestConnectPollsUntilResponse(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")
	delegateDID := newDelegateDID(t)

	var wg sync.WaitGroup
	opts := testOptions(t, relay, wallet, delegateDID)
	opts.OnWalletURI = func(uri string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(150 * time.Millisecond) // let Connect poll 404s first
			wallet.handle(t, uri)
		}()
	}
	defer wg.Wait()

	if _, err := Connect(context.Background(), opts); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.tokenGets < 2 {
		t.Errorf("tokenGets = %d, want at least one pending 404 poll before success", relay.tokenGets)
	}
}

func TestConnectDenied(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")
	wallet.deny = true

	_, err := Connect(context.Background(), testOptions(t, relay, wallet, newDelegateDID(t)))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Connect error = %v, want ErrDenied", err)
	}
}

func TestConnectPollTimeout(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")

	opts := testOptions(t, relay, wallet, newDelegateDID(t))
	opts.OnWalletURI = func(string) {} // wallet never responds
	opts.Timeout = 150 * time.Millisecond
	opts.PollInterval = 30 * time.Millisecond

	_, err := Connect(context.Background(), opts)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Connect error = %v, want ErrTimeout", err)
	}
}

func TestConnectContextCanceled(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")

	ctx, cancel := context.WithCancel(context.Background())
	opts := testOptions(t, relay, wallet, newDelegateDID(t))
	opts.OnWalletURI = func(string) { cancel() }

	_, err := Connect(ctx, opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect error = %v, want context.Canceled", err)
	}
}

func TestConnectWrongPIN(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")

	opts := testOptions(t, relay, wallet, newDelegateDID(t))
	opts.PINPrompt = func() (string, error) { return "9999", nil }

	_, err := Connect(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "decrypting connect response") {
		t.Fatalf("Connect error = %v, want AAD authentication failure", err)
	}
}

func TestConnectEmptyPIN(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")

	opts := testOptions(t, relay, wallet, newDelegateDID(t))
	opts.PINPrompt = func() (string, error) { return "", nil }

	_, err := Connect(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "PIN is required") {
		t.Fatalf("Connect error = %v, want PIN required error", err)
	}
}

func TestConnectDelegateMismatch(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")
	otherDID := newDelegateDID(t)
	wallet.tamperResponse = func(response *EnboxConnectResponse) {
		response.DelegateDID = otherDID
	}

	_, err := Connect(context.Background(), testOptions(t, relay, wallet, newDelegateDID(t)))
	if err == nil || !strings.Contains(err.Error(), "revoke the just-approved session") {
		t.Fatalf("Connect error = %v, want delegate mismatch", err)
	}
}

func TestConnectAudienceMismatch(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")
	wallet.tamperResponse = func(response *EnboxConnectResponse) {
		response.Audience = "did:jwk:somebody-else"
	}

	_, err := Connect(context.Background(), testOptions(t, relay, wallet, newDelegateDID(t)))
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("Connect error = %v, want audience mismatch", err)
	}
}

func TestConnectNonceMismatch(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")
	wallet.tamperResponse = func(response *EnboxConnectResponse) {
		response.Nonce = "bm90LXRoZS1ub25jZQ"
	}

	_, err := Connect(context.Background(), testOptions(t, relay, wallet, newDelegateDID(t)))
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("Connect error = %v, want nonce mismatch", err)
	}
}

func TestConnectExpiredResponse(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")
	wallet.tamperResponse = func(response *EnboxConnectResponse) {
		response.ExpiresAt = time.Now().Unix() - 10
	}

	_, err := Connect(context.Background(), testOptions(t, relay, wallet, newDelegateDID(t)))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Connect error = %v, want expiry error", err)
	}
}

func TestConnectRejectsWrongGrantee(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")
	wallet.granteeDID = newDelegateDID(t) // grants issued to someone else

	_, err := Connect(context.Background(), testOptions(t, relay, wallet, newDelegateDID(t)))
	if err == nil || !strings.Contains(err.Error(), "wallet returned a grant for") {
		t.Fatalf("Connect error = %v, want wrong-grantee rejection", err)
	}
}

func TestConnectRejectsOutOfScopeGrant(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")
	delegateDID := newDelegateDID(t)
	wallet.replaceGrants = func(request *EnboxConnectRequest, grants []json.RawMessage, revocations []SessionRevocation) ([]json.RawMessage, []SessionRevocation) {
		// A Records/Delete grant was never requested.
		extra := makeGrantMessage(t, "grant-extra", delegateDID, wallet.provider.URI+"#0",
			map[string]any{"interface": "Records", "method": "Delete", "protocol": testProtocolURI}, true)
		return append(grants, extra), revocations
	}

	_, err := Connect(context.Background(), testOptions(t, relay, wallet, delegateDID))
	if err == nil || !strings.Contains(err.Error(), "outside the requested permission scope") {
		t.Fatalf("Connect error = %v, want out-of-scope rejection", err)
	}
}

func TestConnectRejectsUnlistedRevocationGrant(t *testing.T) {
	relay := newFakeRelay(t)
	wallet := newTestWallet(t, relay, "1234")
	wallet.replaceGrants = func(request *EnboxConnectRequest, grants []json.RawMessage, revocations []SessionRevocation) ([]json.RawMessage, []SessionRevocation) {
		// Keep the revocation grant but drop its sessionRevocations entry:
		// it must then fail the requested-scope check.
		return grants, nil
	}

	_, err := Connect(context.Background(), testOptions(t, relay, wallet, newDelegateDID(t)))
	if err == nil || !strings.Contains(err.Error(), "outside the requested permission scope") {
		t.Fatalf("Connect error = %v, want out-of-scope rejection", err)
	}
}

func TestConnectValidatesOptions(t *testing.T) {
	base := func() Options {
		return Options{
			AppName:            "app",
			WalletURL:          "https://wallet.example",
			DelegateDID:        "did:jwk:abc",
			PermissionRequests: []PermissionRequest{{ProtocolDefinition: testProtocolDefinition, Permissions: []string{"read"}}},
			OnWalletURI:        func(string) {},
			PINPrompt:          func() (string, error) { return "1234", nil },
		}
	}

	cases := map[string]func(*Options){
		"AppName":            func(o *Options) { o.AppName = "" },
		"WalletURL":          func(o *Options) { o.WalletURL = "" },
		"DelegateDID":        func(o *Options) { o.DelegateDID = "" },
		"PermissionRequests": func(o *Options) { o.PermissionRequests = nil },
		"OnWalletURI":        func(o *Options) { o.OnWalletURI = nil },
		"PINPrompt":          func(o *Options) { o.PINPrompt = nil },
	}
	for name, mutate := range cases {
		opts := base()
		mutate(&opts)
		if _, err := Connect(context.Background(), opts); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: error = %v, want mention of %s", name, err, name)
		}
	}
}
