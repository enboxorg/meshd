// Package enboxconnect implements the client side of the Enbox connect
// relay flow in pre-supplied delegate mode: meshd pushes an encrypted,
// signed permission request to a connect relay, the user approves it in
// their wallet, and the wallet returns delegated DWN permission grants for
// meshd's existing delegate DID through the relay, sealed to an ephemeral
// client DID with an out-of-band PIN as additional authenticated data.
//
// Wire compatibility follows the TypeScript sources at enbox monorepo HEAD:
// packages/auth/src/wallet-connect-client.ts (initClient),
// packages/agent/src/enbox-connect-protocol.ts (JWT/JWE construction),
// packages/auth/src/connect/validate-grants.ts (grant validation),
// packages/cli/src/cli-connect-handler.ts (discovery and defaults), and
// packages/dwn-server/src/http-api.ts (relay endpoints).
//
// This is a pure protocol package: it performs no meshd state I/O.
package enboxconnect

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/enboxorg/meshd/pkg/dids/didjwk"
)

// Defaults mirroring the SDK connect client and CLI handler.
const (
	// DefaultPollInterval is the relay polling interval
	// (wallet-connect-client.ts pollIntervalMs default).
	DefaultPollInterval = 3 * time.Second

	// DefaultTimeout is how long to wait for wallet approval
	// (wallet-connect-client.ts timeoutMs default).
	DefaultTimeout = 5 * time.Minute

	// DefaultSessionTTLSeconds is the requested session TTL
	// (cli-connect-handler.ts DEFAULT_CLI_SESSION_TTL_SECONDS, 30 days).
	// Wallets may clamp it to their policy maximum.
	DefaultSessionTTLSeconds = 30 * 24 * 60 * 60
)

// Sentinel errors.
var (
	// ErrDenied is returned when the user denies the request in the wallet.
	ErrDenied = errors.New("enboxconnect: wallet denied the connect request")

	// ErrTimeout is returned when the wallet does not respond before the
	// poll timeout elapses.
	ErrTimeout = errors.New("enboxconnect: timed out waiting for the wallet response")
)

// Options configures a Connect flow.
type Options struct {
	// AppName is the human-readable requester name shown in the wallet
	// consent UI. Required.
	AppName string

	// WalletURL is the wallet app URL. A bare origin gets /connect/app
	// appended. Required.
	WalletURL string

	// ConnectServerURL is the connect relay URL. When empty it is
	// discovered from the wallet origin's /.well-known/enbox-connect
	// document.
	ConnectServerURL string

	// DelegateDID is meshd's existing delegate DID URI. The wallet grants
	// permissions to this DID; its keys never leave this process.
	// Required.
	DelegateDID string

	// PermissionRequests names the protocols and record permissions to
	// request. Required (at least one).
	PermissionRequests []PermissionRequest

	// RequestedTTLSeconds is the preferred session TTL in seconds.
	// Defaults to DefaultSessionTTLSeconds. Wallets may clamp it.
	RequestedTTLSeconds int

	// OnWalletURI receives the wallet URI (with request_uri and
	// encryption_key in the URI fragment) to hand to the user. Required.
	OnWalletURI func(string)

	// PINPrompt collects the PIN the wallet displays after approval.
	// Required; the PIN must be non-empty.
	PINPrompt func() (string, error)

	// PollInterval is the delay between relay polls. Defaults to
	// DefaultPollInterval.
	PollInterval time.Duration

	// Timeout bounds the overall wait for the wallet response. Defaults
	// to DefaultTimeout.
	Timeout time.Duration

	// HTTPClient overrides the HTTP client used for relay requests.
	HTTPClient *http.Client
}

// Result is the validated outcome of a successful connect flow.
type Result struct {
	// OwnerDID is the wallet owner's DID that authorized the delegation
	// (the response's providerDid).
	OwnerDID string

	// DelegateDID is the delegate DID the grants were issued to.
	DelegateDID string

	// Grants are the delegate grant RecordsWrite messages exactly as
	// received (including encodedData), ready for delegated invocation.
	Grants []json.RawMessage

	// SessionRevocations maps each session grant to the grant that
	// authorizes the delegate to revoke it.
	SessionRevocations []SessionRevocation
}

// Connect runs the full relay-mediated connect flow and returns the
// validated grants. It mirrors initClient in
// packages/auth/src/wallet-connect-client.ts, restricted to pre-supplied
// delegate mode.
func Connect(ctx context.Context, opts Options) (*Result, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	pollInterval := opts.PollInterval
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ttlSeconds := opts.RequestedTTLSeconds
	if ttlSeconds <= 0 {
		ttlSeconds = DefaultSessionTTLSeconds
	}

	connectServerURL := opts.ConnectServerURL
	if connectServerURL == "" {
		discovered, err := DiscoverConnectServerURL(ctx, opts.WalletURL)
		if err != nil {
			return nil, fmt.Errorf("enboxconnect: discovering connect relay from wallet origin: %w", err)
		}
		connectServerURL = discovered
	}

	// Ephemeral client did:jwk for request signing and response ECDH.
	client, err := didjwk.Create()
	if err != nil {
		return nil, fmt.Errorf("enboxconnect: creating ephemeral client DID: %w", err)
	}
	clientKID, err := clientVerificationMethodID(client.URI)
	if err != nil {
		return nil, err
	}

	permissionRequests, err := buildConnectPermissionRequests(opts.PermissionRequests)
	if err != nil {
		return nil, fmt.Errorf("enboxconnect: %w", err)
	}

	nonce, err := randomBase64URL(16)
	if err != nil {
		return nil, fmt.Errorf("enboxconnect: generating nonce: %w", err)
	}
	state, err := randomBase64URL(16)
	if err != nil {
		return nil, fmt.Errorf("enboxconnect: generating state: %w", err)
	}

	request := EnboxConnectRequest{
		ClientDID:                  client.URI,
		AppName:                    opts.AppName,
		RequestedSessionTTLSeconds: ttlSeconds,
		DelegateDID:                opts.DelegateDID,
		PermissionRequests:         permissionRequests,
		Nonce:                      nonce,
		State:                      state,
		CallbackURL:                joinURL(connectServerURL, "callback"),
		ResponseMode:               "direct_post",
		SupportedDIDMethods:        []string{"did:dht", "did:jwk"},
	}

	requestJWT, err := signJWT(request, clientKID, client.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("enboxconnect: signing connect request: %w", err)
	}

	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		return nil, fmt.Errorf("enboxconnect: generating encryption key: %w", err)
	}
	requestJWE, err := sealRequestJWE(requestJWT, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("enboxconnect: encrypting connect request: %w", err)
	}

	requestURI, err := postPAR(ctx, httpClient, connectServerURL, requestJWE)
	if err != nil {
		return nil, fmt.Errorf("enboxconnect: %w", err)
	}

	walletURI, err := buildWalletURI(opts.WalletURL, requestURI, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("enboxconnect: %w", err)
	}
	opts.OnWalletURI(walletURI)

	responseBody, err := pollToken(ctx, httpClient, connectServerURL, state, pollInterval, timeout)
	if err != nil {
		if errors.Is(err, ErrTimeout) {
			return nil, err
		}
		return nil, fmt.Errorf("enboxconnect: %w", err)
	}
	if responseBody == deniedResponseBody {
		return nil, ErrDenied
	}

	pin, err := opts.PINPrompt()
	if err != nil {
		return nil, fmt.Errorf("enboxconnect: collecting PIN: %w", err)
	}
	if pin == "" {
		return nil, fmt.Errorf("enboxconnect: wallet PIN is required")
	}

	responseJWT, err := decryptResponseJWE(responseBody, client.X25519PrivateKey, pin)
	if err != nil {
		return nil, fmt.Errorf("enboxconnect: %w", err)
	}

	payload, err := verifyJWT(string(responseJWT))
	if err != nil {
		return nil, fmt.Errorf("enboxconnect: verifying connect response: %w", err)
	}

	var response EnboxConnectResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, fmt.Errorf("enboxconnect: parsing connect response: %w", err)
	}
	if err := checkConnectResponse(&response, client.URI, opts.DelegateDID, nonce); err != nil {
		return nil, fmt.Errorf("enboxconnect: %w", err)
	}

	if err := validateGrants(response.DelegateGrants, opts.DelegateDID, permissionRequests, response.SessionRevocations); err != nil {
		return nil, fmt.Errorf("enboxconnect: %w", err)
	}

	return &Result{
		OwnerDID:           response.ProviderDID,
		DelegateDID:        response.DelegateDID,
		Grants:             response.DelegateGrants,
		SessionRevocations: response.SessionRevocations,
	}, nil
}

// validateOptions checks the required Options fields.
func validateOptions(opts Options) error {
	switch {
	case opts.AppName == "":
		return fmt.Errorf("enboxconnect: AppName is required")
	case opts.WalletURL == "":
		return fmt.Errorf("enboxconnect: WalletURL is required")
	case opts.DelegateDID == "":
		return fmt.Errorf("enboxconnect: DelegateDID is required (pre-supplied delegate mode)")
	case len(opts.PermissionRequests) == 0:
		return fmt.Errorf("enboxconnect: PermissionRequests must not be empty")
	case opts.OnWalletURI == nil:
		return fmt.Errorf("enboxconnect: OnWalletURI is required")
	case opts.PINPrompt == nil:
		return fmt.Errorf("enboxconnect: PINPrompt is required")
	}
	return nil
}

// checkConnectResponse enforces the response shape
// (enbox-connect-protocol.ts assertConnectResponse) and the claims checks
// the client must apply: audience binding, pre-supplied delegate echo,
// nonce echo, and expiry.
func checkConnectResponse(response *EnboxConnectResponse, clientDID, delegateDID, nonce string) error {
	switch {
	case response.ProviderDID == "":
		return fmt.Errorf("invalid connect response: `providerDid` must be a string")
	case response.DelegateDID == "":
		return fmt.Errorf("invalid connect response: `delegateDid` must be a string")
	case response.Audience == "":
		return fmt.Errorf("invalid connect response: `aud` must be a string")
	case response.IssuedAt == 0:
		return fmt.Errorf("invalid connect response: `iat` must be a number")
	case response.ExpiresAt == 0:
		return fmt.Errorf("invalid connect response: `exp` must be a number")
	case response.DelegateGrants == nil:
		return fmt.Errorf("invalid connect response: `delegateGrants` must be an array")
	}

	if response.Audience != clientDID {
		return fmt.Errorf("connect response audience %q does not match the client DID", response.Audience)
	}
	if response.DelegateDID != delegateDID {
		return fmt.Errorf(
			"wallet returned delegate DID %q, but %q was requested; revoke the just-approved session in the wallet and try again",
			response.DelegateDID, delegateDID)
	}
	if response.Nonce != "" && response.Nonce != nonce {
		return fmt.Errorf("connect response nonce does not echo the request nonce")
	}
	if now := time.Now().Unix(); now >= response.ExpiresAt {
		return fmt.Errorf("connect response expired at %d (now %d)", response.ExpiresAt, now)
	}
	return nil
}

// clientVerificationMethodID returns the client DID's verification method
// id exactly as did:jwk resolution yields it (the TS client uses
// did.document.verificationMethod[0].id as the JWT kid).
func clientVerificationMethodID(clientURI string) (string, error) {
	result, err := (didjwk.Resolver{}).Resolve(clientURI)
	if err != nil {
		return "", fmt.Errorf("enboxconnect: resolving client DID: %w", err)
	}
	if len(result.Document.VerificationMethod) == 0 {
		return "", fmt.Errorf("enboxconnect: client DID document has no verification method")
	}
	return result.Document.VerificationMethod[0].ID, nil
}

// randomBase64URL returns n random bytes as unpadded base64url.
func randomBase64URL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
