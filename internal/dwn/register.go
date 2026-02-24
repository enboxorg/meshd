package dwn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// serverInfo represents the response from GET /info.
type serverInfo struct {
	RegistrationRequirements []string         `json:"registrationRequirements"`
	ProviderAuth             *providerAuthInfo `json:"providerAuth,omitempty"`
}

// providerAuthInfo mirrors the ProviderAuthInfo type from dwn-clients.
type providerAuthInfo struct {
	AuthorizeURL string `json:"authorizeUrl"`
	TokenURL     string `json:"tokenUrl"`
	RefreshURL   string `json:"refreshUrl,omitempty"`
}

// RegisterTenant registers a DID as a tenant on a DWN server.
//
// The function queries GET /info to discover available registration methods and
// dispatches to the appropriate flow:
//
//   - provider-auth-v0: exchanges an authorization code for a registration token
//     via the server's built-in open-auth endpoints.
//   - proof-of-work-sha256-v0: solves a hashcash-style proof-of-work challenge.
//
// If no registration method is available (empty registrationRequirements), the
// server is either open for all or misconfigured — this returns nil (no
// registration needed) or ErrRegistrationNotAvailable respectively.
func RegisterTenant(ctx context.Context, endpoint string, did string) error {
	client := &http.Client{Timeout: 60 * time.Second}
	baseURL := strings.TrimRight(endpoint, "/")

	// 1. Query /info to discover registration requirements.
	info, err := fetchServerInfo(ctx, client, baseURL)
	if err != nil {
		return fmt.Errorf("fetching server info: %w", err)
	}

	// Determine which registration method to use.
	hasProviderAuth := false
	hasProofOfWork := false
	for _, req := range info.RegistrationRequirements {
		switch req {
		case "provider-auth-v0":
			hasProviderAuth = true
		case "proof-of-work-sha256-v0":
			hasProofOfWork = true
		}
	}

	// No registration requirements — server is open for all.
	if len(info.RegistrationRequirements) == 0 {
		return nil
	}

	// Prefer provider-auth when available.
	if hasProviderAuth {
		if info.ProviderAuth == nil || info.ProviderAuth.AuthorizeURL == "" || info.ProviderAuth.TokenURL == "" {
			return fmt.Errorf("server advertises provider-auth-v0 but /info is missing providerAuth URLs")
		}
		return registerViaProviderAuth(ctx, client, baseURL, did, info.ProviderAuth)
	}

	if hasProofOfWork {
		return registerViaProofOfWork(ctx, client, baseURL, did)
	}

	return ErrRegistrationNotAvailable
}

// ErrRegistrationNotAvailable is returned when the DWN server doesn't expose
// any supported registration method.
var ErrRegistrationNotAvailable = errors.New("registration endpoints not available on this server")

// fetchServerInfo calls GET /info and parses the server info response.
func fetchServerInfo(ctx context.Context, client *http.Client, baseURL string) (*serverInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/info", nil)
	if err != nil {
		return nil, fmt.Errorf("creating /info request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET /info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET /info returned %d: %s", resp.StatusCode, string(body))
	}

	var info serverInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding /info response: %w", err)
	}
	return &info, nil
}

// registerViaProviderAuth implements the provider-auth-v0 registration flow:
//  1. GET {authorizeUrl}?redirect_uri=urn:ietf:wg:oauth:2.0:oob&state=<random> → { code }
//  2. POST {tokenUrl} with { code, redirectUri } → { registrationToken }
//  3. POST /registration with { providerAuth: { registrationToken }, registrationData: { did } }
func registerViaProviderAuth(ctx context.Context, client *http.Client, baseURL, did string, auth *providerAuthInfo) error {
	// Use the OOB redirect URI since this is a non-interactive CLI flow.
	const redirectURI = "urn:ietf:wg:oauth:2.0:oob"
	state := generateNonce()

	// Step 1: Get authorization code.
	authorizeURL := auth.AuthorizeURL + "?redirect_uri=" + redirectURI + "&state=" + state
	authReq, err := http.NewRequestWithContext(ctx, "GET", authorizeURL, nil)
	if err != nil {
		return fmt.Errorf("creating authorize request: %w", err)
	}

	authResp, err := client.Do(authReq)
	if err != nil {
		return fmt.Errorf("GET authorize: %w", err)
	}
	defer authResp.Body.Close()

	if authResp.StatusCode != 200 {
		body, _ := io.ReadAll(authResp.Body)
		return fmt.Errorf("authorize endpoint returned %d: %s", authResp.StatusCode, string(body))
	}

	var authResult struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	if err := json.NewDecoder(authResp.Body).Decode(&authResult); err != nil {
		return fmt.Errorf("decoding authorize response: %w", err)
	}
	if authResult.Code == "" {
		return fmt.Errorf("authorize response missing code")
	}

	// Step 2: Exchange code for registration token.
	tokenBody, _ := json.Marshal(map[string]string{
		"code":        authResult.Code,
		"redirectUri": redirectURI,
	})
	tokenReq, err := http.NewRequestWithContext(ctx, "POST", auth.TokenURL, strings.NewReader(string(tokenBody)))
	if err != nil {
		return fmt.Errorf("creating token request: %w", err)
	}
	tokenReq.Header.Set("Content-Type", "application/json")

	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return fmt.Errorf("POST token: %w", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 200 {
		body, _ := io.ReadAll(tokenResp.Body)
		return fmt.Errorf("token endpoint returned %d: %s", tokenResp.StatusCode, string(body))
	}

	var tokenResult struct {
		RegistrationToken string `json:"registrationToken"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenResult); err != nil {
		return fmt.Errorf("decoding token response: %w", err)
	}
	if tokenResult.RegistrationToken == "" {
		return fmt.Errorf("token response missing registrationToken")
	}

	// Step 3: Register the DID with the registration token.
	regBody, _ := json.Marshal(map[string]any{
		"providerAuth": map[string]string{
			"registrationToken": tokenResult.RegistrationToken,
		},
		"registrationData": map[string]string{
			"did": did,
		},
	})

	regReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/registration", strings.NewReader(string(regBody)))
	if err != nil {
		return fmt.Errorf("creating registration request: %w", err)
	}
	regReq.Header.Set("Content-Type", "application/json")

	regResp, err := client.Do(regReq)
	if err != nil {
		return fmt.Errorf("POST /registration: %w", err)
	}
	defer regResp.Body.Close()

	if regResp.StatusCode != 200 {
		body, _ := io.ReadAll(regResp.Body)
		return fmt.Errorf("registration failed: %d %s", regResp.StatusCode, string(body))
	}

	return nil
}

// registerViaProofOfWork implements the proof-of-work-sha256-v0 registration flow:
//  1. GET /registration/terms-of-service (optional)
//  2. GET /registration/proof-of-work → { challengeNonce, maximumAllowedHashValue }
//  3. Solve hashcash: SHA-256(challengeNonce + responseNonce + requestData) <= max
//  4. POST /registration with proofOfWork credentials
func registerViaProofOfWork(ctx context.Context, client *http.Client, baseURL, did string) error {
	// 1. Fetch terms of service (optional — server may not have ToS configured).
	var tosHash string
	tosReq, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/registration/terms-of-service", nil)
	if err != nil {
		return fmt.Errorf("creating TOS request: %w", err)
	}
	tosResp, err := client.Do(tosReq)
	if err != nil {
		return fmt.Errorf("fetching terms of service: %w", err)
	}
	tosBody, _ := io.ReadAll(tosResp.Body)
	tosResp.Body.Close()

	if tosResp.StatusCode == 200 {
		tosHash = hashHex(string(tosBody))
	}
	// 404 is fine — ToS may not be configured.

	// 2. Fetch proof-of-work challenge.
	powReq, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/registration/proof-of-work", nil)
	if err != nil {
		return fmt.Errorf("creating PoW request: %w", err)
	}
	powResp, err := client.Do(powReq)
	if err != nil {
		return fmt.Errorf("fetching proof-of-work challenge: %w", err)
	}
	defer powResp.Body.Close()

	if powResp.StatusCode == 404 {
		return ErrRegistrationNotAvailable
	}
	if powResp.StatusCode != 200 {
		body, _ := io.ReadAll(powResp.Body)
		return fmt.Errorf("proof-of-work challenge: %d %s", powResp.StatusCode, string(body))
	}

	var challenge struct {
		ChallengeNonce          string `json:"challengeNonce"`
		MaximumAllowedHashValue string `json:"maximumAllowedHashValue"`
	}
	if err := json.NewDecoder(powResp.Body).Decode(&challenge); err != nil {
		return fmt.Errorf("decoding proof-of-work challenge: %w", err)
	}

	// 3. Compute the proof-of-work.
	regData := map[string]string{
		"did": did,
	}
	if tosHash != "" {
		regData["termsOfServiceHash"] = tosHash
	}
	regDataJSON, _ := json.Marshal(regData)

	responseNonce, err := solveProofOfWork(ctx, challenge.ChallengeNonce, challenge.MaximumAllowedHashValue, string(regDataJSON))
	if err != nil {
		return fmt.Errorf("solving proof-of-work: %w", err)
	}

	// 4. Send registration request.
	regReqBody := map[string]any{
		"registrationData": regData,
		"proofOfWork": map[string]string{
			"challengeNonce": challenge.ChallengeNonce,
			"responseNonce":  responseNonce,
		},
	}
	regBodyJSON, _ := json.Marshal(regReqBody)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/registration",
		strings.NewReader(string(regBodyJSON)))
	if err != nil {
		return fmt.Errorf("creating registration request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("sending registration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %d %s", resp.StatusCode, string(body))
	}

	return nil
}

// hashHex computes SHA-256 of a string and returns it as lowercase hex.
func hashHex(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

// solveProofOfWork finds a response nonce whose hash qualifies the difficulty.
//
// The algorithm: hash(challengeNonce + responseNonce + requestData) must be
// <= maximumAllowedHashValue (both interpreted as big integers from hex).
func solveProofOfWork(ctx context.Context, challengeNonce, maxHashHex, requestData string) (string, error) {
	maxHash := new(big.Int)
	maxHash.SetString(maxHashHex, 16)

	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}

		nonce := generateNonce()
		input := challengeNonce + nonce + requestData
		hash := hashHex(input)

		computedHash := new(big.Int)
		computedHash.SetString(hash, 16)

		if computedHash.Cmp(maxHash) <= 0 {
			return nonce, nil
		}
	}
}

// generateNonce generates 32 random bytes as an uppercase hex string.
func generateNonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b))
}
