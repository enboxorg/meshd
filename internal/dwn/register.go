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

// RegisterTenant registers a DID as a tenant on a DWN server.
//
// This implements the DWN server's proof-of-work registration flow:
//  1. Fetch terms of service from GET /registration/terms-of-service (optional)
//  2. Fetch proof-of-work challenge from GET /registration/proof-of-work
//  3. Compute a qualifying response nonce (SHA-256 hashcash-style)
//  4. POST /registration with the registration data + proof-of-work
//
// If proof-of-work or terms-of-service endpoints are not available (404),
// this returns ErrRegistrationNotAvailable.
//
// This is required before writing to a DWN that has tenant registration enabled.
func RegisterTenant(ctx context.Context, endpoint string, did string) error {
	client := &http.Client{Timeout: 60 * time.Second}
	baseURL := strings.TrimRight(endpoint, "/")

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

// ErrRegistrationNotAvailable is returned when the DWN server doesn't expose
// registration endpoints (proof-of-work or provider auth may not be enabled).
var ErrRegistrationNotAvailable = errors.New("registration endpoints not available on this server")

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
