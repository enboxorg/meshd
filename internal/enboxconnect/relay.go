package enboxconnect

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// relayRequestTimeout bounds each individual relay HTTP request,
	// mirroring the SDK's AbortSignal.timeout(30_000) per fetch.
	relayRequestTimeout = 30 * time.Second

	// wellKnownFetchTimeout bounds the wallet well-known discovery fetch
	// (cli-connect-handler.ts WELL_KNOWN_FETCH_TIMEOUT_MS).
	wellKnownFetchTimeout = 5 * time.Second

	// maxRelayResponseBytes caps relay response bodies read into memory.
	maxRelayResponseBytes = 16 << 20

	// wellKnownPath is the wallet-origin document naming its preferred
	// connect relay (cli-connect-handler.ts WALLET_WELL_KNOWN_PATH).
	wellKnownPath = "/.well-known/enbox-connect"

	// defaultWalletConnectPath is appended to a wallet URL that has no
	// path (cli-connect-handler.ts DEFAULT_WALLET_CONNECT_PATH).
	defaultWalletConnectPath = "/connect/app"

	// deniedResponseBody is the relay token body signaling that the user
	// denied the request in the wallet.
	deniedResponseBody = "DENIED"
)

// schemeRegexp matches URLs that already carry a scheme
// (cli-connect-handler.ts normalizeUrl).
var schemeRegexp = regexp.MustCompile(`^[a-zA-Z][a-zA-Z\d+.-]*://`)

// postPAR pushes the encrypted request JWE to the relay's pushed
// authorization request endpoint and returns the request_uri the wallet
// will fetch it from (POST <connectServerUrl>/par).
func postPAR(ctx context.Context, client *http.Client, connectServerURL, requestJWE string) (string, error) {
	body, err := json.Marshal(struct {
		Request string `json:"request"`
	}{Request: requestJWE})
	if err != nil {
		return "", fmt.Errorf("marshaling PAR body: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, relayRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, joinURL(connectServerURL, "par"), bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("building PAR request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("pushing authorization request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxRelayResponseBytes))
	if err != nil {
		return "", fmt.Errorf("reading PAR response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("connect relay PAR failed: %d: %s", resp.StatusCode, resp.Status)
	}

	var pushed connectPushedResponse
	if err := json.Unmarshal(respBody, &pushed); err != nil {
		return "", fmt.Errorf("parsing PAR response: %w", err)
	}
	if pushed.RequestURI == "" {
		return "", fmt.Errorf("connect relay PAR response is missing request_uri")
	}
	return pushed.RequestURI, nil
}

// pollToken polls GET <connectServerUrl>/token/<state>.jwt until the wallet
// response arrives, mirroring the SDK's pollWithTtl: the first fetch is
// immediate, any non-2xx status (404 pending included) keeps polling, and
// the first 2xx body is returned without any re-fetch — the relay serves
// each response exactly once. Transport errors abort the poll.
func pollToken(ctx context.Context, client *http.Client, connectServerURL, state string, interval, timeout time.Duration) (string, error) {
	tokenURL := joinURL(connectServerURL, "token", url.PathEscape(state)+".jwt")
	deadline := time.Now().Add(timeout)

	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if !time.Now().Before(deadline) {
			return "", ErrTimeout
		}

		body, ok, err := fetchTokenOnce(ctx, client, tokenURL)
		if err != nil {
			return "", err
		}
		if ok {
			return body, nil
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
	}
}

// fetchTokenOnce performs a single token poll. ok is false when the
// response is not yet available (any non-2xx status).
func fetchTokenOnce(ctx context.Context, client *http.Client, tokenURL string) (body string, ok bool, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, relayRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", false, fmt.Errorf("building token request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("polling connect relay: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxRelayResponseBytes))
	if err != nil {
		return "", false, fmt.Errorf("reading token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", false, nil
	}
	return string(respBody), true, nil
}

// DiscoverConnectServerURL fetches the wallet origin's well-known
// enbox-connect document and returns the connect relay URL it names,
// mirroring discoverWellKnownConnectServerUrl in
// packages/cli/src/cli-connect-handler.ts. Only the origin
// (scheme://host) of walletOrigin is used.
func DiscoverConnectServerURL(ctx context.Context, walletOrigin string) (string, error) {
	origin, err := normalizeURL(walletOrigin)
	if err != nil {
		return "", fmt.Errorf("invalid wallet origin %q: %w", walletOrigin, err)
	}
	wellKnownURL := origin.Scheme + "://" + origin.Host + wellKnownPath

	reqCtx, cancel := context.WithTimeout(ctx, wellKnownFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return "", fmt.Errorf("building well-known request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", wellKnownURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRelayResponseBytes))
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", wellKnownURL, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("fetching %s: unexpected status %d", wellKnownURL, resp.StatusCode)
	}

	var doc struct {
		ConnectServerURL string `json:"connectServerUrl"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("parsing %s: %w", wellKnownURL, err)
	}
	if doc.ConnectServerURL == "" {
		return "", fmt.Errorf("%s does not name a connectServerUrl", wellKnownURL)
	}

	normalized, err := normalizeURL(doc.ConnectServerURL)
	if err != nil {
		return "", fmt.Errorf("invalid connect relay URL %q in %s: %w", doc.ConnectServerURL, wellKnownURL, err)
	}
	return normalized.String(), nil
}

// buildWalletURI builds the URI handed to the user's wallet: the wallet URL
// (with /connect/app appended when it has no path, per cli-connect-handler.ts
// buildWalletUri) carrying the relay request_uri and the base64url-encoded
// request encryption key as query parameters.
func buildWalletURI(walletURL, requestURI string, encryptionKey []byte) (string, error) {
	u, err := normalizeURL(walletURL)
	if err != nil {
		return "", fmt.Errorf("invalid wallet URL %q: %w", walletURL, err)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = defaultWalletConnectPath
	}

	q := u.Query()
	q.Set("request_uri", requestURI)
	q.Set("encryption_key", base64.RawURLEncoding.EncodeToString(encryptionKey))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// normalizeURL validates a URL, defaulting the scheme to https when absent
// (cli-connect-handler.ts normalizeUrl).
func normalizeURL(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("empty URL")
	}
	if !schemeRegexp.MatchString(trimmed) {
		trimmed = "https://" + trimmed
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL has no host")
	}
	return u, nil
}

// joinURL joins a base URL and path segments with exactly one slash between
// each part (the SDK's concatenateUrl for relay endpoints).
func joinURL(base string, segments ...string) string {
	return strings.TrimRight(base, "/") + "/" + strings.Join(segments, "/")
}
