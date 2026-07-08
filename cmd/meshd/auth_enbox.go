package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/internal/enboxconnect"
	"github.com/enboxorg/meshd/internal/profile"
	"github.com/enboxorg/meshd/internal/state"
	"github.com/enboxorg/meshd/protocols"
)

const (
	// defaultEnboxWalletURL is the wallet the enbox connect flow targets when
	// --wallet is not given.
	defaultEnboxWalletURL = "https://enbox-wallet.pages.dev"

	// enboxConnectServerEnv overrides the connect relay URL when the
	// --connect-server flag is not given. When both are empty the relay is
	// discovered from the wallet origin's /.well-known/enbox-connect.
	enboxConnectServerEnv = "ENBOX_CONNECT_SERVER_URL"
)

// runEnboxAuthConnect drives the enbox connect delegate flow, the default
// 'meshd auth connect' path: push an encrypted permission request to the
// connect relay, hand the wallet URI to the user, collect the PIN the wallet
// displays, and store the returned delegated grants as this profile's wallet
// session.
func runEnboxAuthConnect(ctx context.Context, profileFlag string, opts authConnectOptions) error {
	stateDir, identity, err := ensureIdentityForCommand(ctx, profileFlag, "")
	if err != nil {
		return err
	}
	password, err := vaultPasswordForUnlock(stateDir)
	if err != nil {
		return err
	}
	delegateIdentity, err := ensureWalletDelegateIdentity(stateDir)
	if err != nil {
		return err
	}

	meshDefinition, err := protocols.MeshProtocolDefinitionForConnect()
	if err != nil {
		return fmt.Errorf("preparing mesh protocol definition: %w", err)
	}

	walletURL := firstNonEmpty(strings.TrimSpace(opts.walletURL), defaultEnboxWalletURL)
	connectServerURL := firstNonEmpty(
		strings.TrimSpace(opts.connectServerURL),
		strings.TrimSpace(os.Getenv(enboxConnectServerEnv)),
	)
	if connectServerURL == "" {
		connectServerURL, err = enboxconnect.DiscoverConnectServerURL(ctx, walletURL)
		if err != nil {
			return fmt.Errorf("discovering connect relay from wallet origin: %w", err)
		}
	}

	profileName := profileNameForWrite(profileFlag)
	fmt.Println("Connecting this profile to your Enbox wallet.")
	fmt.Printf("  Profile: %s\n", profileName)
	fmt.Printf("  Node DID: %s\n", identity.URI)
	fmt.Printf("  Delegate DID: %s\n", delegateIdentity.URI)
	fmt.Printf("  Wallet: %s\n", walletURL)
	fmt.Printf("  Connect relay: %s\n", connectServerURL)

	result, err := enboxconnect.Connect(ctx, enboxconnect.Options{
		AppName:          "meshd",
		WalletURL:        walletURL,
		ConnectServerURL: connectServerURL,
		DelegateDID:      delegateIdentity.URI,
		PermissionRequests: []enboxconnect.PermissionRequest{{
			ProtocolDefinition: meshDefinition,
			Permissions:        []string{"read", "write", "delete"},
		}},
		OnWalletURI: func(uri string) { handleEnboxWalletURI(uri, opts.walletURIOut) },
		PINPrompt:   promptConnectPIN,
	})
	if err != nil {
		return err
	}

	session := &state.WalletSession{
		Version:            1,
		OwnerDID:           result.OwnerDID,
		ConnectedDID:       result.OwnerDID,
		DelegateDID:        result.DelegateDID,
		NodeDID:            identity.URI,
		WalletOrigin:       walletOriginFromURL(walletURL),
		ExpiresAt:          sessionExpiryFromGrants(result.Grants),
		Grants:             result.Grants,
		ConnectServerURL:   connectServerURL,
		SessionRevocations: sessionRevocationsFromResult(result.SessionRevocations),
	}
	if err := state.StoreWalletSession(stateDir, password, session); err != nil {
		return err
	}

	if os.Getenv("MESHD_STATE_DIR") == "" {
		if err := profile.UpsertProfileEntry(&profile.Entry{
			Name:         profileName,
			DID:          identity.URI,
			AuthType:     profile.AuthTypeWalletAuthorizedNode,
			OwnerDID:     result.OwnerDID,
			ConnectedDID: result.OwnerDID,
			DelegateDID:  result.DelegateDID,
			NodeDID:      identity.URI,
			WalletOrigin: session.WalletOrigin,
			ExpiresAt:    session.ExpiresAt,
		}); err != nil {
			return fmt.Errorf("saving wallet-connected profile: %w", err)
		}
	}

	fmt.Println("\nWallet connected.")
	fmt.Printf("  Wallet Owner DID: %s\n", result.OwnerDID)
	fmt.Printf("  Session Delegate DID: %s\n", result.DelegateDID)
	fmt.Printf("  Node DID: %s\n", identity.URI)
	fmt.Printf("  Grants: %d (delegated)\n", len(result.Grants))
	if session.ExpiresAt != "" {
		fmt.Printf("  Expires: %s\n", session.ExpiresAt)
	}
	fmt.Printf("  Session: encrypted\n")
	fmt.Printf("\nRun 'meshd network create <name>' to create a mesh network, or 'meshd up' to join one.\n")
	return nil
}

// handleEnboxWalletURI hands the wallet connect URI to the user: print it,
// optionally write it to a file for scripted flows, and open the browser
// when running interactively.
func handleEnboxWalletURI(uri string, uriOutPath string) {
	fmt.Printf("\nOpen this link in your Enbox wallet (or scan it):\n  %s\n", uri)
	if uriOutPath != "" {
		if err := writeWalletURIFile(uriOutPath, uri); err != nil {
			fmt.Printf("  Warning: could not write wallet URI to %s: %v\n", uriOutPath, err)
		} else {
			fmt.Printf("  Wallet URI written to %s\n", uriOutPath)
		}
	}
	if stdinIsTerminal() {
		if err := openBrowser(uri); err != nil {
			fmt.Printf("  Could not open browser automatically: %v\n", err)
		} else {
			fmt.Printf("  Browser opened. Approve the request there, then return here.\n")
		}
	}
	fmt.Printf("\nWaiting for wallet approval...\n")
}

// writeWalletURIFile writes the wallet URI to path with 0600 permissions,
// staging through a temp file so readers never observe a partial write.
func writeWalletURIFile(path string, uri string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(uri+"\n"), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// promptConnectPIN reads the PIN the wallet displays after approval. It
// reads a line from stdin so it works both interactively and piped.
func promptConnectPIN() (string, error) {
	fmt.Print("Enter the PIN shown in your wallet: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("reading PIN: %w", err)
	}
	pin := strings.TrimSpace(line)
	if pin == "" {
		return "", fmt.Errorf("PIN is required")
	}
	return pin, nil
}

// walletOriginFromURL reduces a wallet URL to its origin (scheme://host).
// Unparseable values are returned trimmed so the session still records what
// was used.
func walletOriginFromURL(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimRight(trimmed, "/")
	}
	return u.Scheme + "://" + u.Host
}

// sessionExpiryFromGrants returns the earliest dateExpires (RFC 3339) across
// the session grants, or "" when no grant carries a parseable expiry.
func sessionExpiryFromGrants(grants []json.RawMessage) string {
	var earliest time.Time
	value := ""
	for _, raw := range grants {
		grant, err := dwn.ParsePermissionGrant(raw)
		if err != nil {
			continue
		}
		expires, err := time.Parse(time.RFC3339, grant.DateExpires)
		if err != nil {
			continue
		}
		if value == "" || expires.Before(earliest) {
			earliest = expires
			value = grant.DateExpires
		}
	}
	return value
}

// sessionRevocationsFromResult converts the connect result's revocation pairs
// into their persisted wallet-session form.
func sessionRevocationsFromResult(revocations []enboxconnect.SessionRevocation) []state.SessionRevocation {
	if len(revocations) == 0 {
		return nil
	}
	out := make([]state.SessionRevocation, 0, len(revocations))
	for _, revocation := range revocations {
		out = append(out, state.SessionRevocation{
			GrantID:           revocation.GrantID,
			RevocationGrantID: revocation.RevocationGrantID,
		})
	}
	return out
}
