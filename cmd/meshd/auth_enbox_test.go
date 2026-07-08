package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/enboxorg/meshd/internal/enboxconnect"
)

func TestParseAuthConnectArgsEnboxFlags(t *testing.T) {
	opts, err := parseAuthConnectArgs([]string{
		"work",
		"--wallet", "https://wallet.example",
		"--connect-server", "https://relay.example",
		"--wallet-uri-out", "/tmp/uri.txt",
	})
	if err != nil {
		t.Fatalf("parseAuthConnectArgs: %v", err)
	}
	if opts.profileName != "work" {
		t.Fatalf("profileName = %q", opts.profileName)
	}
	if opts.walletURL != "https://wallet.example" || !opts.walletURLSet {
		t.Fatalf("wallet = %q set=%t", opts.walletURL, opts.walletURLSet)
	}
	if opts.connectServerURL != "https://relay.example" {
		t.Fatalf("connectServerURL = %q", opts.connectServerURL)
	}
	if opts.walletURIOut != "/tmp/uri.txt" {
		t.Fatalf("walletURIOut = %q", opts.walletURIOut)
	}
	if opts.useLegacyFlow() {
		t.Fatal("enbox flags must not select the legacy flow")
	}
}

func TestParseAuthConnectArgsDefaultsToEnboxFlow(t *testing.T) {
	opts, err := parseAuthConnectArgs(nil)
	if err != nil {
		t.Fatalf("parseAuthConnectArgs: %v", err)
	}
	if opts.walletURL != "" || opts.walletURLSet {
		t.Fatalf("wallet default = %q set=%t, want unset", opts.walletURL, opts.walletURLSet)
	}
	if opts.useLegacyFlow() {
		t.Fatal("no flags must select the enbox flow")
	}
}

func TestAuthConnectLegacyFlowSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "legacy flag", args: []string{"--legacy"}},
		{name: "request-out", args: []string{"--request-out", "/tmp/req.json"}},
		{name: "no-wait", args: []string{"--no-wait"}},
		{name: "admin", args: []string{"--admin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parseAuthConnectArgs(tc.args)
			if err != nil {
				t.Fatalf("parseAuthConnectArgs: %v", err)
			}
			if !opts.useLegacyFlow() {
				t.Fatalf("args %v must select the legacy flow", tc.args)
			}
		})
	}
}

func TestParseAuthConnectArgsRejectsUnknownFlag(t *testing.T) {
	if _, err := parseAuthConnectArgs([]string{"--bogus"}); err == nil {
		t.Fatal("expected unknown flag error")
	}
}

func TestWalletOriginFromURL(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{in: "https://enbox-wallet.pages.dev", want: "https://enbox-wallet.pages.dev"},
		{in: "https://wallet.example/connect/app?x=1", want: "https://wallet.example"},
		{in: "  https://wallet.example/  ", want: "https://wallet.example"},
		{in: "not a url/", want: "not a url"},
	} {
		if got := walletOriginFromURL(tc.in); got != tc.want {
			t.Fatalf("walletOriginFromURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSessionExpiryFromGrants(t *testing.T) {
	grants := []json.RawMessage{
		testWalletPermissionGrant(t, "later", "did:dht:wallet", "did:jwk:delegate", map[string]any{
			"interface": "Records",
			"method":    "Read",
		}),
		testWalletGrantExpiring(t, "sooner", "did:dht:wallet", "did:jwk:delegate", "2027-01-02T03:04:05Z"),
	}
	if got := sessionExpiryFromGrants(grants); got != "2027-01-02T03:04:05Z" {
		t.Fatalf("sessionExpiryFromGrants = %q, want earliest expiry", got)
	}
	if got := sessionExpiryFromGrants(nil); got != "" {
		t.Fatalf("sessionExpiryFromGrants(nil) = %q, want empty", got)
	}
	if got := sessionExpiryFromGrants([]json.RawMessage{json.RawMessage(`{"bogus":true}`)}); got != "" {
		t.Fatalf("sessionExpiryFromGrants(bogus) = %q, want empty", got)
	}
}

// testWalletGrantExpiring fabricates a delegated grant with a custom expiry.
func testWalletGrantExpiring(t *testing.T, id, grantor, grantee, dateExpires string) json.RawMessage {
	t.Helper()
	raw := testWalletPermissionGrant(t, id, grantor, grantee, map[string]any{
		"interface": "Records",
		"method":    "Write",
	})
	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"dateExpires": dateExpires,
		"delegated":   true,
		"scope":       map[string]any{"interface": "Records", "method": "Write"},
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	msg["encodedData"] = base64.RawURLEncoding.EncodeToString(encoded)
	out, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWriteWalletURIFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wallet-uri.txt")
	if err := writeWalletURIFile(path, "https://wallet.example/connect/app?request_uri=abc"); err != nil {
		t.Fatalf("writeWalletURIFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "https://wallet.example/connect/app?request_uri=abc\n" {
		t.Fatalf("wallet URI file = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("wallet URI file mode = %o, want 0600", info.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind: %v", err)
	}
}

func TestSessionRevocationsFromResult(t *testing.T) {
	got := sessionRevocationsFromResult([]enboxconnect.SessionRevocation{
		{GrantID: "grant-1", RevocationGrantID: "revoke-1"},
		{GrantID: "grant-2", RevocationGrantID: "revoke-2"},
	})
	if len(got) != 2 || got[0].GrantID != "grant-1" || got[0].RevocationGrantID != "revoke-1" ||
		got[1].GrantID != "grant-2" || got[1].RevocationGrantID != "revoke-2" {
		t.Fatalf("sessionRevocationsFromResult = %+v", got)
	}
	if sessionRevocationsFromResult(nil) != nil {
		t.Fatal("nil revocations must map to nil")
	}
}
