package enboxconnect

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDiscoverConnectServerURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wellKnownPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"connectServerUrl":"https://relay.example/connect"}`))
	}))
	defer server.Close()

	// The wallet URL's path must be ignored: discovery hits the origin.
	got, err := DiscoverConnectServerURL(context.Background(), server.URL+"/connect/app?x=1")
	if err != nil {
		t.Fatalf("DiscoverConnectServerURL: %v", err)
	}
	if got != "https://relay.example/connect" {
		t.Errorf("got %q, want %q", got, "https://relay.example/connect")
	}
}

func TestDiscoverConnectServerURLErrors(t *testing.T) {
	notFound := httptest.NewServer(http.NotFoundHandler())
	defer notFound.Close()
	if _, err := DiscoverConnectServerURL(context.Background(), notFound.URL); err == nil {
		t.Error("expected error when the well-known document is absent")
	}

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer empty.Close()
	if _, err := DiscoverConnectServerURL(context.Background(), empty.URL); err == nil ||
		!strings.Contains(err.Error(), "connectServerUrl") {
		t.Error("expected error when the document names no connectServerUrl")
	}

	if _, err := DiscoverConnectServerURL(context.Background(), ""); err == nil {
		t.Error("expected error for empty wallet origin")
	}
}

func TestBuildWalletURI(t *testing.T) {
	key := []byte{1, 2, 3, 4}

	t.Run("bare origin gets the default connect path", func(t *testing.T) {
		got, err := buildWalletURI("https://wallet.example", "https://relay.example/authorize/abc.jwt", key)
		if err != nil {
			t.Fatalf("buildWalletURI: %v", err)
		}
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("parsing result: %v", err)
		}
		if u.Path != defaultWalletConnectPath {
			t.Errorf("path = %q, want %q", u.Path, defaultWalletConnectPath)
		}
		if q := u.Query().Get("request_uri"); q != "https://relay.example/authorize/abc.jwt" {
			t.Errorf("request_uri = %q", q)
		}
		if q := u.Query().Get("encryption_key"); q != base64.RawURLEncoding.EncodeToString(key) {
			t.Errorf("encryption_key = %q", q)
		}
	})

	t.Run("explicit path and existing query are preserved", func(t *testing.T) {
		got, err := buildWalletURI("https://wallet.example/custom/connect?theme=dark", "req-uri", key)
		if err != nil {
			t.Fatalf("buildWalletURI: %v", err)
		}
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("parsing result: %v", err)
		}
		if u.Path != "/custom/connect" {
			t.Errorf("path = %q, want /custom/connect", u.Path)
		}
		if q := u.Query().Get("theme"); q != "dark" {
			t.Errorf("theme = %q, want dark", q)
		}
		if q := u.Query().Get("request_uri"); q != "req-uri" {
			t.Errorf("request_uri = %q", q)
		}
	})

	t.Run("scheme defaults to https", func(t *testing.T) {
		got, err := buildWalletURI("wallet.example", "req-uri", key)
		if err != nil {
			t.Fatalf("buildWalletURI: %v", err)
		}
		if !strings.HasPrefix(got, "https://wallet.example/connect/app?") {
			t.Errorf("got %q", got)
		}
	})
}

func TestJoinURL(t *testing.T) {
	cases := []struct {
		base string
		want string
	}{
		{"https://relay.example", "https://relay.example/par"},
		{"https://relay.example/", "https://relay.example/par"},
		{"https://relay.example/connect", "https://relay.example/connect/par"},
		{"https://relay.example/connect/", "https://relay.example/connect/par"},
	}
	for _, tc := range cases {
		if got := joinURL(tc.base, "par"); got != tc.want {
			t.Errorf("joinURL(%q) = %q, want %q", tc.base, got, tc.want)
		}
	}

	if got := joinURL("https://relay.example", "token", "abc.jwt"); got != "https://relay.example/token/abc.jwt" {
		t.Errorf("joinURL token = %q", got)
	}
}

func TestNormalizeURL(t *testing.T) {
	u, err := normalizeURL("wallet.example")
	if err != nil {
		t.Fatalf("normalizeURL: %v", err)
	}
	if u.String() != "https://wallet.example" {
		t.Errorf("got %q", u.String())
	}

	u, err = normalizeURL("http://localhost:3000/wallet")
	if err != nil {
		t.Fatalf("normalizeURL: %v", err)
	}
	if u.String() != "http://localhost:3000/wallet" {
		t.Errorf("got %q", u.String())
	}

	for _, bad := range []string{"", "   ", "https://"} {
		if _, err := normalizeURL(bad); err == nil {
			t.Errorf("normalizeURL(%q): expected error", bad)
		}
	}
}
