package dashboard

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/enboxorg/meshd/internal/profile"
	"github.com/enboxorg/meshd/internal/state"
)

func TestBuildURL(t *testing.T) {
	rawURL := BuildURL(" https://admin.meshd.sh/?source=cli#peers ", Context{
		OwnerDID:        "did:dht:wallet",
		NetworkRecordID: "network-1",
	})
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != DefaultURL {
		t.Fatalf("dashboard URL base = %q", got)
	}
	if got := parsed.Query().Get("source"); got != "cli" {
		t.Fatalf("existing query = %q", got)
	}
	if got := parsed.Query().Get("owner"); got != "did:dht:wallet" {
		t.Fatalf("owner query = %q", got)
	}
	if got := parsed.Query().Get("network"); got != "network-1" {
		t.Fatalf("network query = %q", got)
	}
	if parsed.Fragment != "peers" {
		t.Fatalf("fragment = %q", parsed.Fragment)
	}
	if got := BuildURL("", Context{}); got != DefaultURL {
		t.Fatalf("default dashboard URL = %q", got)
	}
}

func TestWithOverrides(t *testing.T) {
	fallback := Context{OwnerDID: "did:example:fallback", NetworkRecordID: "fallback-network"}
	got := WithOverrides(fallback, " did:example:owner ", " network-1 ")
	if got.OwnerDID != "did:example:owner" || got.NetworkRecordID != "network-1" {
		t.Fatalf("context = %+v", got)
	}
	if got := WithOverrides(fallback, " ", ""); got != fallback {
		t.Fatalf("blank overrides changed context: %+v", got)
	}
}

func TestResolveContextFromProfileAndNetwork(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")

	if err := profile.UpsertProfileEntry(&profile.Entry{
		Name:     "work",
		DID:      "did:example:node",
		OwnerDID: "did:example:configured-owner",
	}); err != nil {
		t.Fatalf("UpsertProfileEntry: %v", err)
	}

	if got := ResolveContext("work"); got != (Context{OwnerDID: "did:example:configured-owner"}) {
		t.Fatalf("profile context = %+v", got)
	}

	if err := state.SaveNetworkState(profile.DataPath("work"), &state.NetworkState{
		OwnerDID:        "did:example:network-owner",
		NetworkRecordID: "network-1",
	}); err != nil {
		t.Fatalf("SaveNetworkState: %v", err)
	}
	got := ResolveContext("work")
	if got.OwnerDID != "did:example:network-owner" || got.NetworkRecordID != "network-1" {
		t.Fatalf("network context = %+v", got)
	}
}

func TestResolveContextUsesConfiguredOwnerAsNetworkFallback(t *testing.T) {
	t.Setenv("ENBOX_HOME", t.TempDir())
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	if err := profile.UpsertProfileEntry(&profile.Entry{
		Name:     "work",
		DID:      "did:example:node",
		OwnerDID: "did:example:configured-owner",
	}); err != nil {
		t.Fatalf("UpsertProfileEntry: %v", err)
	}
	if err := state.SaveNetworkState(profile.DataPath("work"), &state.NetworkState{
		NetworkRecordID: "network-1",
	}); err != nil {
		t.Fatalf("SaveNetworkState: %v", err)
	}

	got := ResolveContext("work")
	if got.OwnerDID != "did:example:configured-owner" || got.NetworkRecordID != "network-1" {
		t.Fatalf("context = %+v", got)
	}
}

func TestResolveContextStateDirectoryOverrideBypassesProfiles(t *testing.T) {
	t.Setenv("ENBOX_HOME", t.TempDir())
	t.Setenv("ENBOX_PROFILE", "")
	stateDir := t.TempDir()
	t.Setenv("MESHD_STATE_DIR", stateDir)

	if err := state.SaveNetworkState(stateDir, &state.NetworkState{
		MemberDID:       "did:example:legacy-owner",
		NetworkRecordID: "network-1",
	}); err != nil {
		t.Fatalf("SaveNetworkState: %v", err)
	}
	got := ResolveContext("profile-does-not-matter")
	if got.OwnerDID != "did:example:legacy-owner" || got.NetworkRecordID != "network-1" {
		t.Fatalf("override context = %+v", got)
	}
}

func TestResolveContextIgnoresUnreadableNetworkState(t *testing.T) {
	t.Setenv("ENBOX_HOME", t.TempDir())
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	if err := profile.UpsertProfileEntry(&profile.Entry{
		Name:     "work",
		DID:      "did:example:node",
		OwnerDID: "did:example:configured-owner",
	}); err != nil {
		t.Fatalf("UpsertProfileEntry: %v", err)
	}
	stateDir := profile.DataPath("work")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "network.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if got := ResolveContext("work"); got != (Context{OwnerDID: "did:example:configured-owner"}) {
		t.Fatalf("context = %+v", got)
	}
}
