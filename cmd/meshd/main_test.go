package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/invite"
	"github.com/enboxorg/meshd/internal/profile"
	"github.com/enboxorg/meshd/internal/state"
)

func TestParseUpFlagsInviteURL(t *testing.T) {
	u, err := invite.Encode(invite.New("https://dwn.example.com", "did:jwk:anchor", "net", "home", "", "", ""))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	flags := parseUpFlags([]string{u, "--no-tun"})
	if flags.inviteURL != u {
		t.Fatalf("inviteURL = %q, want %q", flags.inviteURL, u)
	}
	if !flags.noTun {
		t.Fatal("expected --no-tun to be parsed")
	}
}

func resetVaultPasswordCache(t *testing.T) {
	t.Helper()
	previous := cachedVaultPassword
	cachedVaultPassword = ""
	t.Cleanup(func() {
		cachedVaultPassword = previous
	})
}

func TestEnsureIdentityForCommandCreatesDefaultProfile(t *testing.T) {
	resetVaultPasswordCache(t)

	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")

	stateDir, identity, err := ensureIdentityForCommand(context.Background(), "", "")
	if err != nil {
		t.Fatalf("ensureIdentityForCommand: %v", err)
	}
	if identity == nil || identity.URI == "" {
		t.Fatal("identity was not created")
	}
	if !strings.HasPrefix(stateDir, home) {
		t.Fatalf("stateDir = %q, want under %q", stateDir, home)
	}
	if !did.EncryptedExists(stateDir) {
		t.Fatal("identity was not stored in encrypted vault")
	}
	if did.Exists(stateDir) {
		t.Fatal("legacy plaintext identity should not be created")
	}

	cfg, err := profile.ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if cfg.DefaultProfile != "default" {
		t.Fatalf("DefaultProfile = %q, want default", cfg.DefaultProfile)
	}
	if cfg.Profiles["default"] == nil {
		t.Fatal("default profile was not saved")
	}
}

func TestEnsureIdentityForCommandUsesResolvedDefaultProfile(t *testing.T) {
	resetVaultPasswordCache(t)

	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")

	if err := profile.UpsertProfile("work", "did:jwk:placeholder"); err != nil {
		t.Fatalf("UpsertProfile: %v", err)
	}

	stateDir, identity, err := ensureIdentityForCommand(context.Background(), "", "")
	if err != nil {
		t.Fatalf("ensureIdentityForCommand: %v", err)
	}
	if identity == nil || identity.URI == "" {
		t.Fatal("identity was not created")
	}
	if stateDir != profile.DataPath("work") {
		t.Fatalf("stateDir = %q, want %q", stateDir, profile.DataPath("work"))
	}
	if !did.EncryptedExists(stateDir) {
		t.Fatal("identity was not stored in encrypted vault")
	}

	cfg, err := profile.ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if cfg.DefaultProfile != "work" {
		t.Fatalf("DefaultProfile = %q, want work", cfg.DefaultProfile)
	}
	if cfg.Profiles["work"].DID != identity.URI {
		t.Fatalf("profile DID = %q, want %q", cfg.Profiles["work"].DID, identity.URI)
	}
}

func TestLoadLocalContextKeyMigratesLegacyContextKey(t *testing.T) {
	resetVaultPasswordCache(t)

	dir := t.TempDir()
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")

	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := identity.StoreEncrypted(dir, "test-password"); err != nil {
		t.Fatalf("StoreEncrypted: %v", err)
	}

	key := bytes.Repeat([]byte{0x42}, 32)
	ns := &state.NetworkState{
		NetworkRecordID: "network-1",
		ContextKey:      base64.StdEncoding.EncodeToString(key),
	}
	if err := state.SaveNetworkState(dir, ns); err != nil {
		t.Fatalf("SaveNetworkState: %v", err)
	}

	source, ok, err := loadLocalContextKeyForCLI(dir, ns, newEncryptionKeyManager(identity))
	if err != nil {
		t.Fatalf("loadLocalContextKeyForCLI: %v", err)
	}
	if !ok {
		t.Fatal("context key was not loaded")
	}
	if source != "legacy cache (migrated)" {
		t.Fatalf("source = %q, want migrated legacy cache", source)
	}

	stored, ok, err := state.LoadContextKey(dir, "test-password", "network-1")
	if err != nil {
		t.Fatalf("LoadContextKey: %v", err)
	}
	if !ok || !bytes.Equal(stored, key) {
		t.Fatalf("encrypted context key mismatch")
	}
	reloaded, err := state.LoadNetworkState(dir)
	if err != nil {
		t.Fatalf("LoadNetworkState: %v", err)
	}
	if reloaded.ContextKey != "" {
		t.Fatalf("legacy ContextKey = %q, want empty", reloaded.ContextKey)
	}
}
