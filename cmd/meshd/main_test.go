package main

import (
	"context"
	"strings"
	"testing"

	"github.com/enboxorg/meshd/internal/invite"
	"github.com/enboxorg/meshd/internal/profile"
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

func TestEnsureIdentityForCommandCreatesDefaultProfile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")

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
