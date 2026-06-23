package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/internal/invite"
	"github.com/enboxorg/meshd/internal/mesh"
	"github.com/enboxorg/meshd/internal/state"
)

func TestCLIInviteJoinFlow(t *testing.T) {
	endpoint := os.Getenv("DWN_ENDPOINT")
	if endpoint == "" {
		t.Skip("DWN_ENDPOINT not set, skipping CLI integration test")
	}

	resetVaultPasswordCache(t)
	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("MESHD_VAULT_PASSWORD", "cli-e2e-password")

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	anchorStateDir, anchorIdentity := createRegisteredCLIIdentity(t, ctx, endpoint, "anchor")
	joinerStateDir, joinerIdentity := createRegisteredCLIIdentity(t, ctx, endpoint, "joiner")

	networkName := "cli-e2e-" + time.Now().UTC().Format("20060102-150405")
	if err := cmdNetworkCreate(ctx, []string{networkName, "--endpoint", endpoint}, "anchor"); err != nil {
		t.Fatalf("cmdNetworkCreate: %v", err)
	}

	anchorState, err := state.LoadNetworkState(anchorStateDir)
	if err != nil {
		t.Fatalf("LoadNetworkState(anchor): %v", err)
	}
	if anchorState == nil || anchorState.NetworkRecordID == "" {
		t.Fatalf("anchor network state missing record id: %#v", anchorState)
	}
	if anchorState.AnchorDID != anchorIdentity.URI {
		t.Fatalf("anchor DID = %q, want %q", anchorState.AnchorDID, anchorIdentity.URI)
	}

	inviteOutput, err := captureStdout(t, func() error {
		return cmdInviteCreate(ctx, []string{"--label", "cli-e2e", "--expires", "1h"}, "anchor")
	})
	if err != nil {
		t.Fatalf("cmdInviteCreate: %v", err)
	}
	inviteURL := extractInviteURL(t, inviteOutput)
	payload, err := invite.Decode(inviteURL)
	if err != nil {
		t.Fatalf("Decode invite URL: %v", err)
	}
	if payload.NetworkID != anchorState.NetworkRecordID {
		t.Fatalf("invite network id = %q, want %q", payload.NetworkID, anchorState.NetworkRecordID)
	}

	if _, err := captureStdout(t, func() error {
		return cmdJoin(ctx, []string{inviteURL}, "joiner")
	}); err != nil {
		t.Fatalf("cmdJoin initial: %v", err)
	}

	joinerState, err := state.LoadNetworkState(joinerStateDir)
	if err != nil {
		t.Fatalf("LoadNetworkState(joiner pending): %v", err)
	}
	if joinerState == nil {
		t.Fatal("joiner network state missing after initial join")
	}
	if joinerState.NetworkRecordID != anchorState.NetworkRecordID {
		t.Fatalf("joiner network id = %q, want %q", joinerState.NetworkRecordID, anchorState.NetworkRecordID)
	}
	if joinerState.NodeRecordID != "" {
		t.Fatalf("joiner node record = %q, want pending empty node record", joinerState.NodeRecordID)
	}

	approvePreAuthForTest(t, ctx, endpoint, anchorState, anchorIdentity, joinerIdentity)
	refreshJoinForTest(t, ctx, inviteURL, joinerStateDir)

	joinerState, err = state.LoadNetworkState(joinerStateDir)
	if err != nil {
		t.Fatalf("LoadNetworkState(joiner refreshed): %v", err)
	}
	if joinerState == nil || joinerState.NodeRecordID == "" {
		t.Fatalf("joiner state was not approved/refreshed: %#v", joinerState)
	}
	if joinerState.ContextKey != "" {
		t.Fatalf("joiner plaintext context key = %q, want encrypted local secret", joinerState.ContextKey)
	}
	if !state.EncryptedSecretsExist(joinerStateDir) {
		t.Fatal("joiner encrypted local secrets were not created")
	}
	if key, ok, err := state.LoadContextKey(joinerStateDir, "cli-e2e-password", anchorState.NetworkRecordID); err != nil {
		t.Fatalf("LoadContextKey(joiner): %v", err)
	} else if !ok || len(key) == 0 {
		t.Fatalf("joiner context key not stored in encrypted secrets: ok=%v len=%d", ok, len(key))
	}

	if !did.EncryptedExists(anchorStateDir) {
		t.Fatal("anchor identity was not stored in encrypted vault")
	}
	if !did.EncryptedExists(joinerStateDir) {
		t.Fatal("joiner identity was not stored in encrypted vault")
	}
}

func createRegisteredCLIIdentity(t *testing.T, ctx context.Context, endpoint string, profileName string) (string, *did.DID) {
	t.Helper()

	stateDir, identity, err := ensureIdentityForCommand(ctx, profileName, endpoint)
	if err != nil {
		t.Fatalf("ensureIdentityForCommand(%s): %v", profileName, err)
	}
	if err := dwn.RegisterTenant(ctx, endpoint, identity.URI); err != nil {
		t.Fatalf("RegisterTenant(%s): %v", profileName, err)
	}
	return stateDir, identity
}

func approvePreAuthForTest(t *testing.T, ctx context.Context, endpoint string, ns *state.NetworkState, anchorIdentity *did.DID, joinerIdentity *did.DID) {
	t.Helper()

	signer := &dwn.Signer{DID: anchorIdentity.URI, PrivateKey: anchorIdentity.SigningKey}
	params := mesh.ApprovePreAuthRequestsParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchorIdentity.URI,
		NetworkRecordID:      ns.NetworkRecordID,
		MeshCIDR:             ns.MeshCIDR,
		Signer:               signer,
		EncryptionKeyManager: newEncryptionKeyManager(anchorIdentity),
	}

	deadline := time.Now().Add(30 * time.Second)
	var lastResult *mesh.ApprovePreAuthResult
	var lastErr error
	for time.Now().Before(deadline) {
		result, err := mesh.ApprovePreAuthRequests(ctx, params)
		if err == nil && result.Approved == 1 {
			return
		}
		lastResult = result
		lastErr = err
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("preauth request for %s was not approved: result=%#v err=%v", joinerIdentity.URI, lastResult, lastErr)
}

func refreshJoinForTest(t *testing.T, ctx context.Context, inviteURL string, joinerStateDir string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := captureStdout(t, func() error {
			return cmdJoin(ctx, []string{inviteURL}, "joiner")
		}); err != nil {
			lastErr = err
		}
		ns, err := state.LoadNetworkState(joinerStateDir)
		if err != nil {
			t.Fatalf("LoadNetworkState(joiner refresh loop): %v", err)
		}
		if ns != nil && ns.NodeRecordID != "" {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("joiner was not refreshed with approved node record: %v", lastErr)
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()

	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = writer

	done := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, reader)
		done <- buf.Bytes()
	}()

	callErr := fn()
	_ = writer.Close()
	os.Stdout = original
	output := <-done
	_ = reader.Close()
	return string(output), callErr
}

func extractInviteURL(t *testing.T, output string) string {
	t.Helper()

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, invite.SchemePrefix) {
			return line
		}
	}
	t.Fatalf("invite URL not found in output:\n%s", output)
	return ""
}
