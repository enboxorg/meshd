package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/internal/invite"
	"github.com/enboxorg/meshd/internal/mesh"
	"github.com/enboxorg/meshd/internal/profile"
	"github.com/enboxorg/meshd/internal/state"
	"github.com/enboxorg/meshd/internal/walletconnect"
	"github.com/enboxorg/meshd/protocols"
)

func TestParseUpFlagsInviteURL(t *testing.T) {
	u, err := invite.Encode(invite.New("https://dwn.example.com", "did:jwk:anchor", "net", "home", "", "", ""))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	flags := parseUpFlags([]string{u, "--owner", "did:dht:wallet", "--no-tun"})
	if flags.inviteURL != u {
		t.Fatalf("inviteURL = %q, want %q", flags.inviteURL, u)
	}
	if flags.ownerDID != "did:dht:wallet" {
		t.Fatalf("ownerDID = %q", flags.ownerDID)
	}
	if !flags.noTun {
		t.Fatal("expected --no-tun to be parsed")
	}
}

func TestParseUpFlagsPositionalOwnerDID(t *testing.T) {
	flags := parseUpFlags([]string{"did:example:owner", "--no-tun"})
	if flags.ownerDID != "did:example:owner" {
		t.Fatalf("ownerDID = %q", flags.ownerDID)
	}
	if flags.inviteURL != "" {
		t.Fatalf("inviteURL = %q, want empty", flags.inviteURL)
	}
	if !flags.noTun {
		t.Fatal("expected --no-tun to be parsed")
	}

	overridden := parseUpFlags([]string{"did:example:pasted", "--owner", "did:example:explicit"})
	if overridden.ownerDID != "did:example:explicit" {
		t.Fatalf("explicit owner should win, got %q", overridden.ownerDID)
	}
}

func TestPromptInteractiveJoinAcceptsInviteFirst(t *testing.T) {
	u, err := invite.Encode(invite.New("https://dwn.example.com", "did:jwk:anchor", "net", "home", "", "", ""))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, err := promptInteractiveJoin(bufio.NewScanner(strings.NewReader(u+"\n")), "")
	if err != nil {
		t.Fatalf("promptInteractiveJoin: %v", err)
	}
	if got.inviteURL != u {
		t.Fatalf("inviteURL = %q, want %q", got.inviteURL, u)
	}
	if got.endpoint != "" || got.anchorDID != "" || got.networkID != "" {
		t.Fatalf("manual fields should be empty for invite join: %+v", got)
	}
}

func TestPromptInteractiveJoinFallsBackToManualDetails(t *testing.T) {
	input := "\nhttps://dwn.example.com\ndid:jwk:anchor\nnetwork-1\n"
	got, err := promptInteractiveJoin(bufio.NewScanner(strings.NewReader(input)), "")
	if err != nil {
		t.Fatalf("promptInteractiveJoin: %v", err)
	}
	if got.inviteURL != "" {
		t.Fatalf("inviteURL = %q, want empty", got.inviteURL)
	}
	if got.endpoint != "https://dwn.example.com" || got.anchorDID != "did:jwk:anchor" || got.networkID != "network-1" {
		t.Fatalf("manual join input = %+v", got)
	}
}

func TestParseInteractiveSetupChoice(t *testing.T) {
	u, err := invite.Encode(invite.New("https://dwn.example.com", "did:jwk:anchor", "net", "home", "", "", ""))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	tests := []struct {
		name      string
		input     string
		want      interactiveSetupChoice
		wantValue string
	}{
		{name: "default", input: "", want: interactiveSetupOwner},
		{name: "owner number", input: "1", want: interactiveSetupOwner},
		{name: "owner word", input: "owner", want: interactiveSetupOwner},
		{name: "owner DID", input: " did:jwk:owner ", want: interactiveSetupOwner, wantValue: "did:jwk:owner"},
		{name: "create number", input: "2", want: interactiveSetupCreate},
		{name: "create word", input: "create", want: interactiveSetupCreate},
		{name: "join number", input: "3", want: interactiveSetupJoin},
		{name: "join word", input: "invite", want: interactiveSetupJoin},
		{name: "invite URL", input: u, want: interactiveSetupJoin, wantValue: u},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, value, err := parseInteractiveSetupChoice(tt.input)
			if err != nil {
				t.Fatalf("parseInteractiveSetupChoice: %v", err)
			}
			if got != tt.want || value != tt.wantValue {
				t.Fatalf("choice = %q value = %q, want %q/%q", got, value, tt.want, tt.wantValue)
			}
		})
	}

	if _, _, err := parseInteractiveSetupChoice("wat"); err == nil {
		t.Fatal("expected invalid setup choice to fail")
	}
}

func TestDefaultTUNName(t *testing.T) {
	if got := defaultTUNName("darwin"); got != "utun" {
		t.Fatalf("defaultTUNName(darwin) = %q, want utun", got)
	}
	if got := defaultTUNName("linux"); got != "meshd0" {
		t.Fatalf("defaultTUNName(linux) = %q, want meshd0", got)
	}
}

func TestPeerListMeshIPFallsBackToDeterministicIP(t *testing.T) {
	const peerDID = "did:jwk:test-peer"
	want, err := mesh.AllocateMeshIP("10.200.0.0/16", peerDID)
	if err != nil {
		t.Fatalf("AllocateMeshIP: %v", err)
	}
	if got := peerListMeshIP("10.200.0.0/16", peerDID, ""); got != want.String() {
		t.Fatalf("peerListMeshIP fallback = %q, want %q", got, want)
	}
	if got := peerListMeshIP("10.200.0.0/16", peerDID, "10.200.9.9"); got != "10.200.9.9" {
		t.Fatalf("peerListMeshIP explicit = %q, want explicit record IP", got)
	}
	if got := peerListMeshIP("", peerDID, ""); got != "?" {
		t.Fatalf("peerListMeshIP missing CIDR = %q, want ?", got)
	}
}

func TestPeerListDeviceLabelsSelf(t *testing.T) {
	const selfDID = "did:jwk:self"
	if got := peerListDevice(selfDID, selfDID); got != "this device" {
		t.Fatalf("peerListDevice(self) = %q, want this device", got)
	}
	if got := peerListDevice("did:jwk:peer", selfDID); got != "peer" {
		t.Fatalf("peerListDevice(peer) = %q, want peer", got)
	}
	if got := peerListDevice("", selfDID); got != "peer" {
		t.Fatalf("peerListDevice(empty) = %q, want peer", got)
	}
}

func TestPeerListOwner(t *testing.T) {
	const (
		nodeDID  = "did:jwk:node"
		ownerDID = "did:jwk:wallet"
	)
	if got := peerListOwner(nodeDID, "", nodeDID, ownerDID); got != ownerDID {
		t.Fatalf("peerListOwner(self fallback) = %q, want %q", got, ownerDID)
	}
	if got := peerListOwner(nodeDID, ownerDID, "", ""); got != ownerDID {
		t.Fatalf("peerListOwner(record owner) = %q, want %q", got, ownerDID)
	}
	if got := peerListOwner(nodeDID, "", "", ""); got != "node" {
		t.Fatalf("peerListOwner(local-only) = %q, want node", got)
	}
	if got := peerListOwner(nodeDID, nodeDID, "", ""); got != "node" {
		t.Fatalf("peerListOwner(same as node) = %q, want node", got)
	}
}

func TestRouteInterfaceParsesPlatformOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "linux ip route",
			output: "10.200.43.197 dev meshd0 src 10.200.26.192 uid 1000\n    cache\n",
			want:   "meshd0",
		},
		{
			name: "darwin route get",
			output: `   route to: 10.200.26.192
destination: 10.200.26.192
  interface: utun7
`,
			want: "utun7",
		},
		{
			name:   "missing",
			output: "default via 100.64.0.1\n",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := routeInterface(tt.output); got != tt.want {
				t.Fatalf("routeInterface() = %q, want %q", got, tt.want)
			}
		})
	}
	if !routeUsesInterface("10.200.43.197 dev meshd0 src 10.200.26.192", "meshd0") {
		t.Fatal("expected routeUsesInterface to match meshd0")
	}
	if routeUsesInterface("10.200.43.197 dev tailscale0 src 100.64.0.1", "meshd0") {
		t.Fatal("expected routeUsesInterface to reject tailscale0")
	}
}

func TestPrintDoctorCheck(t *testing.T) {
	var buf bytes.Buffer
	printDoctorCheck(&buf, doctorCheck{
		Level:  doctorFail,
		Title:  "Peer route does not use meshd TUN",
		Detail: "10.200.26.192 routes via tailscale0, not meshd0",
		Next:   "Run 'meshd down' and then 'meshd up'.",
	})
	got := buf.String()
	for _, want := range []string{
		"[fail] Peer route does not use meshd TUN",
		"10.200.26.192 routes via tailscale0, not meshd0",
		"Next: Run 'meshd down' and then 'meshd up'.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, got)
		}
	}
}

func TestBuildAdminURL(t *testing.T) {
	rawURL := buildAdminURL("https://meshd-admin.pages.dev/", adminContext{
		OwnerDID:        "did:dht:wallet",
		NetworkRecordID: "network-1",
	})
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != "https://meshd-admin.pages.dev" {
		t.Fatalf("admin URL base = %q", got)
	}
	if got := parsed.Query().Get("owner"); got != "did:dht:wallet" {
		t.Fatalf("owner query = %q", got)
	}
	if got := parsed.Query().Get("network"); got != "network-1" {
		t.Fatalf("network query = %q", got)
	}
	if got := buildAdminURL("", adminContext{}); got != "https://meshd-admin.pages.dev" {
		t.Fatalf("default admin URL = %q", got)
	}
	if got := adminDashboardCommand(adminContext{OwnerDID: "did:example:own'er", NetworkRecordID: "network-1"}, true); got != "meshd admin --owner 'did:example:own'\\''er' --network 'network-1' --print" {
		t.Fatalf("admin dashboard command = %q", got)
	}
}

func TestParseAdminArgs(t *testing.T) {
	opts, err := parseAdminArgs([]string{"--dashboard", "http://127.0.0.1:5173", "--owner", "did:example:owner", "--network", "network-1", "--print"})
	if err != nil {
		t.Fatalf("parseAdminArgs: %v", err)
	}
	if opts.dashboardURL != "http://127.0.0.1:5173" || opts.ownerDID != "did:example:owner" || opts.networkRecordID != "network-1" || !opts.printOnly {
		t.Fatalf("admin opts = %+v", opts)
	}
	ctx := adminContextFromOptions(opts, adminContext{OwnerDID: "did:example:fallback", NetworkRecordID: "fallback-network"})
	if ctx.OwnerDID != "did:example:owner" || ctx.NetworkRecordID != "network-1" {
		t.Fatalf("admin context = %+v", ctx)
	}
	if _, err := parseAdminArgs([]string{"--wallet"}); err == nil {
		t.Fatal("expected missing wallet URL to fail")
	}
	if _, err := parseAdminArgs([]string{"--owner"}); err == nil {
		t.Fatal("expected missing owner DID to fail")
	}
	if _, err := parseAdminArgs([]string{"--network", "  "}); err == nil {
		t.Fatal("expected blank network ID to fail")
	}
	if _, err := parseAdminArgs([]string{"--unknown"}); err == nil {
		t.Fatal("expected unknown flag to fail")
	}
}

func TestCollectDoctorChecksNoProfile(t *testing.T) {
	t.Setenv("ENBOX_HOME", t.TempDir())
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")

	checks := collectDoctorChecks(context.Background(), "")
	if len(checks) == 0 {
		t.Fatal("expected at least one doctor check")
	}
	if checks[0].Level != doctorFail || !strings.Contains(checks[0].Title, "identity profile") {
		t.Fatalf("first check = %+v, want missing profile failure", checks[0])
	}
	if !doctorHasLevel(checks, doctorFail) {
		t.Fatal("expected doctor failure level")
	}
}

func TestPeerListRowsFromMapResponse(t *testing.T) {
	ns := &state.NetworkState{MeshCIDR: "10.200.0.0/16"}
	resp := &control.MapResponse{
		Node: &control.Node{
			DID:       "did:jwk:self",
			MemberDID: "did:jwk:wallet",
			Name:      "laptop",
			Label:     "macbook",
			MeshIP:    netip.MustParseAddr("10.200.0.5"),
			ExpiresAt: "2026-07-01T00:00:00Z",
		},
		Peers: []*control.Node{
			{
				DID:            "did:jwk:peer",
				MemberDID:      "did:jwk:wallet",
				MemberRecordID: "member-record",
				Name:           "server",
				Label:          "server-label",
				MeshIP:         netip.MustParseAddr("10.200.0.8"),
				ExpiresAt:      "2026-07-02T00:00:00Z",
			},
		},
	}

	rows := peerListRowsFromMapResponse(ns, resp, "did:jwk:self", "did:jwk:wallet")
	if len(rows) != 2 {
		t.Fatalf("rows len = %d, want 2", len(rows))
	}
	if rows[0].Device != "this device" || rows[0].Owner != "did:jwk:wallet" || rows[0].Path != "network/node" {
		t.Fatalf("self row = %+v", rows[0])
	}
	if rows[1].Device != "peer" || rows[1].Owner != "did:jwk:wallet" || rows[1].Path != "network/member/node" {
		t.Fatalf("peer row = %+v", rows[1])
	}
	if rows[0].Label != "macbook" || rows[1].MeshIP != "10.200.0.8" || rows[1].Label != "server-label" {
		t.Fatalf("peer row data = %+v", rows)
	}
	if rows[0].Expires != "2026-07-01T00:00:00Z" || rows[1].Expires != "2026-07-02T00:00:00Z" {
		t.Fatalf("peer row expiry = %+v", rows)
	}
}

func TestRefreshLocalMembershipMetadataFromMap(t *testing.T) {
	dir := t.TempDir()
	ns := &state.NetworkState{
		NetworkRecordID: "network-1",
		NetworkName:     "home",
		MeshCIDR:        "10.200.0.0/16",
		MeshIP:          "10.200.0.5",
		NodeExpiresAt:   "2026-07-01T00:00:00Z",
		NodeLabel:       "old-label",
		NodeDID:         "did:jwk:node",
		OwnerDID:        "did:jwk:old-owner",
		MemberDID:       "did:jwk:old-owner",
		NodeRecordID:    "node-1",
		MemberRecordID:  "member-1",
	}
	if err := state.SaveNetworkState(dir, ns); err != nil {
		t.Fatalf("SaveNetworkState: %v", err)
	}

	refreshed, changed, err := refreshLocalMembershipMetadataFromMap(dir, ns, &control.MapResponse{
		Node: &control.Node{
			DID:            "did:jwk:node",
			Name:           "server-host",
			Label:          "server-01",
			MeshIP:         netip.MustParseAddr("10.200.0.9"),
			MemberDID:      "did:jwk:wallet",
			MemberRecordID: "member-2",
		},
	})
	if err != nil {
		t.Fatalf("refreshLocalMembershipMetadataFromMap: %v", err)
	}
	if !changed {
		t.Fatal("refreshLocalMembershipMetadataFromMap changed = false, want true")
	}
	if refreshed.MeshIP != "10.200.0.9" || refreshed.NodeExpiresAt != "" || refreshed.NodeLabel != "server-01" || refreshed.OwnerDID != "did:jwk:wallet" || refreshed.MemberRecordID != "member-2" {
		t.Fatalf("refreshed state = %+v", refreshed)
	}

	reloaded, err := state.LoadNetworkState(dir)
	if err != nil {
		t.Fatalf("LoadNetworkState: %v", err)
	}
	if reloaded.MeshIP != "10.200.0.9" || reloaded.NodeExpiresAt != "" || reloaded.NodeLabel != "server-01" || reloaded.OwnerDID != "did:jwk:wallet" || reloaded.MemberDID != "did:jwk:wallet" || reloaded.MemberRecordID != "member-2" {
		t.Fatalf("persisted state = %+v", reloaded)
	}
}

func TestPeerListExpiry(t *testing.T) {
	if got := peerListExpiry(""); got != "never" {
		t.Fatalf("empty expiry = %q, want never", got)
	}
	if got := peerListExpiry("unknown"); got != "unknown" {
		t.Fatalf("unknown expiry = %q", got)
	}
	future := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Minute)
	if got, want := peerListExpiry(future.Format(time.RFC3339)), future.Format("2006-01-02 15:04"); got != want {
		t.Fatalf("future expiry = %q", got)
	}
	if got := peerListExpiry("2020-01-01T00:00:00Z"); got != "expired" {
		t.Fatalf("past expiry = %q, want expired", got)
	}
	if got := peerListExpiry("not-a-valid-rfc3339-date"); got != "not-a-valid-rf..." {
		t.Fatalf("malformed expiry = %q", got)
	}
}

func TestParsePeerAddOptions(t *testing.T) {
	opts, err := parsePeerAddOptions([]string{
		"did:jwk:node",
		"--owner", "did:jwk:wallet",
		"--label", "server",
	})
	if err != nil {
		t.Fatalf("parsePeerAddOptions: %v", err)
	}
	if opts.nodeDID != "did:jwk:node" || opts.ownerDID != "did:jwk:wallet" || opts.label != "server" {
		t.Fatalf("options = %+v", opts)
	}

	legacyOpts, err := parsePeerAddOptions([]string{"did:jwk:node", "--member", "did:jwk:wallet"})
	if err != nil {
		t.Fatalf("parsePeerAddOptions member alias: %v", err)
	}
	if legacyOpts.ownerDID != "did:jwk:wallet" {
		t.Fatalf("member alias ownerDID = %q", legacyOpts.ownerDID)
	}

	if _, err := parsePeerAddOptions([]string{"--member", "did:jwk:wallet"}); err == nil {
		t.Fatal("parsePeerAddOptions without node DID succeeded")
	}
}

func TestParsePeerRemoveOptions(t *testing.T) {
	opts, err := parsePeerRemoveOptions([]string{"did:jwk:node"})
	if err != nil {
		t.Fatalf("parsePeerRemoveOptions: %v", err)
	}
	if opts.nodeDID != "did:jwk:node" {
		t.Fatalf("nodeDID = %q", opts.nodeDID)
	}
	if _, err := parsePeerRemoveOptions(nil); err == nil {
		t.Fatal("parsePeerRemoveOptions without node DID succeeded")
	}
	if _, err := parsePeerRemoveOptions([]string{"did:jwk:node", "extra"}); err == nil {
		t.Fatal("parsePeerRemoveOptions with extra argument succeeded")
	}
	if _, err := parsePeerRemoveOptions([]string{"--force", "did:jwk:node"}); err == nil {
		t.Fatal("parsePeerRemoveOptions with unknown flag succeeded")
	}
}

func TestPeerRemoveCandidateFromRecord(t *testing.T) {
	candidate, ok := peerRemoveCandidateFromRecord(&dwn.Record{
		ID:           "node-record",
		ProtocolPath: "network/node",
	}, "")
	if !ok {
		t.Fatal("top-level candidate not returned")
	}
	if candidate.RecordID != "node-record" || candidate.Path != "network/node" || candidate.MemberRecordID != "" {
		t.Fatalf("top-level candidate = %+v", candidate)
	}

	memberCandidate, ok := peerRemoveCandidateFromRecord(&dwn.Record{
		ID: "member-node-record",
	}, "member-record")
	if !ok {
		t.Fatal("member candidate not returned")
	}
	if memberCandidate.Path != "network/member/node" || memberCandidate.MemberRecordID != "member-record" {
		t.Fatalf("member candidate = %+v", memberCandidate)
	}

	if _, ok := peerRemoveCandidateFromRecord(&dwn.Record{}, ""); ok {
		t.Fatal("empty record candidate returned")
	}
	if _, ok := peerRemoveCandidateFromRecord(nil, ""); ok {
		t.Fatal("nil record candidate returned")
	}
}

func TestAuthDisplayName(t *testing.T) {
	tests := []struct {
		name     string
		authType string
		want     string
	}{
		{name: "default", authType: "", want: "local vault"},
		{name: "local", authType: profile.AuthTypeLocalVault, want: "local vault"},
		{name: "wallet", authType: profile.AuthTypeWalletAuthorizedNode, want: "wallet-authorized node"},
		{name: "legacy wallet", authType: profile.AuthTypeWalletDelegate, want: "wallet-authorized node"},
		{name: "unknown", authType: "custom", want: "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authDisplayName(tt.authType); got != tt.want {
				t.Fatalf("authDisplayName(%q) = %q, want %q", tt.authType, got, tt.want)
			}
		})
	}
}

func TestLoadWalletSessionStatus(t *testing.T) {
	resetVaultPasswordCache(t)

	stateDir := t.TempDir()
	t.Setenv(vaultPasswordEnv, "test-password")
	if err := state.StoreWalletSession(stateDir, "test-password", &state.WalletSession{
		Version:                 1,
		OwnerDID:                "did:dht:wallet",
		DelegateDID:             "did:jwk:control",
		NodeDID:                 "did:jwk:node",
		WalletOrigin:            "https://wallet.enbox.id",
		ExpiresAt:               "2999-01-01T00:00:00Z",
		Grants:                  []json.RawMessage{json.RawMessage(`{"id":"grant-1"}`), json.RawMessage(`{"id":"grant-2"}`)},
		NodeMultiPartyProtocols: []string{protocols.MeshProtocolURI},
	}); err != nil {
		t.Fatalf("StoreWalletSession: %v", err)
	}

	status, err := loadWalletSessionStatus(stateDir, identityMetadata{
		AuthType: profile.AuthTypeWalletAuthorizedNode,
		OwnerDID: "did:dht:wallet",
		NodeDID:  "did:jwk:node",
	})
	if err != nil {
		t.Fatalf("loadWalletSessionStatus: %v", err)
	}
	if !status.Exists || status.GrantCount != 2 || status.NodeProtocolCount != 1 {
		t.Fatalf("wallet session status = %+v", status)
	}
	if status.DelegateDID != "did:jwk:control" {
		t.Fatalf("wallet session metadata = %+v", status)
	}
	if status.OwnerDIDMismatch || status.NodeDIDMismatch {
		t.Fatalf("unexpected mismatch = %+v", status)
	}
}

func TestLoadWalletSessionStatusReportsRuntimeAndAdminAccess(t *testing.T) {
	resetVaultPasswordCache(t)

	stateDir := t.TempDir()
	t.Setenv(vaultPasswordEnv, "test-password")
	meta := identityMetadata{
		AuthType: profile.AuthTypeWalletAuthorizedNode,
		OwnerDID: "did:dht:wallet",
		NodeDID:  "did:jwk:node",
	}
	runtimeGrants := []json.RawMessage{
		testWalletPermissionGrant(t, "mesh-read", meta.OwnerDID, meta.NodeDID, map[string]any{
			"interface": "Records",
			"method":    "Read",
			"protocol":  protocols.MeshProtocolURI,
		}),
		testWalletPermissionGrant(t, "node-info-write", meta.OwnerDID, meta.NodeDID, map[string]any{
			"interface":    "Records",
			"method":       "Write",
			"protocol":     protocols.MeshProtocolURI,
			"protocolPath": "network/node/nodeInfo",
		}),
		testWalletPermissionGrant(t, "node-endpoint-write", meta.OwnerDID, meta.NodeDID, map[string]any{
			"interface":    "Records",
			"method":       "Write",
			"protocol":     protocols.MeshProtocolURI,
			"protocolPath": "network/node/endpoint",
		}),
		testWalletPermissionGrant(t, "member-node-info-write", meta.OwnerDID, meta.NodeDID, map[string]any{
			"interface":    "Records",
			"method":       "Write",
			"protocol":     protocols.MeshProtocolURI,
			"protocolPath": "network/member/node/nodeInfo",
		}),
		testWalletPermissionGrant(t, "member-node-endpoint-write", meta.OwnerDID, meta.NodeDID, map[string]any{
			"interface":    "Records",
			"method":       "Write",
			"protocol":     protocols.MeshProtocolURI,
			"protocolPath": "network/member/node/endpoint",
		}),
	}

	if err := state.StoreWalletSession(stateDir, "test-password", &state.WalletSession{
		Version:  1,
		OwnerDID: meta.OwnerDID,
		NodeDID:  meta.NodeDID,
		Grants:   runtimeGrants,
	}); err != nil {
		t.Fatalf("StoreWalletSession runtime: %v", err)
	}
	status, err := loadWalletSessionStatus(stateDir, meta)
	if err != nil {
		t.Fatalf("loadWalletSessionStatus runtime: %v", err)
	}
	if !status.NodeRuntimeAccess {
		t.Fatalf("runtime access = false, status = %+v", status)
	}
	if status.AdminControlAccess {
		t.Fatalf("admin access = true for runtime grants, status = %+v", status)
	}

	adminGrants := append([]json.RawMessage{}, runtimeGrants...)
	adminGrants = append(adminGrants,
		testWalletPermissionGrant(t, "mesh-write", meta.OwnerDID, meta.NodeDID, map[string]any{
			"interface": "Records",
			"method":    "Write",
			"protocol":  protocols.MeshProtocolURI,
		}),
		testWalletPermissionGrant(t, "mesh-delete", meta.OwnerDID, meta.NodeDID, map[string]any{
			"interface": "Records",
			"method":    "Delete",
			"protocol":  protocols.MeshProtocolURI,
		}),
	)
	if err := state.StoreWalletSession(stateDir, "test-password", &state.WalletSession{
		Version:  1,
		OwnerDID: meta.OwnerDID,
		NodeDID:  meta.NodeDID,
		Grants:   adminGrants,
	}); err != nil {
		t.Fatalf("StoreWalletSession admin: %v", err)
	}
	status, err = loadWalletSessionStatus(stateDir, meta)
	if err != nil {
		t.Fatalf("loadWalletSessionStatus admin: %v", err)
	}
	if !status.NodeRuntimeAccess || !status.AdminControlAccess {
		t.Fatalf("admin status = %+v, want runtime and admin access", status)
	}
}

func TestLoadWalletSessionStatusMissing(t *testing.T) {
	status, err := loadWalletSessionStatus(t.TempDir(), identityMetadata{
		AuthType: profile.AuthTypeWalletAuthorizedNode,
	})
	if err != nil {
		t.Fatalf("loadWalletSessionStatus: %v", err)
	}
	if status == nil || status.Exists {
		t.Fatalf("missing session status = %+v", status)
	}
}

func TestParseUpFlagsTunUsesPlatformDefault(t *testing.T) {
	flags := parseUpFlags([]string{"--tun"})
	want := defaultTUNName(runtime.GOOS)
	if flags.tunName != want {
		t.Fatalf("tunName = %q, want %q", flags.tunName, want)
	}
}

func TestParseUpFlagsForeground(t *testing.T) {
	flags := parseUpFlags([]string{"--foreground"})
	if !flags.foreground {
		t.Fatal("expected --foreground to be parsed")
	}
}

func TestShouldReexecWithSudoForTun(t *testing.T) {
	if !shouldReexecWithSudoForTun(upFlags{}, 501, "darwin", true) {
		t.Fatal("expected interactive non-root darwin up to reexec with sudo")
	}
	if !shouldReexecWithSudoForTun(upFlags{}, 1000, "linux", true) {
		t.Fatal("expected interactive non-root linux up to reexec with sudo")
	}
	if shouldReexecWithSudoForTun(upFlags{}, 0, "linux", true) {
		t.Fatal("did not expect root to reexec with sudo")
	}
	if shouldReexecWithSudoForTun(upFlags{noTun: true}, 1000, "linux", true) {
		t.Fatal("did not expect --no-tun to reexec with sudo")
	}
	if shouldReexecWithSudoForTun(upFlags{}, 1000, "linux", false) {
		t.Fatal("did not expect non-interactive up to reexec with sudo")
	}
	if shouldReexecWithSudoForTun(upFlags{}, 1000, "freebsd", true) {
		t.Fatal("did not expect unsupported OS to reexec with sudo")
	}
}

func TestSudoEnvironmentAssignments(t *testing.T) {
	home := t.TempDir()
	enboxHome := filepath.Join(home, ".enbox-custom")
	t.Setenv("HOME", home)
	t.Setenv("ENBOX_HOME", enboxHome)
	t.Setenv("PATH", "/tmp/test-path")
	t.Setenv("DWN_ENDPOINT", "https://dwn.example")
	t.Setenv("ENBOX_PROFILE", "work")
	t.Setenv("MESHD_STATE_DIR", filepath.Join(home, "state"))
	t.Setenv("MESHD_VAULT_PASSWORD", "secret")
	t.Setenv(vaultPasswordCacheDirEnv, filepath.Join(home, "runtime-cache"))
	t.Setenv(vaultPasswordCacheTTLEnv, "2m")

	assignments := sudoEnvironmentAssignments()
	for _, want := range []string{
		sudoChildEnv + "=1",
		"HOME=" + home,
		"ENBOX_HOME=" + enboxHome,
		"PATH=/tmp/test-path",
		"DWN_ENDPOINT=https://dwn.example",
		"ENBOX_PROFILE=work",
		"MESHD_STATE_DIR=" + filepath.Join(home, "state"),
		vaultPasswordCacheDirEnv + "=" + filepath.Join(home, "runtime-cache"),
		vaultPasswordCacheTTLEnv + "=2m",
	} {
		if !hasString(assignments, want) {
			t.Fatalf("sudoEnvironmentAssignments() missing %q in %v", want, assignments)
		}
	}
	for _, got := range assignments {
		if strings.HasPrefix(got, "MESHD_VAULT_PASSWORD=") {
			t.Fatal("sudoEnvironmentAssignments must not expose MESHD_VAULT_PASSWORD")
		}
	}
}

func TestSudoEnvironmentAssignmentsDefaultsEnboxHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ENBOX_HOME", "")

	assignments := sudoEnvironmentAssignments()
	want := "ENBOX_HOME=" + filepath.Join(home, ".enbox")
	if !hasString(assignments, want) {
		t.Fatalf("sudoEnvironmentAssignments() missing %q in %v", want, assignments)
	}
}

func TestSudoOriginalIDs(t *testing.T) {
	t.Setenv("SUDO_UID", "501")
	t.Setenv("SUDO_GID", "20")

	uid, gid, ok := sudoOriginalIDs()
	if !ok || uid != 501 || gid != 20 {
		t.Fatalf("sudoOriginalIDs() = %d, %d, %v; want 501, 20, true", uid, gid, ok)
	}

	t.Setenv("SUDO_UID", "0")
	if _, _, ok := sudoOriginalIDs(); ok {
		t.Fatal("sudoOriginalIDs() should reject root SUDO_UID")
	}
}

func TestSudoOwnershipRoots(t *testing.T) {
	home := t.TempDir()
	stateDir := filepath.Join(home, "state")
	enboxHome := filepath.Join(home, ".enbox")
	t.Setenv("HOME", home)
	t.Setenv("MESHD_STATE_DIR", stateDir)
	t.Setenv("ENBOX_HOME", enboxHome)

	roots := sudoOwnershipRoots()
	if len(roots) != 1 || roots[0] != stateDir {
		t.Fatalf("sudoOwnershipRoots() = %v, want [%s]", roots, stateDir)
	}

	t.Setenv("MESHD_STATE_DIR", "")
	roots = sudoOwnershipRoots()
	if len(roots) != 1 || roots[0] != enboxHome {
		t.Fatalf("sudoOwnershipRoots() = %v, want [%s]", roots, enboxHome)
	}
}

func TestSudoOwnershipRootsRejectsOutsideHome(t *testing.T) {
	home := t.TempDir()
	outside := filepath.Join(t.TempDir(), "state")
	t.Setenv("HOME", home)
	t.Setenv("MESHD_STATE_DIR", outside)
	t.Setenv("ENBOX_HOME", "")

	if roots := sudoOwnershipRoots(); len(roots) != 0 {
		t.Fatalf("sudoOwnershipRoots() = %v, want empty for path outside HOME", roots)
	}
	if isSafeSudoOwnershipRoot(home, home) {
		t.Fatal("home itself must not be accepted as an ownership root")
	}
}

func TestEnsureDWNTenantRegistered(t *testing.T) {
	var registeredDID string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/info":
			writeJSON(t, w, map[string]any{
				"registrationRequirements": []string{"provider-auth-v0"},
				"providerAuth": map[string]string{
					"authorizeUrl": server.URL + "/authorize",
					"tokenUrl":     server.URL + "/token",
				},
			})
		case "/authorize":
			writeJSON(t, w, map[string]string{
				"code":  "test-code",
				"state": r.URL.Query().Get("state"),
			})
		case "/token":
			writeJSON(t, w, map[string]string{"registrationToken": "test-token"})
		case "/registration":
			var body struct {
				RegistrationData struct {
					DID string `json:"did"`
				} `json:"registrationData"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decoding registration body: %v", err)
			}
			registeredDID = body.RegistrationData.DID
			writeJSON(t, w, map[string]string{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	identity := &did.DID{URI: "did:jwk:test"}
	if err := ensureDWNTenantRegistered(context.Background(), server.URL, identity); err != nil {
		t.Fatalf("ensureDWNTenantRegistered: %v", err)
	}
	if registeredDID != identity.URI {
		t.Fatalf("registered DID = %q, want %q", registeredDID, identity.URI)
	}
}

func TestEnsureDWNTenantRegisteredNoopWithoutEndpoint(t *testing.T) {
	if err := ensureDWNTenantRegistered(context.Background(), "", &did.DID{URI: "did:jwk:test"}); err != nil {
		t.Fatalf("ensureDWNTenantRegistered empty endpoint: %v", err)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encoding response: %v", err)
	}
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestParseNetworkCreateArgs(t *testing.T) {
	t.Setenv("DWN_ENDPOINT", "")

	name, endpoint := parseNetworkCreateArgs([]string{"home", "--endpoint", "https://dwn.example.com"})
	if name != "home" {
		t.Fatalf("name = %q, want home", name)
	}
	if endpoint != "https://dwn.example.com" {
		t.Fatalf("endpoint = %q, want https://dwn.example.com", endpoint)
	}
}

func TestParseNetworkCreateArgsUsesEndpointEnv(t *testing.T) {
	t.Setenv("DWN_ENDPOINT", "https://env.example.com")

	name, endpoint := parseNetworkCreateArgs([]string{"home"})
	if name != "home" {
		t.Fatalf("name = %q, want home", name)
	}
	if endpoint != "https://env.example.com" {
		t.Fatalf("endpoint = %q, want https://env.example.com", endpoint)
	}
}

func TestParseNetworkCreateOptionsWalletFlags(t *testing.T) {
	t.Setenv("DWN_ENDPOINT", "")

	opts, err := parseNetworkCreateOptions([]string{
		"home",
		"--endpoint", "https://dev.aws.dwn.enbox.id",
		"--cidr", "10.201.0.0/16",
		"--request-out", "request.json",
		"--wallet", "https://wallet.enbox.id",
	})
	if err != nil {
		t.Fatalf("parseNetworkCreateOptions: %v", err)
	}
	if opts.name != "home" || opts.endpoint != "https://dev.aws.dwn.enbox.id" {
		t.Fatalf("name/endpoint = %q/%q", opts.name, opts.endpoint)
	}
	if opts.meshCIDR != "10.201.0.0/16" {
		t.Fatalf("meshCIDR = %q", opts.meshCIDR)
	}
	if opts.requestOut != "request.json" {
		t.Fatalf("requestOut = %q", opts.requestOut)
	}
	if opts.walletURL != "https://wallet.enbox.id" {
		t.Fatalf("walletURL = %q", opts.walletURL)
	}
}

func TestWalletResponseCallbackAcceptsPost(t *testing.T) {
	cb, err := startWalletResponseCallback()
	if err != nil {
		t.Fatalf("startWalletResponseCallback: %v", err)
	}
	defer cb.close()

	preflight, err := http.NewRequest(http.MethodOptions, cb.url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	preflight.Header.Set("Access-Control-Request-Private-Network", "true")
	preflightResp, err := http.DefaultClient.Do(preflight)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	preflightResp.Body.Close()
	if preflightResp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want %d", preflightResp.StatusCode, http.StatusNoContent)
	}
	if got := preflightResp.Header.Get("Access-Control-Allow-Private-Network"); got != "true" {
		t.Fatalf("Access-Control-Allow-Private-Network = %q, want true", got)
	}

	postResp, err := http.Post(cb.url, "application/json", strings.NewReader(`{"ok":true}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusAccepted {
		t.Fatalf("post status = %d, want %d", postResp.StatusCode, http.StatusAccepted)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data, err := cb.wait(ctx)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if string(data) != `{"ok":true}` {
		t.Fatalf("callback data = %q", data)
	}
}

func TestBrowserOpenCommand(t *testing.T) {
	for _, tc := range []struct {
		goos string
		want string
	}{
		{goos: "darwin", want: "open"},
		{goos: "linux", want: "xdg-open"},
		{goos: "windows", want: "rundll32"},
	} {
		t.Run(tc.goos, func(t *testing.T) {
			got, args, ok := browserOpenCommand(tc.goos, "https://wallet.enbox.id")
			if !ok {
				t.Fatal("browserOpenCommand returned !ok")
			}
			if got != tc.want {
				t.Fatalf("command = %q, want %q", got, tc.want)
			}
			if len(args) == 0 {
				t.Fatal("expected args")
			}
		})
	}
}

func TestNetworkCreateWalletAuthorizedNodeAllowsMissingEndpoint(t *testing.T) {
	resetVaultPasswordCache(t)

	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")
	t.Setenv("DWN_ENDPOINT", "")

	_, identity, err := ensureIdentityForCommand(context.Background(), "walleted", "")
	if err != nil {
		t.Fatalf("ensureIdentityForCommand: %v", err)
	}
	if err := profile.UpsertProfileEntry(&profile.Entry{
		Name:     "walleted",
		DID:      identity.URI,
		AuthType: profile.AuthTypeWalletAuthorizedNode,
		OwnerDID: "did:dht:wallet",
		NodeDID:  identity.URI,
	}); err != nil {
		t.Fatalf("UpsertProfileEntry: %v", err)
	}

	requestFile := filepath.Join(t.TempDir(), "request.json")
	if err := cmdNetworkCreate(context.Background(), []string{
		"home",
		"--request-out", requestFile,
		"--wallet", "",
	}, "walleted"); err != nil {
		t.Fatalf("cmdNetworkCreate: %v", err)
	}

	data, err := os.ReadFile(requestFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var req walletconnect.NetworkCreateRequest
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if req.RequestedEndpoint != "" {
		t.Fatalf("requested endpoint = %q, want empty", req.RequestedEndpoint)
	}
	if req.NetworkName != "home" || req.NodeDID != identity.URI {
		t.Fatalf("request = %+v", req)
	}
}

func TestSetupCreateNetworkWalletAuthorizedNodeRequiresInteractiveWithoutEndpoint(t *testing.T) {
	resetVaultPasswordCache(t)

	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")
	t.Setenv("DWN_ENDPOINT", "")

	stateDir, identity, err := ensureIdentityForCommand(context.Background(), "walleted", "")
	if err != nil {
		t.Fatalf("ensureIdentityForCommand: %v", err)
	}
	if err := profile.UpsertProfileEntry(&profile.Entry{
		Name:     "walleted",
		DID:      identity.URI,
		AuthType: profile.AuthTypeWalletAuthorizedNode,
		OwnerDID: "did:dht:wallet",
		NodeDID:  identity.URI,
	}); err != nil {
		t.Fatalf("UpsertProfileEntry: %v", err)
	}

	_, err = setupCreateNetwork(context.Background(), upFlags{createNetwork: "home"}, stateDir, identity, "walleted")
	if err == nil || !strings.Contains(err.Error(), "wallet-owned network creation requires an interactive terminal") {
		t.Fatalf("setupCreateNetwork error = %v, want interactive wallet create error", err)
	}
}

func TestNetworkCreateMissingEndpointDoesNotCreateLocalIdentity(t *testing.T) {
	resetVaultPasswordCache(t)

	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")
	t.Setenv("DWN_ENDPOINT", "")

	err := cmdNetworkCreate(context.Background(), []string{"home"}, "")
	if err == nil || !strings.Contains(err.Error(), "usage: meshd network create") {
		t.Fatalf("cmdNetworkCreate error = %v, want usage error", err)
	}

	cfg, err := profile.ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if len(cfg.Profiles) != 0 {
		t.Fatalf("profiles = %+v, want none", cfg.Profiles)
	}
}

func TestParseNetworkJoinArgs(t *testing.T) {
	t.Setenv("DWN_ENDPOINT", "")

	endpoint, anchorDID, networkID, preauth := parseNetworkJoinArgs([]string{
		"--endpoint", "https://dwn.example.com",
		"--anchor", "did:jwk:anchor",
		"--network", "net",
		"--preauth",
	})
	if endpoint != "https://dwn.example.com" {
		t.Fatalf("endpoint = %q, want https://dwn.example.com", endpoint)
	}
	if anchorDID != "did:jwk:anchor" {
		t.Fatalf("anchorDID = %q, want did:jwk:anchor", anchorDID)
	}
	if networkID != "net" {
		t.Fatalf("networkID = %q, want net", networkID)
	}
	if !preauth {
		t.Fatal("preauth = false, want true")
	}
}

func TestParseNetworkJoinArgsUsesEndpointEnv(t *testing.T) {
	t.Setenv("DWN_ENDPOINT", "https://env.example.com")

	endpoint, anchorDID, networkID, preauth := parseNetworkJoinArgs([]string{
		"--anchor", "did:jwk:anchor",
		"--network", "net",
	})
	if endpoint != "https://env.example.com" {
		t.Fatalf("endpoint = %q, want https://env.example.com", endpoint)
	}
	if anchorDID != "did:jwk:anchor" {
		t.Fatalf("anchorDID = %q, want did:jwk:anchor", anchorDID)
	}
	if networkID != "net" {
		t.Fatalf("networkID = %q, want net", networkID)
	}
	if preauth {
		t.Fatal("preauth = true, want false")
	}
}

func TestParseOwnerDIDArg(t *testing.T) {
	got := parseOwnerDIDArg([]string{
		"--endpoint", "https://dwn.example.com",
		"--owner", "did:dht:wallet",
	})
	if got != "did:dht:wallet" {
		t.Fatalf("owner DID = %q", got)
	}

	got = parseOwnerDIDArg([]string{"--member", "did:dht:legacy"})
	if got != "did:dht:legacy" {
		t.Fatalf("legacy member alias owner DID = %q", got)
	}
}

func TestOwnerDWNEndpointFromInput(t *testing.T) {
	previous := defaultOwnerRequestEndpoint
	defaultOwnerRequestEndpoint = "https://default.example.com/"
	t.Cleanup(func() { defaultOwnerRequestEndpoint = previous })

	got, err := ownerDWNEndpointFromInput("https://explicit.example.com/", "https://resolved.example.com", nil, nil, io.Discard)
	if err != nil {
		t.Fatalf("explicit endpoint: %v", err)
	}
	if got != "https://explicit.example.com" {
		t.Fatalf("explicit endpoint = %q", got)
	}

	got, err = ownerDWNEndpointFromInput("", "https://resolved.example.com/", nil, nil, io.Discard)
	if err != nil {
		t.Fatalf("resolved endpoint: %v", err)
	}
	if got != "https://resolved.example.com" {
		t.Fatalf("resolved endpoint = %q", got)
	}

	got, err = ownerDWNEndpointFromInput("", "", context.Canceled, nil, io.Discard)
	if err != nil {
		t.Fatalf("default endpoint: %v", err)
	}
	if got != "https://default.example.com" {
		t.Fatalf("default endpoint = %q", got)
	}
}

func TestOwnerDWNEndpointFromInputPromptDefault(t *testing.T) {
	previous := defaultOwnerRequestEndpoint
	defaultOwnerRequestEndpoint = "https://default.example.com/"
	t.Cleanup(func() { defaultOwnerRequestEndpoint = previous })

	var out bytes.Buffer
	got, err := ownerDWNEndpointFromInput("", "", context.Canceled, bufio.NewScanner(strings.NewReader("\n")), &out)
	if err != nil {
		t.Fatalf("prompt default: %v", err)
	}
	if got != "https://default.example.com" {
		t.Fatalf("prompt default endpoint = %q", got)
	}
	if !strings.Contains(out.String(), "Owner DWN endpoint URL [https://default.example.com]") {
		t.Fatalf("prompt output = %q", out.String())
	}
}

func TestOwnerDWNEndpointFromInputPromptOverride(t *testing.T) {
	previous := defaultOwnerRequestEndpoint
	defaultOwnerRequestEndpoint = "https://default.example.com/"
	t.Cleanup(func() { defaultOwnerRequestEndpoint = previous })

	var out bytes.Buffer
	got, err := ownerDWNEndpointFromInput("", "", nil, bufio.NewScanner(strings.NewReader("https://custom.example.com/\n")), &out)
	if err != nil {
		t.Fatalf("prompt override: %v", err)
	}
	if got != "https://custom.example.com" {
		t.Fatalf("prompt override endpoint = %q", got)
	}
}

func TestParseJoinCommandArgsWithOwner(t *testing.T) {
	inviteURL := "meshd://invite/test"
	gotURL, ownerDID, noStartHint, err := parseJoinCommandArgs([]string{
		inviteURL,
		"--owner", "did:dht:wallet",
		"--no-start-hint",
	})
	if err != nil {
		t.Fatalf("parseJoinCommandArgs: %v", err)
	}
	if gotURL != inviteURL {
		t.Fatalf("inviteURL = %q", gotURL)
	}
	if ownerDID != "did:dht:wallet" {
		t.Fatalf("ownerDID = %q", ownerDID)
	}
	if !noStartHint {
		t.Fatal("noStartHint = false, want true")
	}
}

func TestParseNetworkJoinOptionsNoStartHint(t *testing.T) {
	opts := parseNetworkJoinOptions([]string{
		"--endpoint", "https://dwn.example.com",
		"--anchor", "did:jwk:anchor",
		"--network", "network-1",
		"--preauth",
		"--no-start-hint",
	})
	if opts.endpoint != "https://dwn.example.com" || opts.anchorDID != "did:jwk:anchor" || opts.networkID != "network-1" {
		t.Fatalf("network join options = %+v", opts)
	}
	if !opts.preauthRequested || !opts.noStartHint {
		t.Fatalf("network join flags = preauth %v noStartHint %v, want true/true", opts.preauthRequested, opts.noStartHint)
	}
}

func TestNetworkIdentityFallbacks(t *testing.T) {
	const fallback = "did:jwk:local"
	if got := networkNodeDID(nil, fallback); got != fallback {
		t.Fatalf("networkNodeDID nil = %q", got)
	}
	if got := networkOwnerDID(&state.NetworkState{}, fallback); got != fallback {
		t.Fatalf("networkOwnerDID empty = %q", got)
	}
	ns := &state.NetworkState{NodeDID: "did:jwk:node", OwnerDID: "did:dht:wallet"}
	if got := networkNodeDID(ns, fallback); got != "did:jwk:node" {
		t.Fatalf("networkNodeDID = %q", got)
	}
	if got := networkOwnerDID(ns, fallback); got != "did:dht:wallet" {
		t.Fatalf("networkOwnerDID = %q", got)
	}
}

func TestIsNetworkOwnerProfile(t *testing.T) {
	ns := &state.NetworkState{
		AnchorDID: "did:dht:wallet",
		NodeDID:   "did:jwk:node",
		OwnerDID:  "did:dht:wallet",
		MemberDID: "did:dht:wallet",
	}

	localAnchor := identityMetadata{
		AuthType: profile.AuthTypeLocalVault,
		OwnerDID: "did:dht:wallet",
		NodeDID:  "did:dht:wallet",
	}
	if !isNetworkOwnerProfile(localAnchor, "did:dht:wallet", ns) {
		t.Fatal("local anchor DID should be a network owner")
	}

	walletOwner := identityMetadata{
		AuthType: profile.AuthTypeWalletAuthorizedNode,
		OwnerDID: "did:dht:wallet",
		NodeDID:  "did:jwk:node",
	}
	if !isNetworkOwnerProfile(walletOwner, "did:jwk:node", ns) {
		t.Fatal("wallet-connected node owned by anchor DID should be a network owner")
	}

	otherWallet := identityMetadata{
		AuthType: profile.AuthTypeWalletAuthorizedNode,
		OwnerDID: "did:dht:other",
		NodeDID:  "did:jwk:node",
	}
	if isNetworkOwnerProfile(otherWallet, "did:jwk:node", ns) {
		t.Fatal("wallet-connected node for another member should not be network owner")
	}
}

func TestWalletDWNAuthForOperationDelegatedSession(t *testing.T) {
	resetVaultPasswordCache(t)

	stateDir := t.TempDir()
	t.Setenv(vaultPasswordEnv, "test-password")

	readGrant := testWalletPermissionGrant(t, "grant-read", "did:jwk:wallet", "did:jwk:node", map[string]any{
		"interface": "Records",
		"method":    "Read",
		"protocol":  "https://enbox.id/protocols/wireguard-mesh",
	})
	endpointGrant := testWalletPermissionGrant(t, "grant-endpoint", "did:jwk:wallet", "did:jwk:node", map[string]any{
		"interface":    "Records",
		"method":       "Write",
		"protocol":     "https://enbox.id/protocols/wireguard-mesh",
		"protocolPath": "network/member/node/endpoint",
	})
	if err := state.StoreWalletSession(stateDir, "test-password", &state.WalletSession{
		Version:  1,
		OwnerDID: "did:jwk:wallet",
		NodeDID:  "did:jwk:node",
		Grants:   []json.RawMessage{readGrant, endpointGrant},
	}); err != nil {
		t.Fatalf("StoreWalletSession: %v", err)
	}
	meta := identityMetadata{
		AuthType: profile.AuthTypeWalletAuthorizedNode,
		OwnerDID: "did:jwk:wallet",
		NodeDID:  "did:jwk:node",
	}

	auth, err := walletDWNAuthForOperation(stateDir, meta, dwn.InterfaceRecordsQuery, "https://enbox.id/protocols/wireguard-mesh", "", "", true)
	if err != nil {
		t.Fatalf("walletDWNAuthForOperation: %v", err)
	}
	if auth.PermissionGrantID != "" {
		t.Fatalf("delegated session returned plain grant ID %q", auth.PermissionGrantID)
	}
	if got := testGrantRecordID(t, auth.DelegatedGrant); got != "grant-read" {
		t.Fatalf("delegated grant = %q, want grant-read", got)
	}

	auth, err = walletDWNAuthForOperation(stateDir, meta, dwn.InterfaceRecordsWrite, "https://enbox.id/protocols/wireguard-mesh", "network/member/node/endpoint", "network-1", true)
	if err != nil {
		t.Fatalf("endpoint walletDWNAuthForOperation: %v", err)
	}
	if got := testGrantRecordID(t, auth.DelegatedGrant); got != "grant-endpoint" {
		t.Fatalf("endpoint delegated grant = %q, want grant-endpoint", got)
	}

	auth, err = walletDWNAuthForOperation(stateDir, meta, dwn.InterfaceRecordsWrite, "https://enbox.id/protocols/wireguard-mesh", "network/preAuthKey", "network-1", false)
	if err != nil {
		t.Fatalf("preAuthKey walletDWNAuthForOperation: %v", err)
	}
	if authHasGrant(auth) {
		t.Fatalf("preAuthKey auth = %+v, want none", auth)
	}

	_, err = walletDWNAuthForOperation(stateDir, meta, dwn.InterfaceRecordsWrite, "https://enbox.id/protocols/wireguard-mesh", "network/preAuthKey", "network-1", true)
	if err == nil || !strings.Contains(err.Error(), "meshd auth connect --admin") {
		t.Fatalf("missing admin grant error = %v, want --admin guidance", err)
	}
}

func TestWalletDWNAuthForOperationPlainSession(t *testing.T) {
	resetVaultPasswordCache(t)

	stateDir := t.TempDir()
	t.Setenv(vaultPasswordEnv, "test-password")

	readGrant := testWalletGrantMessage(t, "plain-grant-read", "did:jwk:wallet", "did:jwk:node", false, map[string]any{
		"interface": "Records",
		"method":    "Read",
		"protocol":  "https://enbox.id/protocols/wireguard-mesh",
	})
	if err := state.StoreWalletSession(stateDir, "test-password", &state.WalletSession{
		Version:  1,
		OwnerDID: "did:jwk:wallet",
		NodeDID:  "did:jwk:node",
		Grants:   []json.RawMessage{readGrant},
	}); err != nil {
		t.Fatalf("StoreWalletSession: %v", err)
	}

	auth, err := walletDWNAuthForOperation(stateDir, identityMetadata{
		AuthType: profile.AuthTypeWalletAuthorizedNode,
		OwnerDID: "did:jwk:wallet",
		NodeDID:  "did:jwk:node",
	}, dwn.InterfaceRecordsQuery, "https://enbox.id/protocols/wireguard-mesh", "", "", true)
	if err != nil {
		t.Fatalf("walletDWNAuthForOperation: %v", err)
	}
	if auth.PermissionGrantID != "plain-grant-read" {
		t.Fatalf("grantID = %q, want plain-grant-read", auth.PermissionGrantID)
	}
	if len(auth.DelegatedGrant) != 0 {
		t.Fatalf("plain session returned delegated grant %s", auth.DelegatedGrant)
	}
}

func TestWalletDWNAuthForOperationDelegateGrantee(t *testing.T) {
	resetVaultPasswordCache(t)

	stateDir := t.TempDir()
	t.Setenv(vaultPasswordEnv, "test-password")

	nodeReadGrant := testWalletPermissionGrant(t, "grant-read", "did:jwk:wallet", "did:jwk:node", map[string]any{
		"interface": "Records",
		"method":    "Read",
		"protocol":  "https://enbox.id/protocols/wireguard-mesh",
	})
	delegateReadGrant := testWalletPermissionGrant(t, "delegate-grant-read", "did:jwk:wallet", "did:jwk:delegate", map[string]any{
		"interface": "Records",
		"method":    "Read",
		"protocol":  "https://enbox.id/protocols/wireguard-mesh",
	})
	meta := identityMetadata{
		AuthType:    profile.AuthTypeWalletAuthorizedNode,
		OwnerDID:    "did:jwk:wallet",
		NodeDID:     "did:jwk:node",
		DelegateDID: "did:jwk:delegate",
	}

	if err := state.StoreWalletSession(stateDir, "test-password", &state.WalletSession{
		Version:     1,
		OwnerDID:    "did:jwk:wallet",
		NodeDID:     "did:jwk:node",
		DelegateDID: "did:jwk:delegate",
		Grants:      []json.RawMessage{nodeReadGrant},
	}); err != nil {
		t.Fatalf("StoreWalletSession delegate with node grant: %v", err)
	}
	_, err := walletDWNAuthForOperation(stateDir, meta, dwn.InterfaceRecordsQuery, "https://enbox.id/protocols/wireguard-mesh", "", "", true)
	if err == nil || !strings.Contains(err.Error(), "no permission grant") {
		t.Fatalf("delegate session used node-DID grant or returned wrong error: %v", err)
	}

	if err := state.StoreWalletSession(stateDir, "test-password", &state.WalletSession{
		Version:     1,
		OwnerDID:    "did:jwk:wallet",
		NodeDID:     "did:jwk:node",
		DelegateDID: "did:jwk:delegate",
		Grants:      []json.RawMessage{delegateReadGrant},
	}); err != nil {
		t.Fatalf("StoreWalletSession delegate grant: %v", err)
	}
	auth, err := walletDWNAuthForOperation(stateDir, meta, dwn.InterfaceRecordsQuery, "https://enbox.id/protocols/wireguard-mesh", "", "", true)
	if err != nil {
		t.Fatalf("delegate walletDWNAuthForOperation: %v", err)
	}
	if got := testGrantRecordID(t, auth.DelegatedGrant); got != "delegate-grant-read" {
		t.Fatalf("delegate grant = %q, want delegate-grant-read", got)
	}
}

// testGrantRecordID extracts the recordId of a raw grant message.
func testGrantRecordID(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	if len(raw) == 0 {
		t.Fatal("expected a delegated grant, got none")
	}
	var msg struct {
		RecordID string `json:"recordId"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("parsing grant message: %v", err)
	}
	return msg.RecordID
}

// testWalletPermissionGrant fabricates a DELEGATED grant message (the shape
// enbox connect sessions store).
func testWalletPermissionGrant(t *testing.T, id string, grantor string, grantee string, scope map[string]any) json.RawMessage {
	t.Helper()
	return testWalletGrantMessage(t, id, grantor, grantee, true, scope)
}

// testWalletGrantMessage fabricates a grant RecordsWrite message with the
// fields the CLI's grant matching reads.
func testWalletGrantMessage(t *testing.T, id string, grantor string, grantee string, delegated bool, scope map[string]any) json.RawMessage {
	t.Helper()
	header, err := json.Marshal(map[string]string{
		"alg": "EdDSA",
		"kid": grantor + "#0",
	})
	if err != nil {
		t.Fatal(err)
	}
	grantData := map[string]any{
		"dateExpires": "2999-01-01T00:00:00Z",
		"scope":       scope,
	}
	if delegated {
		grantData["delegated"] = true
	}
	data, err := json.Marshal(grantData)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := json.Marshal(map[string]any{
		"recordId":    id,
		"encodedData": base64.RawURLEncoding.EncodeToString(data),
		"descriptor": map[string]any{
			"recipient":   grantee,
			"dateCreated": "2026-06-23T00:00:00Z",
		},
		"authorization": map[string]any{
			"signature": map[string]any{
				"payload": "",
				"signatures": []map[string]any{{
					"protected": base64.RawURLEncoding.EncodeToString(header),
					"signature": "",
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func resetVaultPasswordCache(t *testing.T) {
	t.Helper()
	previous := cachedVaultPassword
	previousStateDir := cachedVaultPasswordStateDir
	cachedVaultPassword = ""
	cachedVaultPasswordStateDir = ""
	t.Setenv(vaultPasswordCacheDirEnv, t.TempDir())
	t.Setenv(vaultPasswordCacheTTLEnv, "")
	t.Cleanup(func() {
		cachedVaultPassword = previous
		cachedVaultPasswordStateDir = previousStateDir
	})
}

func TestVaultPasswordCachePersistsAcrossCLIInvocations(t *testing.T) {
	resetVaultPasswordCache(t)

	stateDir := t.TempDir()
	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := identity.StoreEncrypted(stateDir, "test-password"); err != nil {
		t.Fatalf("StoreEncrypted: %v", err)
	}

	rememberVaultPassword(stateDir, "test-password", true)
	cachePath, err := vaultPasswordCachePath(stateDir)
	if err != nil {
		t.Fatalf("vaultPasswordCachePath: %v", err)
	}
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("stat vault password cache: %v", err)
	}
	if info.Mode().Perm() != vaultPasswordCacheFileMode {
		t.Fatalf("cache mode = %v, want %v", info.Mode().Perm(), vaultPasswordCacheFileMode)
	}

	cachedVaultPassword = ""
	cachedVaultPasswordStateDir = ""
	loaded, err := loadIdentity(stateDir)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	if loaded.URI != identity.URI {
		t.Fatalf("loaded DID = %q, want %q", loaded.URI, identity.URI)
	}
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

func TestAuthConnectImportsWalletResponse(t *testing.T) {
	resetVaultPasswordCache(t)

	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")

	stateDir, identity, err := ensureIdentityForCommand(context.Background(), "walleted", "")
	if err != nil {
		t.Fatalf("ensureIdentityForCommand: %v", err)
	}
	delegateIdentity, err := ensureWalletDelegateIdentity(stateDir)
	if err != nil {
		t.Fatalf("ensureWalletDelegateIdentity: %v", err)
	}
	resp := walletconnect.Response{
		Version:      1,
		Type:         walletconnect.ResponseType,
		ProfileName:  "walleted",
		OwnerDID:     "did:dht:wallet",
		DelegateDID:  delegateIdentity.URI,
		NodeDID:      identity.URI,
		WalletOrigin: "https://wallet.enbox.id",
		Grants:       []json.RawMessage{json.RawMessage(`{"id":"grant-1"}`)},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	responseFile := filepath.Join(t.TempDir(), "response.json")
	if err := os.WriteFile(responseFile, data, 0600); err != nil {
		t.Fatalf("write response: %v", err)
	}

	if err := cmdAuthConnect(context.Background(), []string{"walleted", "--response", responseFile}, ""); err != nil {
		t.Fatalf("cmdAuthConnect: %v", err)
	}

	cfg, err := profile.ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	entry := cfg.Profiles["walleted"]
	if entry == nil {
		t.Fatal("walleted profile missing")
	}
	if entry.EffectiveAuthType() != profile.AuthTypeWalletAuthorizedNode {
		t.Fatalf("auth type = %q", entry.EffectiveAuthType())
	}
	if entry.EffectiveOwnerDID() != "did:dht:wallet" {
		t.Fatalf("owner DID = %q", entry.EffectiveOwnerDID())
	}
	if entry.ConnectedDID != "did:dht:wallet" {
		t.Fatalf("legacy connected DID = %q", entry.ConnectedDID)
	}
	if entry.EffectiveNodeDID() != identity.URI {
		t.Fatalf("node DID = %q", entry.EffectiveNodeDID())
	}
	if entry.DelegateDID != delegateIdentity.URI {
		t.Fatalf("delegate DID = %q", entry.DelegateDID)
	}

	session, err := state.LoadWalletSession(stateDir, "test-password")
	if err != nil {
		t.Fatalf("LoadWalletSession: %v", err)
	}
	if session == nil || session.EffectiveOwnerDID() != "did:dht:wallet" || session.ConnectedDID != "did:dht:wallet" || session.NodeDID != identity.URI || session.DelegateDID != delegateIdentity.URI {
		t.Fatalf("wallet session = %+v", session)
	}
}

func TestAuthConnectImportRequiresDistinctDelegate(t *testing.T) {
	resetVaultPasswordCache(t)

	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")

	_, identity, err := ensureIdentityForCommand(context.Background(), "walleted", "")
	if err != nil {
		t.Fatalf("ensureIdentityForCommand: %v", err)
	}
	for _, tc := range []struct {
		name        string
		delegateDID string
		want        string
	}{
		{name: "node DID", delegateDID: identity.URI, want: "distinct from node DID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := walletconnect.Response{
				Version:     1,
				Type:        walletconnect.ResponseType,
				ProfileName: "walleted",
				OwnerDID:    "did:dht:wallet",
				DelegateDID: tc.delegateDID,
				NodeDID:     identity.URI,
			}
			data, err := json.Marshal(resp)
			if err != nil {
				t.Fatalf("marshal response: %v", err)
			}
			err = importAuthConnectResponseData(context.Background(), "walleted", data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("importAuthConnectResponseData error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAuthConnectAdminRequestIncludesExplicitAdminPermission(t *testing.T) {
	resetVaultPasswordCache(t)

	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")

	requestFile := filepath.Join(t.TempDir(), "wallet-request.json")
	if err := cmdAuthConnect(context.Background(), []string{
		"walleted",
		"--admin",
		"--request-out", requestFile,
		"--wallet", "",
	}, ""); err != nil {
		t.Fatalf("cmdAuthConnect admin request: %v", err)
	}

	data, err := os.ReadFile(requestFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var req walletconnect.Request
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if req.ProfileName != "walleted" || req.NodeDID == "" {
		t.Fatalf("request identity fields = %+v", req)
	}
	if req.DelegateDID == "" || req.DelegateDID == req.NodeDID {
		t.Fatalf("delegate DID = %q, node DID = %q", req.DelegateDID, req.NodeDID)
	}
	if !slices.Contains(req.Permissions, "mesh-node") {
		t.Fatalf("permissions = %v, missing mesh-node", req.Permissions)
	}
	if !slices.Contains(req.Permissions, "mesh-admin") {
		t.Fatalf("permissions = %v, missing mesh-admin", req.Permissions)
	}
}

func TestNetworkCreateImportsWalletResponse(t *testing.T) {
	resetVaultPasswordCache(t)

	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")

	stateDir, identity, err := ensureIdentityForCommand(context.Background(), "walleted", "")
	if err != nil {
		t.Fatalf("ensureIdentityForCommand: %v", err)
	}
	delegateIdentity, err := ensureWalletDelegateIdentity(stateDir)
	if err != nil {
		t.Fatalf("ensureWalletDelegateIdentity: %v", err)
	}

	resp := walletconnect.NetworkCreateResponse{
		Version:                 1,
		Type:                    walletconnect.NetworkCreateResponseType,
		ProfileName:             "walleted",
		OwnerDID:                "did:dht:wallet",
		DelegateDID:             delegateIdentity.URI,
		NodeDID:                 identity.URI,
		WalletOrigin:            "https://wallet.enbox.id",
		ExpiresAt:               "2999-01-01T00:00:00Z",
		AnchorEndpoint:          "https://dev.aws.dwn.enbox.id",
		NetworkRecordID:         "network-1",
		NetworkName:             "home",
		MeshCIDR:                "10.200.0.0/16",
		MeshIP:                  "10.200.4.5",
		MemberRecordID:          "member-1",
		MemberDateCreated:       "2026-06-23T00:00:00Z",
		NodeRecordID:            "node-1",
		NodeDateCreated:         "2026-06-23T00:00:00Z",
		Grants:                  []json.RawMessage{json.RawMessage(`{"id":"grant-1"}`)},
		NodeMultiPartyProtocols: []string{protocols.MeshProtocolURI},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	responseFile := filepath.Join(t.TempDir(), "network-create-response.json")
	if err := os.WriteFile(responseFile, data, 0600); err != nil {
		t.Fatalf("write response: %v", err)
	}

	if err := cmdNetworkCreate(context.Background(), []string{"--response", responseFile}, ""); err != nil {
		t.Fatalf("cmdNetworkCreate import: %v", err)
	}

	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		t.Fatalf("LoadNetworkState: %v", err)
	}
	if ns == nil {
		t.Fatal("network state missing")
	}
	if ns.AnchorDID != "did:dht:wallet" || ns.NodeDID != identity.URI || ns.OwnerDID != "did:dht:wallet" || ns.MemberDID != "did:dht:wallet" || ns.DelegateDID != delegateIdentity.URI {
		t.Fatalf("network identities = anchor %q node %q owner %q member %q delegate %q", ns.AnchorDID, ns.NodeDID, ns.OwnerDID, ns.MemberDID, ns.DelegateDID)
	}
	if ns.NetworkRecordID != "network-1" || ns.NodeRecordID != "node-1" || ns.MeshIP != "10.200.4.5" {
		t.Fatalf("network state = %+v", ns)
	}
	if ns.MemberRecordID != "member-1" {
		t.Fatalf("member record ID = %q, want member-1", ns.MemberRecordID)
	}

	session, err := state.LoadWalletSession(stateDir, "test-password")
	if err != nil {
		t.Fatalf("LoadWalletSession: %v", err)
	}
	if session == nil || session.EffectiveOwnerDID() != "did:dht:wallet" || session.ConnectedDID != "did:dht:wallet" || session.NodeDID != identity.URI || session.DelegateDID != delegateIdentity.URI {
		t.Fatalf("wallet session = %+v", session)
	}
	if len(session.Grants) != 1 {
		t.Fatalf("wallet session grants = %d", len(session.Grants))
	}

	cfg, err := profile.ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	entry := cfg.Profiles["walleted"]
	if entry == nil {
		t.Fatal("walleted profile missing")
	}
	if entry.EffectiveAuthType() != profile.AuthTypeWalletAuthorizedNode {
		t.Fatalf("auth type = %q", entry.EffectiveAuthType())
	}
	if entry.EffectiveOwnerDID() != "did:dht:wallet" {
		t.Fatalf("owner DID = %q", entry.EffectiveOwnerDID())
	}
	if entry.ConnectedDID != "did:dht:wallet" {
		t.Fatalf("legacy connected DID = %q", entry.ConnectedDID)
	}
	if entry.EffectiveNodeDID() != identity.URI {
		t.Fatalf("node DID = %q", entry.EffectiveNodeDID())
	}
	if entry.DelegateDID != delegateIdentity.URI {
		t.Fatalf("delegate DID = %q", entry.DelegateDID)
	}
}

func TestNetworkCreateImportRequiresDistinctDelegate(t *testing.T) {
	resetVaultPasswordCache(t)

	for _, tc := range []struct {
		name        string
		delegateDID string
		want        string
	}{
		{name: "node DID", want: "distinct from node DID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("ENBOX_HOME", home)
			t.Setenv("ENBOX_PROFILE", "")
			t.Setenv("MESHD_STATE_DIR", "")
			t.Setenv("MESHD_VAULT_PASSWORD", "test-password")

			_, identity, err := ensureIdentityForCommand(context.Background(), "walleted", "")
			if err != nil {
				t.Fatalf("ensureIdentityForCommand: %v", err)
			}
			delegateDID := tc.delegateDID
			if tc.name == "node DID" {
				delegateDID = identity.URI
			}
			resp := walletconnect.NetworkCreateResponse{
				Version:         1,
				Type:            walletconnect.NetworkCreateResponseType,
				ProfileName:     "walleted",
				OwnerDID:        "did:dht:wallet",
				DelegateDID:     delegateDID,
				NodeDID:         identity.URI,
				AnchorEndpoint:  "https://dev.aws.dwn.enbox.id",
				NetworkRecordID: "network-1",
				NetworkName:     "home",
				MeshCIDR:        "10.200.0.0/16",
				MeshIP:          "10.200.4.5",
			}
			data, err := json.Marshal(resp)
			if err != nil {
				t.Fatalf("marshal response: %v", err)
			}
			err = importNetworkCreateResponseData(context.Background(), "walleted", data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("importNetworkCreateResponseData error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNetworkCreateImportRejectsMismatchedExistingWalletSession(t *testing.T) {
	resetVaultPasswordCache(t)

	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")

	stateDir, identity, err := ensureIdentityForCommand(context.Background(), "walleted", "")
	if err != nil {
		t.Fatalf("ensureIdentityForCommand: %v", err)
	}
	delegateIdentity, err := ensureWalletDelegateIdentity(stateDir)
	if err != nil {
		t.Fatalf("ensureWalletDelegateIdentity: %v", err)
	}
	if err := state.StoreWalletSession(stateDir, "test-password", &state.WalletSession{
		Version:  1,
		OwnerDID: "did:dht:wallet-a",
		NodeDID:  identity.URI,
	}); err != nil {
		t.Fatalf("StoreWalletSession: %v", err)
	}

	resp := walletconnect.NetworkCreateResponse{
		Version:         1,
		Type:            walletconnect.NetworkCreateResponseType,
		ProfileName:     "walleted",
		OwnerDID:        "did:dht:wallet-b",
		DelegateDID:     delegateIdentity.URI,
		NodeDID:         identity.URI,
		AnchorEndpoint:  "https://dev.aws.dwn.enbox.id",
		NetworkRecordID: "network-1",
		NetworkName:     "home",
		MeshCIDR:        "10.200.0.0/16",
		MeshIP:          "10.200.4.5",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	responseFile := filepath.Join(t.TempDir(), "network-create-response.json")
	if err := os.WriteFile(responseFile, data, 0600); err != nil {
		t.Fatalf("write response: %v", err)
	}

	err = cmdNetworkCreate(context.Background(), []string{"--response", responseFile}, "")
	if err == nil {
		t.Fatal("cmdNetworkCreate import succeeded with mismatched wallet session")
	}
	if !strings.Contains(err.Error(), "wallet session owner DID") {
		t.Fatalf("error = %v, want owner DID mismatch", err)
	}
	if state.HasNetwork(stateDir) {
		t.Fatal("network state should not be saved after session mismatch")
	}
}

func TestOwnerAutomationRequiresExplicitAdminGrantsForWalletOwnedNode(t *testing.T) {
	ns := &state.NetworkState{
		AnchorDID: "did:jwk:wallet",
		NodeDID:   "did:jwk:node",
	}

	if !ownerAutomationEnabled(ns, "did:jwk:wallet", true, "", "", "") {
		t.Fatal("local anchor should run owner automation without wallet grants")
	}
	if ownerAutomationEnabled(ns, "did:jwk:node", true, "read", "write", "") {
		t.Fatal("wallet-owned node with partial admin grants should not run owner automation")
	}
	if !ownerAutomationEnabled(ns, "did:jwk:node", true, "read", "write", "delete") {
		t.Fatal("wallet-owned node with explicit admin grants should run owner automation")
	}
	if ownerAutomationEnabled(ns, "did:jwk:node", false, "read", "write", "delete") {
		t.Fatal("non-owner profile should not run owner automation")
	}
}

func TestNodeRuntimeProtocolPaths(t *testing.T) {
	topLevel := &state.NetworkState{}
	if got := nodeInfoProtocolPath(topLevel); got != "network/node/nodeInfo" {
		t.Fatalf("top-level nodeInfo path = %q", got)
	}
	if got := endpointProtocolPath(topLevel); got != "network/node/endpoint" {
		t.Fatalf("top-level endpoint path = %q", got)
	}

	memberNode := &state.NetworkState{MemberRecordID: "member-1"}
	if got := nodeInfoProtocolPath(memberNode); got != "network/member/node/nodeInfo" {
		t.Fatalf("member nodeInfo path = %q", got)
	}
	if got := endpointProtocolPath(memberNode); got != "network/member/node/endpoint" {
		t.Fatalf("member endpoint path = %q", got)
	}
}

func TestReadProtocolRole(t *testing.T) {
	const anchorDID = "did:dht:anchor"
	const nodeDID = "did:jwk:node"

	tests := []struct {
		name           string
		anchorDID      string
		selfNodeDID    string
		memberRecordID string
		want           string
	}{
		{
			name:        "anchor reads as author",
			anchorDID:   anchorDID,
			selfNodeDID: anchorDID,
			want:        "",
		},
		{
			name:           "member-associated node reads as network/member",
			anchorDID:      anchorDID,
			selfNodeDID:    nodeDID,
			memberRecordID: "member-1",
			want:           "network/member",
		},
		{
			name:        "owner-provisioned node reads as network/node",
			anchorDID:   anchorDID,
			selfNodeDID: nodeDID,
			want:        "network/node",
		},
		{
			// The anchor short-circuit wins even if a member record is present.
			name:           "anchor with member record still reads as author",
			anchorDID:      anchorDID,
			selfNodeDID:    anchorDID,
			memberRecordID: "member-1",
			want:           "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := readProtocolRole(tt.anchorDID, tt.selfNodeDID, tt.memberRecordID); got != tt.want {
				t.Fatalf("readProtocolRole(%q, %q, %q) = %q, want %q",
					tt.anchorDID, tt.selfNodeDID, tt.memberRecordID, got, tt.want)
			}
		})
	}
}
